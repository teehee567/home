use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use home_traits::FramedStream;

use crate::crypto::{
    aead,
    hybrid,
    keys::derive_subkey,
    noise,
    opaque::OpaqueServer,
};

use super::types::*;
use super::server_identity::ServerIdentity;

const NOISE_MSG_BUF: usize = 65535;

/// sends server noise static ublic and ML-KEM-768 public inside opaque registration
/// returns encrypted at rest key
pub async fn handle_registration(
    server_identity: &ServerIdentity,
    opaque_server: &mut OpaqueServer,
    username: &str,
    tls_cert_fingerprint: &[u8; 32],
    stream: &mut impl FramedStream,
) -> Result<Vec<u8>> {
    // receive RegistrationStart
    let start: RegistrationStart = postcard::from_bytes(&stream.receive().await?)
        .context("malformed registration start")?;

    // OPAQUE registration start
    let opaque_resp =
        opaque_server.registration_start(username, &start.opaque_registration_request)?;

    // send RegistrationResponse with server identity
    let resp = RegistrationResponse {
        opaque_registration_response: opaque_resp,
        server_noise_static_pubkey: *server_identity.noise_public_key(),
        server_ml_kem_pubkey: server_identity.ml_kem_public_key_bytes().to_vec(),
        server_tls_cert_fingerprint: *tls_cert_fingerprint,
    };
    stream.send(&postcard::to_allocvec(&resp)?).await?;

    // receive RegistrationFinalize
    let fin: RegistrationFinalize = postcard::from_bytes(&stream.receive().await?)
        .context("malformed registration finalize")?;

    // finish OPAQUE registration
    opaque_server.registration_finish(username, &fin.opaque_registration_record)?;

    // return the encrypted at rest key
    Ok(fin.encrypted_at_rest_key_blob)
}

/// combined Noise IK + ML-KEM-768 + OPAQUE login handshake.
/// Sequence
/// 1.
/// (client -> server) noise ik -> e, es, s, ss carrying Opaque ke1 + ml-kem-768 encoded as payload
/// 2.
/// (server -> client) noise ik <- e, ee, se carrying Opaque ke2 + at rest key
/// 3.
/// (client -> server) using noise stream opaque ke3 + at rest key encrypted for server
/// 4.
/// (server -> client) key confirmation
/// 
/// AFter 4 both sides have final_key which is 
/// `HKDF(ml_kem_ss || opaque_session_key, noise_handshake_hash, "noob:transport:final:1"`
pub async fn handle_login(
    server_identity: &ServerIdentity,
    opaque_server: &OpaqueServer,
    username: &str,
    encrypted_at_rest_key_blob: &[u8],
    stream: &mut impl FramedStream,
) -> Result<ServerHandshakeResult> {
    // receive Noise Flight 1
    let f1_encrypted = stream.receive().await?;

    // create noise responder and f1 payload
    let mut responder = noise::build_responder(server_identity.noise_private_key())?;
    let mut payload_buf = vec![0u8; NOISE_MSG_BUF];
    let plen = responder
        .read_message(&f1_encrypted, &mut payload_buf)
        .map_err(|e| anyhow::anyhow!("noise read flight 1: {e}"))?;
    let f1: Flight1Payload =
        postcard::from_bytes(&payload_buf[..plen]).context("malformed flight 1")?;

    // ML-KEM-768 decapsulate
    let ml_kem_ss = server_identity.ml_kem_decapsulate(&f1.ml_kem_ciphertext)?;

    // OPAQUE login start create ke2 from ke1
    let (ke2, opaque_state) = opaque_server.login_start(username, &f1.opaque_ke1)?;

    // build + send Noise Flight
    let f2_payload = postcard::to_allocvec(&Flight2Payload {
        opaque_ke2: ke2,
        encrypted_at_rest_key_blob: encrypted_at_rest_key_blob.to_vec(),
    })?;
    let mut buf = vec![0u8; NOISE_MSG_BUF];
    let len = responder
        .write_message(&f2_payload, &mut buf)
        .map_err(|e| anyhow::anyhow!("noise write flight 2: {e}"))?;
    stream.send(&buf[..len]).await?;

    // handshake hash, enter transport mode
    let handshake_hash = responder.get_handshake_hash().to_vec();
    let mut transport = responder
        .into_transport_mode()
        .map_err(|e| anyhow::anyhow!("noise transport: {e}"))?;

    // receive Flight 3 over Noise
    let f3_encrypted = stream.receive().await?;
    let mut payload_buf = vec![0u8; NOISE_MSG_BUF];
    let plen = transport
        .read_message(&f3_encrypted, &mut payload_buf)
        .map_err(|e| anyhow::anyhow!("noise read flight 3: {e}"))?;
    let f3: Flight3Message =
        postcard::from_bytes(&payload_buf[..plen]).context("malformed flight 3")?;

    // OPAQUE login finish verify KE3, derive session_key
    let session_key = OpaqueServer::login_finish(opaque_state, &f3.opaque_ke3)?;

    // decrypt the at rest key
    let ark_tx_key = derive_subkey(
        session_key.expose_secret(),
        &[],
        "noob:at-rest-key:transport",
    );
    let mut ark_bytes = aead::decrypt(&ark_tx_key, &f3.encrypted_at_rest_key)?;
    let mut ark = [0u8; 32];
    ark.copy_from_slice(&ark_bytes);
    let at_rest_key = SecretBox::new(Box::new(ark));
    ark.zeroize();
    ark_bytes.zeroize();

    // derive final transport key and rekey the Noise session
    let final_key =
        hybrid::derive_final_transport_key(&handshake_hash, &ml_kem_ss, &session_key);
    noise::rekey_transport(&mut transport, &final_key, &handshake_hash);

    // send Flight 4 (key confirmation) over new noise
    let f4 = noise::noise_encrypt(&mut transport, HANDSHAKE_OK)?;
    stream.send(&f4).await?;

    Ok(ServerHandshakeResult {
        transport,
        transport_key: final_key,
        session_key,
        at_rest_key,
    })
}
