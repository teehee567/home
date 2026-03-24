use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use transport::framed::FramedStream;

use crate::crypto::{
    aead,
    hybrid,
    keys::derive_subkey,
    ml_kem,
    noise,
    opaque::OpaqueClient,
};

use super::types::*;

const NOISE_MSG_BUF: usize = 65535;

// clinet side registration function
pub async fn register(
    password: &[u8],
    stream: &mut impl FramedStream,
) -> Result<(ClientEnrollment, SecretBox<[u8; 64]>)> {
    // start opaque registration
    let (reg_req, opaque_state) = OpaqueClient::registration_start(password)?;
    stream.send(&postcard::to_allocvec(&reg_req)?).await?;

    // receive registration respnose
    let resp: RegistrationResponse = postcard::from_bytes(&stream.receive().await?)?;

    // finish opaque registration
    let (reg_record, export_key) = OpaqueClient::registration_finish(
        opaque_state,
        password,
        &resp.opaque_registration_response,
    )?;

    // generate random key 256bit use something else later
    let mut at_rest_key = [0u8; 32];
    at_rest_key.copy_from_slice(&rand::random::<[u8; 32]>());

    // encrypt at rest key with export derived key
    let ark_enc_key =
        derive_subkey(export_key.expose_secret(), &[], "noob:at-rest-key:encryption");
    let encrypted_ark = aead::encrypt(&ark_enc_key, &at_rest_key)?;
    at_rest_key.zeroize();

    // send final response
    let fin = RegistrationFinalize {
        opaque_registration_record: reg_record,
        encrypted_at_rest_key_blob: encrypted_ark,
    };
    stream.send(&postcard::to_allocvec(&fin)?).await?;

    Ok((
        ClientEnrollment {
            server_noise_pubkey: resp.server_noise_static_pubkey,
            server_ml_kem_pubkey: resp.server_ml_kem_pubkey,
            tls_cert_fingerprint: resp.server_tls_cert_fingerprint,
        },
        export_key,
    ))
}

/// combined Noise IK + ML-KEM-768 + OPAQUE login handshake.
///
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
pub async fn login(
    password: &[u8],
    enrollment: &ClientEnrollment,
    stream: &mut impl FramedStream,
) -> Result<ClientHandshakeResult> {
    let client_kp = noise::generate_noise_keypair()?;

    // OPAQUE login start -> KE1
    let (ke1, opaque_state) = OpaqueClient::login_start(password)?;

    // ML-KEM-768 encapsulate with public key
    let (ml_kem_ct, ml_kem_ss) =
        ml_kem::encapsulate(&enrollment.server_ml_kem_pubkey)?;

    // f1 payload
    let f1_payload = postcard::to_allocvec(&Flight1Payload {
        opaque_ke1: ke1,
        ml_kem_ciphertext: ml_kem_ct,
    })?;

    // noise IK start and write Flight 1
    let mut initiator =
        noise::build_initiator(&client_kp.private, &enrollment.server_noise_pubkey)?;
    let mut buf = vec![0u8; NOISE_MSG_BUF];
    let len = initiator
        .write_message(&f1_payload, &mut buf)
        .map_err(|e| anyhow::anyhow!("noise write flight 1: {e}"))?;
    stream.send(&buf[..len]).await?;

    // receive + read Noise Flight 2
    let f2_encrypted = stream.receive().await?;
    let mut payload_buf = vec![0u8; NOISE_MSG_BUF];
    let plen = initiator
        .read_message(&f2_encrypted, &mut payload_buf)
        .map_err(|e| anyhow::anyhow!("noise read flight 2: {e}"))?;
    let f2: Flight2Payload =
        postcard::from_bytes(&payload_buf[..plen]).context("malformed flight 2")?;

    // handshake hash, transition noise to transport mode
    let handshake_hash = initiator.get_handshake_hash().to_vec();
    let mut transport = initiator
        .into_transport_mode()
        .map_err(|e| anyhow::anyhow!("noise transport: {e}"))?;

    // OPAQUE login finish -> KE3 + session_key + export_key
    let (ke3, opaque_result) =
        OpaqueClient::login_finish(opaque_state, password, &f2.opaque_ke2)?;

    // at rest key is encrypted and returned by server since it is created only on registration
    // so client needs to decrypt using export key and send back to server so server can decrypt
    // database stuff
    // this is correct because otherwise the key derived by sha512 would be different on every login
    // so the server cant decrypt anything on database
    let ark_enc_key = derive_subkey(
        opaque_result.export_key.expose_secret(),
        &[],
        "noob:at-rest-key:encryption",
    );
    let at_rest_key_bytes =
        aead::decrypt(&ark_enc_key, &f2.encrypted_at_rest_key_blob)?;

    // Encrypt at rest key for server using session_key
    let ark_tx_key = derive_subkey(
        opaque_result.session_key.expose_secret(),
        &[],
        "noob:at-rest-key:transport",
    );
    let encrypted_ark = aead::encrypt(&ark_tx_key, &at_rest_key_bytes)?;

    // send flight 3 over Noise transport
    let f3_bytes = postcard::to_allocvec(&Flight3Message {
        opaque_ke3: ke3,
        encrypted_at_rest_key: encrypted_ark,
    })?;
    let mut buf = vec![0u8; f3_bytes.len() + 64];
    let len = transport
        .write_message(&f3_bytes, &mut buf)
        .map_err(|e| anyhow::anyhow!("noise write flight 3: {e}"))?;
    stream.send(&buf[..len]).await?;

    // derive final transport key and rekey the Noise session
    let final_key = hybrid::derive_final_transport_key(
        &handshake_hash,
        &ml_kem_ss,
        &opaque_result.session_key,
    );
    noise::rekey_transport(&mut transport, &final_key, &handshake_hash);

    // receive flight 4 (key confirmation) over new noise
    let f4_encrypted = stream.receive().await?;
    let f4_plain = noise::noise_decrypt(&mut transport, &f4_encrypted)
        .context("flight 4 key confirmation failed")?;
    if f4_plain != HANDSHAKE_OK {
        bail!("handshake key confirmation mismatch");
    }

    Ok(ClientHandshakeResult {
        transport,
        transport_key: final_key,
        session_key: opaque_result.session_key,
        export_key: opaque_result.export_key,
    })
}
