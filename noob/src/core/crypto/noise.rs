use anyhow::Result;
use secrecy::ExposeSecret;
use secrecy::SecretBox;

use super::keys::derive_subkey;

use snow::params::NoiseParams;

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// build noise initiator
pub fn build_initiator(
    client_private: &[u8],
    server_public: &[u8],
) -> Result<snow::HandshakeState> {
    let params = noise_params();
    snow::Builder::new(params)
        .local_private_key(client_private)?
        .remote_public_key(server_public)?
        .build_initiator()
        .map_err(|e| anyhow::anyhow!("noise initiator: {e}"))
}

pub fn build_responder(server_private: &[u8]) -> Result<snow::HandshakeState> {
    let params = noise_params();
    snow::Builder::new(params)
        .local_private_key(server_private)?
        .build_responder()
        .map_err(|e| anyhow::anyhow!("noise responder: {e}"))
}

pub fn generate_noise_keypair() -> Result<snow::Keypair> {
    let params = noise_params();
    snow::Builder::new(params)
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("noise keygen: {e}"))
}

fn noise_params() -> NoiseParams {
    NOISE_PATTERN.parse().unwrap()
}

pub fn rekey_stateless(
    transport: &mut snow::StatelessTransportState,
    final_key: &SecretBox<[u8; 32]>,
    handshake_hash: &[u8],
) {
    let initiator_key = derive_subkey(
        final_key.expose_secret(),
        handshake_hash,
        "noob:noise:rekey:initiator:v1",
    );
    let responder_key = derive_subkey(
        final_key.expose_secret(),
        handshake_hash,
        "noob:noise:rekey:responder:v1",
    );
    transport.rekey_manually(
        Some(initiator_key.expose_secret()),
        Some(responder_key.expose_secret()),
    );
}
