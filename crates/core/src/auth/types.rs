use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

pub const HANDSHAKE_OK: &[u8] = b"MEOW_OK";

// registration

#[derive(Serialize, Deserialize)]
pub struct RegistrationStart {
    pub opaque_registration_request: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub opaque_registration_response: Vec<u8>,
    pub server_noise_static_pubkey: [u8; 32],
    pub server_ml_kem_pubkey: Vec<u8>,
    pub server_tls_cert_fingerprint: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationFinalize {
    pub opaque_registration_record: Vec<u8>,
    pub encrypted_at_rest_key_blob: Vec<u8>,
}

// login

#[derive(Serialize, Deserialize)]
pub struct Flight1Payload {
    pub opaque_ke1: Vec<u8>,
    pub ml_kem_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Flight2Payload {
    pub opaque_ke2: Vec<u8>,
    pub encrypted_at_rest_key_blob: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Flight3Message {
    pub opaque_ke3: Vec<u8>,
    pub encrypted_at_rest_key: Vec<u8>,
}

// handshake results

/// data for client to store
pub struct ClientEnrollment {
    pub server_noise_pubkey: [u8; 32],
    pub server_ml_kem_pubkey: Vec<u8>,
    pub tls_cert_fingerprint: [u8; 32],
}

/// keys from successful client login
pub struct ClientHandshakeResult {
    pub transport: snow::TransportState,
    pub transport_key: SecretBox<[u8; 32]>,
    pub session_key: SecretBox<[u8; 64]>,
    pub export_key: SecretBox<[u8; 64]>,
}

/// keys from successful server login
pub struct ServerHandshakeResult {
    pub transport: snow::TransportState,
    pub transport_key: SecretBox<[u8; 32]>,
    pub session_key: SecretBox<[u8; 64]>,
    pub at_rest_key: SecretBox<[u8; 32]>,
}
