use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use super::keys::derive_subkey;

/// Derive final key
///
/// `HKDF(salt=noise_handshake_hash, ikm=ml_kem_ss || opaque_session_key, info="noob:transport:final:v1")`
pub fn derive_final_transport_key(
    handshake_hash: &[u8],
    ml_kem_ss: &SecretBox<[u8; 32]>,
    opaque_session_key: &SecretBox<[u8; 64]>,
) -> SecretBox<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 + 64);
    ikm.extend_from_slice(ml_kem_ss.expose_secret());
    ikm.extend_from_slice(opaque_session_key.expose_secret());
    let key = derive_subkey(&ikm, handshake_hash, "noob:transport:final:v1");
    ikm.zeroize();
    key
}
