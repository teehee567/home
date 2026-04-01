use anyhow::Result;
use crate::core::crypto::{ml_kem, noise};
use secrecy::SecretBox;

// long term identity
// need to setup a way to pull form disk and store
// conatins static keypair for noise ik and ml-kem-768
pub struct ServerIdentity {
    noise_private: [u8; 32],
    noise_public: [u8; 32],
    ml_kem_dk_bytes: Vec<u8>,
    ml_kem_ek_bytes: Vec<u8>,
}

impl ServerIdentity {
    pub fn generate() -> Result<Self> {
        let kp = noise::generate_noise_keypair()?;
        let (dk_bytes, ek_bytes) = ml_kem::generate_keypair();

        let mut noise_private = [0u8; 32];
        let mut noise_public = [0u8; 32];
        noise_private.copy_from_slice(&kp.private);
        noise_public.copy_from_slice(&kp.public);

        Ok(Self {
            noise_private,
            noise_public,
            ml_kem_dk_bytes: dk_bytes,
            ml_kem_ek_bytes: ek_bytes,
        })
    }

    pub fn noise_public_key(&self) -> &[u8; 32] {
        &self.noise_public
    }

    pub fn noise_private_key(&self) -> &[u8; 32] {
        &self.noise_private
    }

    pub fn ml_kem_public_key_bytes(&self) -> &[u8] {
        &self.ml_kem_ek_bytes
    }

    pub fn ml_kem_decapsulate(&self, ct_bytes: &[u8]) -> Result<SecretBox<[u8; 32]>> {
        ml_kem::decapsulate(&self.ml_kem_dk_bytes, ct_bytes)
    }
}
