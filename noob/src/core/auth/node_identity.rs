use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ActiveValue, DatabaseConnection, EntityTrait};
use secrecy::SecretBox;

use crate::core::crypto::{ml_kem, noise};
use crate::storage::identity_store;

// long term node/device identity — who this node is in the mesh, used as the
// responder identity when accepting connections
// need to setup a way to pull form disk and store
// conatins static keypair for noise ik and ml-kem-768
pub struct NodeIdentity {
    noise_private: [u8; 32],
    noise_public: [u8; 32],
    ml_kem_dk_bytes: Vec<u8>,
    ml_kem_ek_bytes: Vec<u8>,
}

impl NodeIdentity {
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

    // rebuild from stored keys
    pub fn from_parts(
        noise_private: [u8; 32],
        noise_public: [u8; 32],
        ml_kem_dk_bytes: Vec<u8>,
        ml_kem_ek_bytes: Vec<u8>,
    ) -> Self {
        Self { noise_private, noise_public, ml_kem_dk_bytes, ml_kem_ek_bytes }
    }

    // load or generate on first run
    pub async fn load_or_generate(db: &DatabaseConnection) -> Result<Self> {
        if let Some(row) = identity_store::Entity::find_by_id(identity_store::ROW_ID)
            .one(db)
            .await
            .context("load node identity")?
        {
            let noise_private: [u8; 32] = row
                .noise_private
                .as_slice()
                .try_into()
                .context("stored noise private key wrong size")?;
            let noise_public: [u8; 32] = row
                .noise_public
                .as_slice()
                .try_into()
                .context("stored noise public key wrong size")?;
            return Ok(Self::from_parts(
                noise_private,
                noise_public,
                row.ml_kem_dk,
                row.ml_kem_ek,
            ));
        }

        let identity = Self::generate()?;
        identity_store::ActiveModel {
            id: ActiveValue::Set(identity_store::ROW_ID),
            noise_private: ActiveValue::Set(identity.noise_private.to_vec()),
            noise_public: ActiveValue::Set(identity.noise_public.to_vec()),
            ml_kem_dk: ActiveValue::Set(identity.ml_kem_dk_bytes.clone()),
            ml_kem_ek: ActiveValue::Set(identity.ml_kem_ek_bytes.clone()),
        }
        .insert(db)
        .await
        .context("persist node identity")?;
        Ok(identity)
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
