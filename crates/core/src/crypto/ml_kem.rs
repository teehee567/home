use anyhow::{anyhow, Result};
use ml_kem::{
    EncapsulationKey768, KeyExport, KeyInit, MlKem768, TryKeyInit,
    kem::{Decapsulate, Encapsulate, Kem}, DecapsulationKey768
};

use secrecy::SecretBox;

// generate MK-KEM-768 keypair
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate_keypair();

    (dk.to_bytes().to_vec(), ek.to_bytes().to_vec())
}

// Encapsulate secret using ML-KEM-768 encapsulation
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, SecretBox<[u8; 32]>)> {
    let ek = EncapsulationKey768::new_from_slice(ek_bytes)?;

    let (ct, ss) = ek.encapsulate();
    let ct_vec = ct.to_vec();
    let secret = SecretBox::new(Box::new(
        <[u8; 32]>::try_from(ss.as_ref())
            .map_err(|_| anyhow!("cant get array from ss ML-KEM-768"))?,
    ));

    Ok((ct_vec, secret))
}

/// Decapsulate secret using ML-KEM-768 decapsulation
pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<SecretBox<[u8; 32]>> {
    let dk = DecapsulationKey768::new_from_slice(dk_bytes)?;
    let ss = dk.decapsulate_slice(ct_bytes).map_err(|_| anyhow!("ML-KEM-768 decapsulation failed"))?;
    let secret = SecretBox::new(Box::new(
        <[u8; 32]>::try_from(ss.as_ref())
            .map_err(|_| anyhow!("ML-KEM-768 decapsulation failed"))?,
    ));

    Ok(secret)
}
