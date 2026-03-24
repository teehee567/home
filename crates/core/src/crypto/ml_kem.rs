use anyhow::Result;
use hybrid_array::Array;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use secrecy::SecretBox;
use zeroize::Zeroize;

type Ek768 = <MlKem768 as KemCore>::EncapsulationKey;
type Dk768 = <MlKem768 as KemCore>::DecapsulationKey;

// generate MK-KEM-768 keypair
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    (
        dk.as_bytes().as_slice().to_vec(),
        ek.as_bytes().as_slice().to_vec(),
    )
}

// Encapsulate secret using ML-KEM-768 encapsulation
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, SecretBox<[u8; 32]>)> {
    let ek_arr: Array<u8, _> = ek_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 ek length"))?;
    let ek = Ek768::from_bytes(&ek_arr);
    let mut rng = OsRng;
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow::anyhow!("ML-KEM-768 encapsulation failed"))?;

    let ct_vec: Vec<u8> = ct.as_slice().to_vec();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(ss.as_ref());
    let secret = SecretBox::new(Box::new(arr));
    arr.zeroize();
    Ok((ct_vec, secret))
}

/// Decapsulate secret using ML-KEM-768 decapsulation
pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<SecretBox<[u8; 32]>> {
    let dk_arr: Array<u8, _> = dk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 dk length"))?;
    let dk = Dk768::from_bytes(&dk_arr);
    let ct_arr: Array<u8, _> = ct_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 ciphertext length"))?;
    let ss = dk
        .decapsulate(&ct_arr)
        .map_err(|_| anyhow::anyhow!("ML-KEM-768 decapsulation failed"))?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(ss.as_ref());
    let secret = SecretBox::new(Box::new(arr));
    arr.zeroize();
    Ok(secret)
}
