use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use secrecy::{ExposeSecret, SecretBox};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("ciphertext too short to contain nonce + tag")]
    TooShort,
    #[error("MAC verification failed")]
    MacVerification,
}

pub fn encrypt(key: &SecretBox<[u8; 32]>, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!(e))
        .context("XChaCha20-Poly1305 encryption failed")?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &SecretBox<[u8; 32]>, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        bail!(AeadError::TooShort);
    }
    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| AeadError::MacVerification)
        .context("XChaCha20-Poly1305 decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SecretBox::new(Box::new([0u8; 32]));
        let plaintext = b"BRUH BRUH BRUH BRUH";
        let ct = encrypt(&key, plaintext).expect("encrypt should succeed");
        assert_eq!(ct.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
        let pt = decrypt(&key, &ct).expect("decrypt should succeed");
        assert_eq!(pt, plaintext);
    }
}
