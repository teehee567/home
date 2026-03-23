use hkdf::Hkdf;
use secrecy::SecretBox;
use sha2::Sha512;
use zeroize::Zeroize;

pub const SUBKEY_LEN: usize = 32;

pub fn derive_subkey(ikm: &[u8], salt: &[u8], context_string: &str) -> SecretBox<[u8; SUBKEY_LEN]> {
    let hk = Hkdf::<Sha512>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = [0u8; SUBKEY_LEN];
    hk.expand(context_string.as_bytes(), &mut okm)
        .expect("32 bytes is within HKDF-SHA-512 max output length");
    let secret = SecretBox::new(Box::new(okm));
    okm.zeroize();
    secret
}