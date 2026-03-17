use blake3;

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

pub fn hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

pub struct Hasher(blake3::Hasher);

impl Hasher {
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    pub fn keyed(key: &[u8; HASH_LEN]) -> Self {
        Self(blake3::Hasher::new_keyed(key))
    }

    pub fn derive_key(context: &str) -> Self {
        Self(blake3::Hasher::new_derive_key(context))
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    pub fn finalize(&self) -> Hash {
        *self.0.finalize().as_bytes()
    }

    pub fn reset(&mut self) -> &mut Self {
        self.0.reset();
        self
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_matches_streaming() {
        let data = b"bruh";
        let one_shot = hash(data);

        let streaming = Hasher::new().update(data).finalize();
        assert_eq!(one_shot, streaming);
    }

    #[test]
    fn incremental_chunks_match_one_shot() {
        let full = b"bruh";
        let expected = hash(full);

        let mut h = Hasher::new();
        h.update(b"br").update(b"uh");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn keyed_differs_from_unkeyed() {
        let data = b"bruh";
        let key = [0x42u8; HASH_LEN];

        let unkeyed = hash(data);
        let keyed = Hasher::keyed(&key).update(data).finalize();
        assert_ne!(unkeyed, keyed);
    }

    #[test]
    fn derive_key_deterministic() {
        let ctx = "noob";
        let a = Hasher::derive_key(ctx).update(b"bruh").finalize();
        let b = Hasher::derive_key(ctx).update(b"bruh").finalize();
        assert_eq!(a, b);
    }

    #[test]
    fn reset_clears_state() {
        let mut h = Hasher::new();
        h.update(b"bruh");
        h.reset();
        h.update(b"meow");
        assert_eq!(h.finalize(), hash(b"meow"));
    }
}
