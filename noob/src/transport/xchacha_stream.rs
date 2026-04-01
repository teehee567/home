use anyhow::Result;
use secrecy::SecretBox;

use crate::core::crypto::aead;
use crate::traits::FramedStream;

pub struct XChaChaStream<T> {
    inner: T,
    key: SecretBox<[u8; 32]>,
}

impl<T> XChaChaStream<T> {
    pub fn new(inner: T, key: SecretBox<[u8; 32]>) -> Self {
        Self { inner, key }
    }
}

impl<T: FramedStream> FramedStream for XChaChaStream<T> {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let out = aead::encrypt(&self.key, data)?;
        self.inner.send(&out).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let raw = self.inner.receive().await?;
        aead::decrypt(&self.key, &raw)
    }
}
