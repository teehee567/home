use std::sync::Arc;

use anyhow::Result;
use secrecy::SecretBox;

use super::duplex::Duplex;
use crate::core::crypto::aead;
use crate::traits::{FramedReceiver, FramedSender, SplittableStream};

pub type XChaChaStream<R, W> = Duplex<XChaChaReader<R>, XChaChaWriter<W>>;

impl<R, W> Duplex<XChaChaReader<R>, XChaChaWriter<W>> {
    pub fn new<I>(inner: I, key: SecretBox<[u8; 32]>) -> Self
    where
        I: SplittableStream<Reader = R, Writer = W>,
    {
        Self::from_arc(inner, Arc::new(key))
    }

    pub fn from_arc<I>(inner: I, key: Arc<SecretBox<[u8; 32]>>) -> Self
    where
        I: SplittableStream<Reader = R, Writer = W>,
    {
        let (r, w) = inner.split();
        Duplex::from_halves(
            XChaChaReader { inner: r, key: key.clone(), decrypt_buf: Vec::new() },
            XChaChaWriter { inner: w, key, encrypt_buf: Vec::new() },
        )
    }
}

pub struct XChaChaReader<R> {
    inner: R,
    key: Arc<SecretBox<[u8; 32]>>,
    decrypt_buf: Vec<u8>,
}

pub struct XChaChaWriter<W> {
    inner: W,
    key: Arc<SecretBox<[u8; 32]>>,
    encrypt_buf: Vec<u8>,
}

impl<R: FramedReceiver> FramedReceiver for XChaChaReader<R> {
    async fn receive(&mut self) -> Result<Vec<u8>> {
        let raw = self.inner.receive().await?;
        aead::decrypt_in(&self.key, &raw, &mut self.decrypt_buf)
    }
}

impl<W: FramedSender> FramedSender for XChaChaWriter<W> {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        aead::encrypt_in(&self.key, data, &mut self.encrypt_buf)?;
        self.inner.send(&self.encrypt_buf).await
    }
}
