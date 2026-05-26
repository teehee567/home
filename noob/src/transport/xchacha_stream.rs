use std::sync::Arc;

use anyhow::Result;
use secrecy::SecretBox;

use crate::core::crypto::aead;
use crate::traits::{FramedReceiver, FramedSender, FramedStream, SplittableStream};

pub struct XChaChaStream<T> {
    inner: T,
    key: Arc<SecretBox<[u8; 32]>>,
}

impl<T> XChaChaStream<T> {
    pub fn new(inner: T, key: SecretBox<[u8; 32]>) -> Self {
        Self { inner, key: Arc::new(key) }
    }

    pub fn from_arc(inner: T, key: Arc<SecretBox<[u8; 32]>>) -> Self {
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

impl<T: SplittableStream> SplittableStream for XChaChaStream<T> {
    type Writer = XChaChaWriter<T::Writer>;
    type Reader = XChaChaReader<T::Reader>;
    fn split(self) -> (Self::Reader, Self::Writer) {
        let (r, w) = self.inner.split();
        (
            XChaChaReader { inner: r, key: self.key.clone(), decrypt_buf: Vec::new() },
            XChaChaWriter { inner: w, key: self.key, encrypt_buf: Vec::new() },
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

