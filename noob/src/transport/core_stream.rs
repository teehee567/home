use std::sync::Arc;

use anyhow::Result;
use quinn::{RecvStream, SendStream};
use secrecy::SecretBox;
use serde::{Serialize, de::DeserializeOwned};
use snow::StatelessTransportState;

use crate::traits::{FramedReceiver, FramedSender, FramedStream, SplittableStream};
use super::noise_stream::{NoiseReader, NoiseStream, NoiseWriter};
use super::quic::{QuicReader, QuicStream, QuicWriter};
use super::xchacha_stream::{XChaChaReader, XChaChaStream, XChaChaWriter};

pub struct CoreStream {
    inner: XChaChaStream<NoiseStream<QuicStream>>,
}

impl CoreStream {
    pub fn new(
        connection: (SendStream, RecvStream),
        noise_transport: Arc<StatelessTransportState>,
        stream_id: u16,
        module_transport_key: SecretBox<[u8; 32]>,
    ) -> Self {
        let quic = QuicStream::new(connection);
        let noise = NoiseStream::new(quic, noise_transport, stream_id);
        let xchacha = XChaChaStream::new(noise, module_transport_key);
        Self { inner: xchacha }
    }

    pub fn split(self) -> (CoreReader, CoreWriter) {
        let (r, w) = self.inner.split();
        (CoreReader { inner: r }, CoreWriter { inner: w })
    }
}

impl CoreStream {
    pub async fn send_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        let bytes = postcard::to_allocvec(message)?;
        self.inner.send(&bytes).await
    }

    pub async fn receive_message<T: DeserializeOwned>(&mut self) -> Result<T> {
        let bytes = self.inner.receive().await?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

impl FramedStream for CoreStream {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.inner.send(data).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        self.inner.receive().await
    }
}

impl SplittableStream for CoreStream {
    type Reader = CoreReader;
    type Writer = CoreWriter;
    fn split(self) -> (CoreReader, CoreWriter) {
        CoreStream::split(self)
    }
}

pub struct CoreReader {
    inner: XChaChaReader<NoiseReader<QuicReader>>,
}

pub struct CoreWriter {
    inner: XChaChaWriter<NoiseWriter<QuicWriter>>,
}

impl CoreReader {
    pub async fn receive_message<T: DeserializeOwned>(&mut self) -> Result<T> {
        let bytes = self.inner.receive().await?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

impl CoreWriter {
    pub async fn send_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        let bytes = postcard::to_allocvec(message)?;
        self.inner.send(&bytes).await
    }
}

impl FramedReceiver for CoreReader {
    async fn receive(&mut self) -> Result<Vec<u8>> {
        self.inner.receive().await
    }
}

impl FramedSender for CoreWriter {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.inner.send(data).await
    }
}
