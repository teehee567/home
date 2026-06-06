use std::sync::Arc;

use anyhow::Result;
use secrecy::SecretBox;
use serde::{Serialize, de::DeserializeOwned};
use snow::StatelessTransportState;

use super::duplex::Duplex;
use super::noise_stream::{NoiseReader, NoiseStream, NoiseWriter};
use super::quic::{QuicReader, QuicStream, QuicWriter};
use super::xchacha_stream::{XChaChaReader, XChaChaStream, XChaChaWriter};
use crate::traits::{FramedReceiver, FramedSender, SplittableStream};

pub type CoreStream = Duplex<CoreReader, CoreWriter>;

impl Duplex<CoreReader, CoreWriter> {
    pub fn new(
        connection: (quinn::SendStream, quinn::RecvStream),
        noise_transport: Arc<StatelessTransportState>,
        stream_id: u16,
        module_transport_key: SecretBox<[u8; 32]>,
    ) -> Self {
        let quic = QuicStream::new(connection);
        let noise = NoiseStream::new(quic, noise_transport, stream_id);
        let xchacha = XChaChaStream::new(noise, module_transport_key);
        let (reader, writer) = xchacha.split();
        Duplex::from_halves(CoreReader { inner: reader }, CoreWriter { inner: writer })
    }

    pub async fn send_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        self.writer_mut().send_message(message).await
    }

    pub async fn receive_message<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.reader_mut().receive_message().await
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
