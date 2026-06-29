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

// test thing
const ENCRYPT_STREAMS: bool = true;

impl Duplex<CoreReader, CoreWriter> {
    pub fn new(
        connection: (quinn::SendStream, quinn::RecvStream),
        noise_transport: Arc<StatelessTransportState>,
        stream_id: u16,
        module_transport_key: SecretBox<[u8; 32]>,
    ) -> Self {
        let quic = QuicStream::new(connection);
        if ENCRYPT_STREAMS {
            let noise = NoiseStream::new(quic, noise_transport, stream_id);
            let xchacha = XChaChaStream::new(noise, module_transport_key);
            let (reader, writer) = xchacha.split();
            Duplex::from_halves(CoreReader::Encrypted(reader), CoreWriter::Encrypted(writer))
        } else {
            let (reader, writer) = quic.split();
            Duplex::from_halves(CoreReader::Raw(reader), CoreWriter::Raw(writer))
        }
    }

    pub async fn send_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        self.writer_mut().send_message(message).await
    }

    pub async fn receive_message<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.reader_mut().receive_message().await
    }
}

// raw QUIC half when ENCRYPT_STREAMS is off, full crypto stack when on
pub enum CoreReader {
    Encrypted(XChaChaReader<NoiseReader<QuicReader>>),
    Raw(QuicReader),
}

pub enum CoreWriter {
    Encrypted(XChaChaWriter<NoiseWriter<QuicWriter>>),
    Raw(QuicWriter),
}

impl CoreReader {
    pub async fn receive_message<T: DeserializeOwned>(&mut self) -> Result<T> {
        let bytes = self.receive().await?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

impl CoreWriter {
    pub async fn send_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        let bytes = postcard::to_allocvec(message)?;
        self.send(&bytes).await
    }
}

impl FramedReceiver for CoreReader {
    async fn receive(&mut self) -> Result<Vec<u8>> {
        match self {
            CoreReader::Encrypted(r) => r.receive().await,
            CoreReader::Raw(r) => r.receive().await,
        }
    }
}

impl FramedSender for CoreWriter {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        match self {
            CoreWriter::Encrypted(w) => w.send(data).await,
            CoreWriter::Raw(w) => w.send(data).await,
        }
    }
}
