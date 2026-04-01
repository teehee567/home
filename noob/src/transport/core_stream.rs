use anyhow::Result;
use secrecy::SecretBox;
use serde::{Serialize, de::DeserializeOwned};
use snow::TransportState;
use quinn::{RecvStream, SendStream};

use crate::traits::FramedStream;
use super::noise_stream::NoiseStream;
use super::quic::QuicStream;
use super::xchacha_stream::XChaChaStream;

pub struct CoreStream {
    inner: XChaChaStream<NoiseStream<QuicStream>>,
}

impl CoreStream {
    pub fn new(
        connection: (SendStream, RecvStream),
        noise_transport: TransportState,
        module_transport_key: SecretBox<[u8; 32]>,
    ) -> Self {
        let quic = QuicStream::new(connection);
        let noise = NoiseStream::new(quic, noise_transport);
        let xchacha = XChaChaStream::new(noise, module_transport_key);
        Self { inner: xchacha }
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
