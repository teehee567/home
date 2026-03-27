use anyhow::Result;
use secrecy::SecretBox;
use snow::TransportState;
use quinn::{RecvStream, SendStream};

use noob_traits::FramedStream;
use crate::noise_stream::NoiseStream;
use crate::quic::QuicStream;
use crate::xchacha_stream::XChaChaStream;
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

impl FramedStream for CoreStream {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.inner.send(data).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        self.inner.receive().await
    }
}
