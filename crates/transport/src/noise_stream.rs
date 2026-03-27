use anyhow::Result;
use snow::TransportState;

use home_traits::FramedStream;

const NOISE_MAX_MSG: usize = 65535;

pub struct NoiseStream<T> {
    inner: T,
    transport: TransportState,
    encrypt_buf: Vec<u8>,
    decrypt_buf: Vec<u8>,
}

impl<T> NoiseStream<T> {
    pub fn new(inner: T, transport: TransportState) -> Self {
        Self {
            inner,
            transport,
            encrypt_buf: vec![0u8; NOISE_MAX_MSG],
            decrypt_buf: vec![0u8; NOISE_MAX_MSG],
        }
    }
}

impl<T: FramedStream> FramedStream for NoiseStream<T> {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let needed = data.len() + 16;
        if self.encrypt_buf.len() < needed {
            self.encrypt_buf.resize(needed, 0);
        }
        let len = self
            .transport
            .write_message(data, &mut self.encrypt_buf)?;
        self.inner.send(&self.encrypt_buf[..len]).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let ciphertext = self.inner.receive().await?;
        let needed = ciphertext.len();
        if self.decrypt_buf.len() < needed {
            self.decrypt_buf.resize(needed, 0);
        }
        let len = self
            .transport
            .read_message(&ciphertext, &mut self.decrypt_buf)?;
        Ok(self.decrypt_buf[..len].to_vec())
    }
}
