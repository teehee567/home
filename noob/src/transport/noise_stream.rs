use std::sync::Arc;

use anyhow::Result;
use snow::StatelessTransportState;

use super::duplex::Duplex;
use crate::traits::{FramedReceiver, FramedSender, SplittableStream};

pub type NoiseStream<R, W> = Duplex<NoiseReader<R>, NoiseWriter<W>>;

impl<R, W> Duplex<NoiseReader<R>, NoiseWriter<W>> {
    pub fn new<I>(inner: I, transport: Arc<StatelessTransportState>, stream_id: u16) -> Self
    where
        I: SplittableStream<Reader = R, Writer = W>,
    {
        let (r, w) = inner.split();
        Duplex::from_halves(
            NoiseReader {
                inner: r,
                transport: transport.clone(),
                stream_id,
                recv_counter: 0,
                decrypt_buf: vec![0u8],
            },
            NoiseWriter {
                inner: w,
                transport,
                stream_id,
                send_counter: 0,
                encrypt_buf: vec![0u8],
            },
        )
    }
}

fn nonce(stream_id: u16, counter: u64) -> u64 {
    ((stream_id as u64) << 48) | (counter & 0x0000_FFFF_FFFF_FFFF)
}

pub struct NoiseReader<R> {
    inner: R,
    transport: Arc<StatelessTransportState>,
    stream_id: u16,
    recv_counter: u64,
    decrypt_buf: Vec<u8>,
}

pub struct NoiseWriter<W> {
    inner: W,
    transport: Arc<StatelessTransportState>,
    stream_id: u16,
    send_counter: u64,
    encrypt_buf: Vec<u8>,
}

impl<R: FramedReceiver> FramedReceiver for NoiseReader<R> {
    async fn receive(&mut self) -> Result<Vec<u8>> {
        let ciphertext = self.inner.receive().await?;
        let needed = ciphertext.len();
        if self.decrypt_buf.len() < needed {
            self.decrypt_buf.resize(needed, 0);
        }
        let n = nonce(self.stream_id, self.recv_counter);
        let len = self
            .transport
            .read_message(n, &ciphertext, &mut self.decrypt_buf)?;
        self.recv_counter += 1;
        Ok(self.decrypt_buf[..len].to_vec())
    }
}

impl<W: FramedSender> FramedSender for NoiseWriter<W> {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let needed = data.len() + 16;
        if self.encrypt_buf.len() < needed {
            self.encrypt_buf.resize(needed, 0);
        }
        let n = nonce(self.stream_id, self.send_counter);
        let len = self
            .transport
            .write_message(n, data, &mut self.encrypt_buf)?;
        self.send_counter += 1;
        self.inner.send(&self.encrypt_buf[..len]).await
    }
}
