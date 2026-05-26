use std::sync::Arc;

use anyhow::Result;
use snow::StatelessTransportState;

use crate::traits::{FramedReceiver, FramedSender, FramedStream, SplittableStream};

pub struct NoiseStream<T> {
    inner: T,
    transport: Arc<StatelessTransportState>,
    stream_id: u16,
    send_counter: u64,
    recv_counter: u64,
    encrypt_buf: Vec<u8>,
    decrypt_buf: Vec<u8>,
}

impl<T> NoiseStream<T> {
    pub fn new(inner: T, transport: Arc<StatelessTransportState>, stream_id: u16) -> Self {
        Self {
            inner,
            transport,
            stream_id,
            send_counter: 0,
            recv_counter: 0,
            encrypt_buf: vec![0u8],
            decrypt_buf: vec![0u8],
        }
    }
}

fn nonce(stream_id: u16, counter: u64) -> u64 {
    ((stream_id as u64) << 48) | (counter & 0x0000_FFFF_FFFF_FFFF)
}

impl<T: FramedStream> FramedStream for NoiseStream<T> {
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

impl<T: SplittableStream> SplittableStream for NoiseStream<T> {
    type Reader = NoiseReader<T::Reader>;
    type Writer = NoiseWriter<T::Writer>;
    fn split(self) -> (Self::Reader, Self::Writer) {
        let (r, w) = self.inner.split();
        (
            NoiseReader {
                inner: r,
                transport: self.transport.clone(),
                stream_id: self.stream_id,
                recv_counter: self.recv_counter,
                decrypt_buf: self.decrypt_buf,
            },
            NoiseWriter {
                inner: w,
                transport: self.transport,
                stream_id: self.stream_id,
                send_counter: self.send_counter,
                encrypt_buf: self.encrypt_buf,
            },
        )
    }
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
