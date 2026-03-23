use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::framed::FramedStream;

pub struct QuicStream<W, R> {
    send: W,
    recv: R,
}

impl<W: AsyncWriteExt + Unpin + Send, R: AsyncReadExt + Unpin + Send> QuicStream<W, R> {
    pub fn new(send: W, recv: R) -> Self {
        Self { send, recv }
    }
}

impl<W: AsyncWriteExt + Unpin + Send, R: AsyncReadExt + Unpin + Send> FramedStream for QuicStream<W, R> {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = u32::try_from(data.len()).context("message too large")?;
        self.send.write_all(&len.to_be_bytes()).await?;
        self.send.write_all(data).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        self.recv.read_exact(&mut buf).await?;
        Ok(buf)
    }
}
