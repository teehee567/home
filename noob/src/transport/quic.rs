use anyhow::Result;
use quinn::{RecvStream, SendStream};

use crate::traits::{FramedReceiver, FramedSender, FramedStream, SplittableStream};

pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    pub fn new(connection: (SendStream, RecvStream)) -> Self {
        Self { send: connection.0, recv: connection.1 }
    }

    pub fn split(self) -> (QuicReader, QuicWriter) {
        (QuicReader { recv: self.recv }, QuicWriter { send: self.send })
    }
}

impl FramedStream for QuicStream {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        self.send.write_all(&len).await?;
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

impl SplittableStream for QuicStream {
    type Reader = QuicReader;
    type Writer = QuicWriter;
    fn split(self) -> (QuicReader, QuicWriter) {
        QuicStream::split(self)
    }
}

pub struct QuicReader {
    recv: RecvStream,
}

pub struct QuicWriter {
    send: SendStream,
}

impl FramedReceiver for QuicReader {
    async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.recv.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

impl FramedSender for QuicWriter {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        self.send.write_all(&len).await?;
        self.send.write_all(data).await?;
        Ok(())
    }
}
