use anyhow::Result;

use crate::traits::{FramedReceiver, FramedSender, FramedStream, SplittableStream};

// combined stream so it can easily be split
pub struct Duplex<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> Duplex<R, W> {
    pub fn from_halves(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

impl<R: FramedReceiver, W: FramedSender> FramedStream for Duplex<R, W> {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.writer.send(data).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        self.reader.receive().await
    }
}

impl<R, W> SplittableStream for Duplex<R, W>
where
    R: FramedReceiver + Send + 'static,
    W: FramedSender + Send + 'static,
{
    type Reader = R;
    type Writer = W;
    fn split(self) -> (R, W) {
        (self.reader, self.writer)
    }
}
