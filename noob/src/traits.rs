use anyhow::Result;

#[trait_variant::make(Send)]
pub trait FramedStream {
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn receive(&mut self) -> Result<Vec<u8>>;
}

#[trait_variant::make(Send)]
pub trait FramedSender {
    async fn send(&mut self, data: &[u8]) -> Result<()>;
}

#[trait_variant::make(Send)]
pub trait FramedReceiver {
    async fn receive(&mut self) -> Result<Vec<u8>>;
}

pub trait SplittableStream: Send {
    type Reader: FramedReceiver + Send + 'static;
    type Writer: FramedSender + Send + 'static;
    fn split(self) -> (Self::Reader, Self::Writer);
}
