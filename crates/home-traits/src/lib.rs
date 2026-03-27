use anyhow::Result;

#[trait_variant::make(Send)]
pub trait FramedStream {
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn receive(&mut self) -> Result<Vec<u8>>;
}
