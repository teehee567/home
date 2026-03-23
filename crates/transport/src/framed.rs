use anyhow::Result;
use std::future::Future;

pub trait FramedStream {
    fn send(&mut self, data: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn receive(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

