//! Typed remote handles — call a module hosted on another node exactly like a local one.

use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::broadcast;

use crate::modules::{Module, Routed};
use crate::transport::conn_manager::Peer;

pub struct RemoteHandle<M> {
    peer: Arc<Peer>,
    _marker: PhantomData<fn() -> M>,
}

impl<M: Module + Routed> RemoteHandle<M> {
    pub fn new(peer: Arc<Peer>) -> Self {
        Self { peer, _marker: PhantomData }
    }

    pub async fn request(&self, req: M::Request) -> Result<M::Response> {
        let bytes = postcard::to_allocvec(&req)?;
        let resp = self.peer.request(M::ID, bytes).await?;
        Ok(postcard::from_bytes(&resp)?)
    }

    pub fn subscribe(&self) -> RemoteEvents<M> {
        RemoteEvents { inner: self.peer.subscribe(M::ID), _marker: PhantomData }
    }
}

pub struct RemoteEvents<M> {
    inner: broadcast::Receiver<Vec<u8>>,
    _marker: PhantomData<fn() -> M>,
}

impl<M: Module> RemoteEvents<M> {
    pub async fn recv(&mut self) -> Result<M::Event> {
        loop {
            match self.inner.recv().await {
                Ok(bytes) => return Ok(postcard::from_bytes(&bytes)?),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}
