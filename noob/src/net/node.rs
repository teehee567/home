//! A symmetric node: hosts `Modules`, and both accepts and dials peers over `CoreStream`.
//!
//! "Server" and "client" are roles — `listen()` vs `dial()`. Both end in `pool.attach`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use quinn::{Endpoint, Incoming};

use crate::modules::Modules;
use crate::net::STREAM_ID;
use crate::traits::SplittableStream;
use crate::transport::conn_manager::{Peer, PeerId, PeerPool};
use crate::transport::core_stream::CoreStream;
use crate::transport::quic::QuicStream;

pub struct Node {
    endpoint: Endpoint,
    pool: Arc<PeerPool<Modules>>,
    modules: Arc<Modules>,
    next_peer: AtomicU64,
}

impl Node {
    pub fn new(endpoint: Endpoint, modules: Arc<Modules>) -> Arc<Self> {
        let pool = PeerPool::new(modules.clone());
        modules.broadcast_events(pool.clone());
        Arc::new(Self { endpoint, pool, modules, next_peer: AtomicU64::new(1) })
    }

    pub fn pool(&self) -> &Arc<PeerPool<Modules>> {
        &self.pool
    }

    pub fn modules(&self) -> &Arc<Modules> {
        &self.modules
    }

    /// Accept inbound connections forever, attaching each as a peer (responder role).
    pub async fn listen(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let node = self.clone();
            tokio::spawn(async move {
                let _ = node.accept_one(incoming).await;
            });
        }
    }

    async fn accept_one(&self, incoming: Incoming) -> Result<PeerId> {
        let conn = incoming.accept()?.await?;
        let (s, r) = conn.accept_bi().await?;
        let mut hs = QuicStream::new((s, r));
        let (transport, key) = todo!();

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into_send(), reader.into_recv()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        self.pool.attach(id, core);

        tokio::spawn(async move { let _ = conn.closed().await; });
        Ok(id)
    }

    /// Dial a remote node (initiator role); returns the attached peer.
    pub async fn dial(&self, addr: SocketAddr, server_name: &str) -> Result<Arc<Peer>> {
        let conn = self.endpoint.connect(addr, server_name)?.await?;
        let (s, r) = conn.open_bi().await?;
        let mut hs = QuicStream::new((s, r));
        let (transport, key) = todo!();

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into_send(), reader.into_recv()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        let peer = self.pool.attach(id, core);

        tokio::spawn(async move { let _ = conn.closed().await; });
        Ok(peer)

    }

}
