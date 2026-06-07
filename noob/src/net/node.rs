use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use quinn::{Endpoint, Incoming};

use crate::core::auth::server_identity::ServerIdentity;
use crate::modules::Modules;
use crate::net::{STREAM_ID, auth};
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

    // accept incomming connections
    pub async fn listen(self: Arc<Self>, identity: Arc<ServerIdentity>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let node = self.clone();
            let identity = identity.clone();
            tokio::spawn(async move {
                let _ = node.accept_one(incoming, identity).await;
            });
        }
    }

    async fn accept_one(&self, incoming: Incoming, identity: Arc<ServerIdentity>) -> Result<PeerId> {
        let conn = incoming.accept()?.await?;
        let (s, r) = conn.accept_bi().await?;
        let mut hs = QuicStream::new((s, r));
        let (transport, key) = auth::server(&mut hs, &identity).await?;

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into(), reader.into()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        self.pool.attach(id, core);

        tokio::spawn(async move { let _ = conn.closed().await; });
        Ok(id)
    }

    pub async fn connect(&self, addr: SocketAddr, server_name: &str, password: &[u8]) -> Result<Arc<Peer>> {
        let conn = self.endpoint.connect(addr, server_name)?.await?;
        let (s, r) = conn.open_bi().await?;
        let mut hs = QuicStream::new((s, r));
        let (transport, key) = auth::client(&mut hs, password).await?;

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into(), reader.into()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        let peer = self.pool.attach(id, core);

        tokio::spawn(async move { let _ = conn.closed().await; });
        Ok(peer)
    }
}
