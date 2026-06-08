use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use quinn::{Endpoint, Incoming};

use crate::consts::ACCOUNT_ID;
use crate::core::auth::server_identity::ServerIdentity;
use crate::core::auth::{client, server};
use crate::core::crypto::opaque::OpaqueServer;
use crate::modules::Modules;
use crate::net::STREAM_ID;
use crate::storage::secrets::Secrets;
use crate::traits::SplittableStream;
use crate::transport::conn_manager::{Peer, PeerId, PeerPool};
use crate::transport::core_stream::CoreStream;
use crate::transport::quic::QuicStream;

// for testing
const DEV_TLS_FINGERPRINT: [u8; 32] = [0u8; 32];

pub struct Node {
    endpoint: Endpoint,
    pool: Arc<PeerPool<Modules>>,
    modules: Arc<Modules>,
    next_peer: AtomicU64,
    identity: Arc<ServerIdentity>,
    password: Vec<u8>,
}

impl Node {
    pub fn new(endpoint: Endpoint, modules: Arc<Modules>) -> Arc<Self> {
        let pool = PeerPool::new(modules.clone());
        modules.broadcast_events(pool.clone());
        let secrets = Secrets::load(crate::storage::secrets::default_path());
        let identity = Arc::new(ServerIdentity::generate().expect("generate server identity"));
        let password = secrets.password();
        Arc::new(Self {
            endpoint,
            pool,
            modules,
            next_peer: AtomicU64::new(1),
            identity,
            password,
        })
    }

    pub fn pool(&self) -> &Arc<PeerPool<Modules>> {
        &self.pool
    }

    pub fn modules(&self) -> &Arc<Modules> {
        &self.modules
    }

    // accept incomming connections
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

        // temp for testing
        let mut opaque = OpaqueServer::new();
        let blob = server::handle_registration(
            &self.identity,
            &mut opaque,
            ACCOUNT_ID,
            &DEV_TLS_FINGERPRINT,
            &mut hs,
        )
        .await?;
        let res = server::handle_login(&self.identity, &opaque, ACCOUNT_ID, &blob, &mut hs).await?;
        let (transport, key) = (res.transport, res.transport_key);

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into(), reader.into()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        self.pool.attach(id, core);

        tokio::spawn(async move { let _ = conn.closed().await; });
        Ok(id)
    }

    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Arc<Peer>> {
        let conn = self.endpoint.connect(addr, server_name)?.await?;
        let (s, r) = conn.open_bi().await?;
        let mut hs = QuicStream::new((s, r));

        // temp for testing
        let (enrollment, _export_key) = client::register(&self.password, &mut hs).await?;
        let res = client::login(&self.password, &enrollment, &mut hs).await?;
        let (transport, key) = (res.transport, res.transport_key);

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into(), reader.into()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        let peer = self.pool.attach(id, core);

        tokio::spawn(async move { let _ = conn.closed().await; });
        Ok(peer)
    }
}
