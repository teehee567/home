use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow};
use quinn::{Endpoint, Incoming};
use sea_orm::DatabaseConnection;

use crate::consts::ACCOUNT_ID;
use crate::core::auth::node_identity::NodeIdentity;
use crate::core::auth::{HandshakeIntent, client, client_store, server, server_store};
use crate::core::crypto::opaque::OpaqueServer;
use crate::modules::Modules;
use crate::net::{NetStats, STREAM_ID};
use crate::traits::{FramedStream, SplittableStream};
use crate::transport::conn_manager::{Peer, PeerId, PeerPool};
use crate::transport::core_stream::CoreStream;
use crate::transport::quic::QuicStream;

// for testing
const DEV_TLS_FINGERPRINT: [u8; 32] = [0u8; 32];

// node in mesh, every node is identical in theoyr, the server is the authority node that gets 
// authority modules spawned in it
pub struct Node {
    endpoint: Endpoint,
    pool: Arc<PeerPool<Modules>>,
    modules: Arc<Modules>,
    next_peer: AtomicU64,
    identity: Arc<NodeIdentity>,
    // setup only, records in db
    opaque: Arc<OpaqueServer>,
    db: DatabaseConnection,
    // live quinn connections, read by the metrics module
    net_stats: NetStats,
}

impl Node {
    pub fn new(
        endpoint: Endpoint,
        modules: Arc<Modules>,
        identity: Arc<NodeIdentity>,
        opaque: Arc<OpaqueServer>,
        db: DatabaseConnection,
        net_stats: NetStats,
    ) -> Arc<Self> {
        let pool = PeerPool::new(modules.clone());
        modules.broadcast_events(pool.clone());
        Arc::new(Self {
            endpoint,
            pool,
            modules,
            next_peer: AtomicU64::new(1),
            identity,
            opaque,
            db,
            net_stats,
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

        // register or login
        let intent: HandshakeIntent = postcard::from_bytes(&hs.receive().await?)
            .context("malformed handshake intent")?;

        if intent == HandshakeIntent::Register {
            let outcome = server::handle_registration(
                &self.identity,
                &self.opaque,
                ACCOUNT_ID,
                &DEV_TLS_FINGERPRINT,
                &mut hs,
            )
            .await?;
            server_store::persist_registration(
                &self.db,
                ACCOUNT_ID,
                &outcome.registration_record,
                &outcome.at_rest_blob,
            )
            .await?;
        }

        // creds from db
        let (record, at_rest) = server_store::fetch_user(&self.db, ACCOUNT_ID)
            .await?
            .ok_or_else(|| anyhow!("login for unregistered user"))?;
        let res = server::handle_login(
            &self.identity,
            &self.opaque,
            ACCOUNT_ID,
            &record,
            &at_rest,
            &mut hs,
        )
        .await?;
        let (transport, key) = (res.transport, res.transport_key);

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into(), reader.into()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        self.pool.attach(id, core);
        self.net_stats.insert(id, conn.clone());

        let net_stats = self.net_stats.clone();
        tokio::spawn(async move {
            let _ = conn.closed().await;
            net_stats.remove(id);
        });
        Ok(id)
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        credential: &[u8],
    ) -> Result<Arc<Peer>> {
        let conn = self.endpoint.connect(addr, server_name)?.await?;
        let (s, r) = conn.open_bi().await?;
        let mut hs = QuicStream::new((s, r));

        // login if enrolled else register first
        let enrollment = match client_store::load_enrollment(&self.db).await? {
            Some(enrollment) => {
                hs.send(&postcard::to_allocvec(&HandshakeIntent::Login)?).await?;
                enrollment
            }
            None => {
                hs.send(&postcard::to_allocvec(&HandshakeIntent::Register)?).await?;
                let (enrollment, _export_key) = client::register(credential, &mut hs).await?;
                client_store::persist_enrollment(&self.db, &enrollment).await?;
                enrollment
            }
        };

        let res = client::login(credential, &enrollment, &mut hs).await?;
        let (transport, key) = (res.transport, res.transport_key);

        let (reader, writer) = hs.split();
        let core = CoreStream::new((writer.into(), reader.into()), transport, STREAM_ID, key);
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        let peer = self.pool.attach(id, core);
        self.net_stats.insert(id, conn.clone());

        let net_stats = self.net_stats.clone();
        tokio::spawn(async move {
            let _ = conn.closed().await;
            net_stats.remove(id);
        });
        Ok(peer)
    }
}
