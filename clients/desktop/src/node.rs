use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use noob::core::auth::node_identity::NodeIdentity;
use noob::core::auth::server_store;
use noob::modules::Modules;
use noob::net::Node;
use noob::storage::secrets::{self, Secrets};
use noob::storage::{NodeDeps, node_data_dir};
use noob::transport::conn_manager::Peer;
use noob::transport::quic;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::OnceCell;

const CLIENT_CERT: &[u8] = include_bytes!("../../../out/certs/client-cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("../../../out/certs/client-key.der");
const PINNED_SERVER_CERT: &[u8] = include_bytes!("../../../out/certs/server-cert.der");

const DEFAULT_ADDR: &str = "noob.local:4433";

pub struct DesktopNode {
    node: Arc<Node>,
    server_peer: OnceCell<Arc<Peer>>,
}

impl DesktopNode {
    pub async fn new() -> Result<Arc<Self>> {
        let endpoint = quic::client_endpoint(
            "0.0.0.0:0".parse()?,
            CertificateDer::from(CLIENT_CERT),
            PrivatePkcs8KeyDer::from(CLIENT_KEY),
            CertificateDer::from(PINNED_SERVER_CERT),
        )?;
        let deps = NodeDeps::open(node_data_dir("desktop")).await?;
        let modules = Arc::new(Modules::spawn_desktop(&deps).await?);
        let identity = Arc::new(NodeIdentity::load_or_generate(&deps.db()).await?);
        let opaque = Arc::new(server_store::load_opaque_server(&deps.db()).await?);
        let node = Node::new(endpoint, modules, identity, opaque, deps.db());
        Ok(Arc::new(Self { node, server_peer: OnceCell::new() }))
    }

    pub async fn connect_server(&self) -> Result<Arc<Peer>> {
        self.server_peer
            .get_or_try_init(|| async {
                let target = env::var("NOOB_SERVER").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
                let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&target).await?.collect();
                let addr = resolved
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| resolved.first())
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("could not resolve {target}"))?;
                let password = Secrets::load(secrets::default_path()).password();
                self.node.connect(addr, "localhost", &password).await
            })
            .await
            .cloned()
    }

    pub fn modules(&self) -> &Arc<Modules> {
        self.node.modules()
    }

    // to identify main server peer to handle proper server persistence
    #[allow(dead_code)]
    pub fn server_peer(&self) -> Option<Arc<Peer>> {
        self.server_peer.get().cloned()
    }
}
