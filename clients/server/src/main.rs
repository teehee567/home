use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use noob::core::auth::node_identity::NodeIdentity;
use noob::core::auth::server_store;
use noob::modules::Modules;
use noob::net::Node;
use noob::storage::{NodeDeps, node_data_dir};
use noob::transport::quic;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const SERVER_CERT: &[u8] = include_bytes!("../../../out/certs/server-cert.der");
const SERVER_KEY: &[u8] = include_bytes!("../../../out/certs/server-key.der");
const PINNED_CLIENT_CERT: &[u8] = include_bytes!("../../../out/certs/client-cert.der");

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = "0.0.0.0:4433".parse()?;
    let endpoint = quic::server_endpoint(
        addr,
        CertificateDer::from(SERVER_CERT),
        PrivatePkcs8KeyDer::from(SERVER_KEY),
        CertificateDer::from(PINNED_CLIENT_CERT),
    )?;

    let deps = NodeDeps::open(node_data_dir("server")).await?;
    let modules = Arc::new(Modules::spawn_server(&deps).await?);
    let identity = Arc::new(NodeIdentity::load_or_generate(&deps.db()).await?);
    let opaque = Arc::new(server_store::load_opaque_server(&deps.db()).await?);
    let node = Node::new(endpoint, modules, identity, opaque, deps.db(), deps.net_stats());

    println!("home server listening on {addr}");
    node.listen().await;
    Ok(())
}
