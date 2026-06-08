use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use noob::modules::Modules;
use noob::net::Node;
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

    let modules = Arc::new(Modules::spawn());
    let node = Node::new(endpoint, modules);

    println!("home server listening on {addr}");
    node.listen().await;
    Ok(())
}
