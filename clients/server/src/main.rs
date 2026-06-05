use std::net::SocketAddr;

use anyhow::Result;
use noob::core::crypto::tls;
use noob::transport::quic;

const SERVER_CERT: &[u8] = include_bytes!("../../../out/certs/server-cert.der");
const SERVER_KEY: &[u8] = include_bytes!("../../../out/certs/server-key.der");
const PINNED_CLIENT_CERT: &[u8] = include_bytes!("../../../out/certs/client-cert.der");

#[tokio::main]
async fn main() -> Result<()> {
    println!("home server starting");

    Ok(())
}
