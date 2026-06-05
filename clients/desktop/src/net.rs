use std::net::SocketAddr;

use anyhow::Result;
use noob::core::crypto::tls;
use noob::transport::quic;
use quinn::{Connection, Endpoint};

const CLIENT_CERT: &[u8] = include_bytes!("../../../out/certs/client-cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("../../../out/certs/client-key.der");
const PINNED_SERVER_CERT: &[u8] = include_bytes!("../../../out/certs/server-cert.der");