use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};

use super::duplex::Duplex;
use crate::core::crypto::tls;
use crate::traits::{FramedReceiver, FramedSender};

pub type QuicStream = Duplex<QuicReader, QuicWriter>;

impl Duplex<QuicReader, QuicWriter> {
    pub fn new(connection: (SendStream, RecvStream)) -> Self {
        Duplex::from_halves(
            QuicReader { recv: connection.1 },
            QuicWriter { send: connection.0 },
        )
    }
}

pub struct QuicReader {
    recv: RecvStream,
}

pub struct QuicWriter {
    send: SendStream,
}

impl QuicReader {
    /// Recover the underlying quinn stream (to reuse a post-handshake stream as data).
    pub fn into_recv(self) -> RecvStream {
        self.recv
    }
}

impl QuicWriter {
    pub fn into_send(self) -> SendStream {
        self.send
    }
}

impl FramedReceiver for QuicReader {
    async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.recv.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

impl FramedSender for QuicWriter {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        self.send.write_all(&len).await?;
        self.send.write_all(data).await?;
        Ok(())
    }
}

pub fn server_endpoint(
    addr: SocketAddr,
    server_cert: CertificateDer<'static>,
    server_key: PrivatePkcs8KeyDer<'static>,
    pinned_client_cert: CertificateDer<'static>,
) -> Result<Endpoint> {
    let crypto = tls::server_config(server_cert, server_key, pinned_client_cert)?;
    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    Ok(Endpoint::server(server_config, addr)?)
}

pub fn client_endpoint(
    bind_addr: SocketAddr,
    client_cert: CertificateDer<'static>,
    client_key: PrivatePkcs8KeyDer<'static>,
    pinned_server_cert: CertificateDer<'static>,
) -> Result<Endpoint> {
    let crypto = tls::client_config(client_cert, client_key, pinned_server_cert)?;
    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}