mod opaque_server;
mod opaque_client;

use opaque_ke::{CipherSuite, Ristretto255, TripleDh, argon2::Argon2};
pub use opaque_server::*;
pub use opaque_client::*;
use sha2::Sha512;

struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use secrecy::ExposeSecret;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use transport::framed::FramedStream;

    struct DuplexFramed(tokio::io::DuplexStream);

    impl FramedStream for DuplexFramed {
        async fn send(&mut self, data: &[u8]) -> Result<()> {
            let len = (data.len() as u32).to_be_bytes();
            self.0.write_all(&len).await?;
            self.0.write_all(data).await?;
            Ok(())
        }

        async fn receive(&mut self) -> Result<Vec<u8>> {
            let mut len_buf = [0u8; 4];
            self.0.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            self.0.read_exact(&mut buf).await?;
            Ok(buf)
        }
    }

    fn make_pair() -> (DuplexFramed, DuplexFramed) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (DuplexFramed(a), DuplexFramed(b))
    }

    #[tokio::test]
    async fn register_then_login() {
        let password = b"128-byte-passwordlasdjf;asjfasjdf;askdfj;asdjf;klajsdfl;kjas;ldfja;sjf;lasjdf;klajsdf;lkjas;fja;dfjasjdf;aksjdfa;skdjfa;as;dkjll";
        let username = "king noob";

        let mut server = OpaqueServer::new();

        // register
        let (mut client_stream, mut server_stream) = make_pair();

        let (export_key, _) = tokio::join!(
            OpaqueClient::register(password, &mut client_stream),
            server.register(username, &mut server_stream),
        );
        let export_key = export_key.unwrap();
        assert!(server.has_user(username));

        // login
        let (mut client_stream, mut server_stream) = make_pair();

        let (client_result, server_sk) = tokio::join!(
            OpaqueClient::login(password, &mut client_stream),
            server.login(username, &mut server_stream),
        );
        let client_result = client_result.unwrap();
        let server_sk = server_sk.unwrap();

        assert_eq!(
            server_sk.expose_secret(),
            client_result.session_key.expose_secret(),
        );
        assert_eq!(
            export_key.expose_secret(),
            client_result.export_key.expose_secret(),
        );
    }
}