pub mod types;
pub mod client;
pub mod server;
pub mod server_identity;

pub use types::*;

#[cfg(test)]
mod tests {
	use anyhow::Result;
	use secrecy::ExposeSecret;
	use tokio::sync::mpsc;
	use crate::traits::FramedStream;

	use super::{client, server, server_identity::ServerIdentity};
	use crate::core::crypto::opaque::OpaqueServer;

	struct ChannelFramed {
		tx: mpsc::Sender<Vec<u8>>,
		rx: mpsc::Receiver<Vec<u8>>,
	}

	impl FramedStream for ChannelFramed {
		async fn send(&mut self, data: &[u8]) -> Result<()> {
			self.tx.send(data.to_vec()).await?;
			Ok(())
		}

		async fn receive(&mut self) -> Result<Vec<u8>> {
			self.rx.recv().await.ok_or_else(|| anyhow::anyhow!("channel closed"))
		}
	}

	fn make_pair() -> (ChannelFramed, ChannelFramed) {
		let (tx_a, rx_a) = mpsc::channel(8);
		let (tx_b, rx_b) = mpsc::channel(8);
		(
			ChannelFramed { tx: tx_a, rx: rx_b },
			ChannelFramed { tx: tx_b, rx: rx_a },
		)
	}

	#[tokio::test]
	async fn test_register_login() -> Result<()> {
		let password = b"128-byte-passwordlasdjf;asjfasjdf;askdfj;asdjf;klajsdfl;kjas;ldfja;sjf;lasjdf;klajsdf;lkjas;fja;dfjasjdf;aksjdfa;skdjfa;as;dkjll";
		let username = "alice";
		let fingerprint = rand::random::<[u8; 32]>();

		let identity = ServerIdentity::generate()?;
		let mut opaque = OpaqueServer::new();

		// register
		let (mut c, mut s) = make_pair();
		let (client_res, server_res) = tokio::join!(
			client::register(password, &mut c),
			server::handle_registration(&identity, &mut opaque, username, &fingerprint, &mut s),
		);
		let (enrollment, export_key) = client_res?;
		let blob = server_res?;

		assert!(!export_key.expose_secret().iter().all(|&b| b == 0));
		assert!(!blob.is_empty());

		// login
		let (mut c, mut s) = make_pair();
		let (client_res, server_res) = tokio::join!(
			client::login(password, &enrollment, &mut c),
			server::handle_login(&identity, &opaque, username, &blob, &mut s),
		);

		let cl = client_res?;
		let sl = server_res?;

		assert_eq!(cl.session_key.expose_secret(), sl.session_key.expose_secret());
		assert_eq!(cl.transport_key.expose_secret(), sl.transport_key.expose_secret());

		Ok(())
	}
}
