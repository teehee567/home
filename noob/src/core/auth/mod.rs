pub mod types;
pub mod client;
pub mod server;
pub mod server_store;
pub mod client_store;
pub mod node_identity;

pub use types::*;

#[cfg(test)]
mod tests {
	use anyhow::Result;
	use secrecy::ExposeSecret;
	use tokio::sync::mpsc;
	use crate::traits::FramedStream;

	use super::{client, server, node_identity::NodeIdentity};
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

		let identity = NodeIdentity::generate()?;
		let opaque = OpaqueServer::new();

		// register
		let (mut c, mut s) = make_pair();
		let (client_res, server_res) = tokio::join!(
			client::register(password, &mut c),
			server::handle_registration(&identity, &opaque, username, &fingerprint, &mut s),
		);
		let (enrollment, export_key) = client_res?;
		let outcome = server_res?;

		assert!(!export_key.expose_secret().iter().all(|&b| b == 0));
		assert!(!outcome.registration_record.is_empty());
		assert!(!outcome.at_rest_blob.is_empty());

		// login
		let (mut c, mut s) = make_pair();
		let (client_res, server_res) = tokio::join!(
			client::login(password, &enrollment, &mut c),
			server::handle_login(
				&identity,
				&opaque,
				username,
				&outcome.registration_record,
				&outcome.at_rest_blob,
				&mut s,
			),
		);

		let cl = client_res?;
		let sl = server_res?;

		assert_eq!(cl.session_key.expose_secret(), sl.session_key.expose_secret());
		assert_eq!(cl.transport_key.expose_secret(), sl.transport_key.expose_secret());

		Ok(())
	}
}

#[cfg(test)]
mod persistence_tests {
	use anyhow::Result;
	use secrecy::ExposeSecret;

	use super::node_identity::NodeIdentity;
	use super::{ClientEnrollment, client, client_store, server, server_store};
	use crate::storage::NodeDeps;

	#[tokio::test]
	async fn identity_is_stable_across_loads() -> Result<()> {
		let deps = NodeDeps::memory().await?;
		let first = NodeIdentity::load_or_generate(&deps.db()).await?;
		let second = NodeIdentity::load_or_generate(&deps.db()).await?;

		assert_eq!(first.noise_public_key(), second.noise_public_key());
		assert_eq!(first.ml_kem_public_key_bytes(), second.ml_kem_public_key_bytes());
		Ok(())
	}

	#[tokio::test]
	async fn opaque_setup_round_trips() -> Result<()> {
		let deps = NodeDeps::memory().await?;
		let first = server_store::load_opaque_server(&deps.db()).await?;
		let second = server_store::load_opaque_server(&deps.db()).await?;
		assert_eq!(first.serialize_setup(), second.serialize_setup());
		Ok(())
	}

	#[tokio::test]
	async fn client_enrollment_round_trips() -> Result<()> {
		let deps = NodeDeps::memory().await?;
		assert!(client_store::load_enrollment(&deps.db()).await?.is_none());

		let enrollment = ClientEnrollment {
			server_noise_pubkey: [7u8; 32],
			server_ml_kem_pubkey: vec![1, 2, 3, 4],
			tls_cert_fingerprint: [9u8; 32],
		};
		client_store::persist_enrollment(&deps.db(), &enrollment).await?;

		let loaded = client_store::load_enrollment(&deps.db()).await?.expect("enrollment");
		assert_eq!(loaded.server_noise_pubkey, enrollment.server_noise_pubkey);
		assert_eq!(loaded.server_ml_kem_pubkey, enrollment.server_ml_kem_pubkey);
		assert_eq!(loaded.tls_cert_fingerprint, enrollment.tls_cert_fingerprint);
		Ok(())
	}

	// login after reload
	#[tokio::test]
	async fn login_works_after_reload() -> Result<()> {
		use tokio::sync::mpsc;

		use crate::traits::FramedStream;

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
			(ChannelFramed { tx: tx_a, rx: rx_b }, ChannelFramed { tx: tx_b, rx: rx_a })
		}

		let password = b"128-byte-passwordlasdjf;asjfasjdf;askdfj;asdjf;klajsdfl;kjas;ldfja;sjf;lasjdf;klajsdf;lkjas;fja;dfjasjdf;aksjdfa;skdjfa;as;dkjll";
		let username = crate::consts::ACCOUNT_ID;
		let fingerprint = [0u8; 32];

		let deps = NodeDeps::memory().await?;
		let identity = NodeIdentity::load_or_generate(&deps.db()).await?;

		// register then persist
		let opaque = server_store::load_opaque_server(&deps.db()).await?;
		let (mut c, mut s) = make_pair();
		let (client_res, server_res) = tokio::join!(
			client::register(password, &mut c),
			server::handle_registration(&identity, &opaque, username, &fingerprint, &mut s),
		);
		let (enrollment, _export_key) = client_res?;
		let outcome = server_res?;
		server_store::persist_registration(
			&deps.db(),
			username,
			&outcome.registration_record,
			&outcome.at_rest_blob,
		)
		.await?;

		// reload and login
		let identity = NodeIdentity::load_or_generate(&deps.db()).await?;
		let opaque = server_store::load_opaque_server(&deps.db()).await?;
		let (record, at_rest) =
			server_store::fetch_user(&deps.db(), username).await?.expect("registered user");

		let (mut c, mut s) = make_pair();
		let (client_res, server_res) = tokio::join!(
			client::login(password, &enrollment, &mut c),
			server::handle_login(&identity, &opaque, username, &record, &at_rest, &mut s),
		);
		let cl = client_res?;
		let sl = server_res?;
		assert_eq!(cl.session_key.expose_secret(), sl.session_key.expose_secret());
		assert_eq!(cl.transport_key.expose_secret(), sl.transport_key.expose_secret());
		Ok(())
	}
}
