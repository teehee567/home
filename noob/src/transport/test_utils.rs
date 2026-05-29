use std::sync::Arc;

use super::duplex::Duplex;
use crate::traits::{FramedReceiver, FramedSender};
use snow::StatelessTransportState;
use tokio::sync::mpsc;

pub type Chan = Duplex<ChanReader, ChanWriter>;

pub fn chan_pair() -> (Chan, Chan) {
    let (tx1, rx1) = mpsc::unbounded_channel();
    let (tx2, rx2) = mpsc::unbounded_channel();
    (
        Duplex::from_halves(ChanReader { rx: rx2 }, ChanWriter { tx: tx1 }),
        Duplex::from_halves(ChanReader { rx: rx1 }, ChanWriter { tx: tx2 }),
    )
}

pub struct ChanReader {
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

pub struct ChanWriter {
    pub tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl FramedReceiver for ChanReader {
    async fn receive(&mut self) -> anyhow::Result<Vec<u8>> {
        self.rx.recv().await.ok_or_else(|| anyhow::anyhow!("closed"))
    }
}

impl FramedSender for ChanWriter {
    async fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.tx.send(data.to_vec()).map_err(|e| anyhow::anyhow!(e))
    }
}

pub fn noise_pair() -> (Arc<StatelessTransportState>, Arc<StatelessTransportState>) {
    let p: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let ck = snow::Builder::new(p.clone()).generate_keypair().unwrap();
    let sk = snow::Builder::new(p.clone()).generate_keypair().unwrap();
    let mut ini = snow::Builder::new(p.clone())
        .local_private_key(&ck.private).unwrap()
        .remote_public_key(&sk.public).unwrap()
        .build_initiator().unwrap();
    let mut res = snow::Builder::new(p).local_private_key(&sk.private).unwrap().build_responder().unwrap();
    let (mut a, mut b) = ([0u8; 65535], [0u8; 65535]);
    let n = ini.write_message(&[], &mut a).unwrap();
    res.read_message(&a[..n], &mut b).unwrap();
    let n = res.write_message(&[], &mut a).unwrap();
    ini.read_message(&a[..n], &mut b).unwrap();
    (
        Arc::new(ini.into_stateless_transport_mode().unwrap()),
        Arc::new(res.into_stateless_transport_mode().unwrap()),
    )
}
