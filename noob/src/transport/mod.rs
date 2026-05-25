pub mod quic;
pub mod noise_stream;
pub mod xchacha_stream;
pub mod core_stream;
pub mod codec;
pub mod frame;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::noise_stream::NoiseStream;
    use super::xchacha_stream::XChaChaStream;
    use crate::traits::FramedStream;
    use secrecy::SecretBox;
    use snow::StatelessTransportState;
    use tokio::sync::mpsc;

    struct Chan {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    fn chan_pair() -> (Chan, Chan) {
        let (tx1, rx1) = mpsc::unbounded_channel();
        let (tx2, rx2) = mpsc::unbounded_channel();
        (Chan { tx: tx1, rx: rx2 }, Chan { tx: tx2, rx: rx1 })
    }

    impl FramedStream for Chan {
        async fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
            self.tx.send(data.to_vec()).map_err(|e| anyhow::anyhow!(e))
        }
        async fn receive(&mut self) -> anyhow::Result<Vec<u8>> {
            self.rx.recv().await.ok_or_else(|| anyhow::anyhow!("closed"))
        }
    }

    fn noise_pair() -> (Arc<StatelessTransportState>, Arc<StatelessTransportState>) {
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

    #[tokio::test]
    async fn full_stack_encrypts_and_roundtrips() {
        let msg = b"super secret finance data";
        let (ini_noise, res_noise) = noise_pair();
        let (wire_a, wire_b) = chan_pair();
        let key = || SecretBox::new(Box::new([42u8; 32]));

        let mut sender = XChaChaStream::new(NoiseStream::new(wire_a, ini_noise, 1), key());
        let mut receiver = XChaChaStream::new(NoiseStream::new(wire_b, res_noise, 1), key());

        sender.send(msg).await.unwrap();
        let got = receiver.receive().await.unwrap();
        assert_eq!(got, msg, "roundtrip failed");
    }

    #[tokio::test]
    async fn multiple_streams_share_one_transport() {
        let (ini_noise, res_noise) = noise_pair();
        let (wire_a1, wire_b1) = chan_pair();
        let (wire_a2, wire_b2) = chan_pair();

        let mut s1 = NoiseStream::new(wire_a1, ini_noise.clone(), 1);
        let mut r1 = NoiseStream::new(wire_b1, res_noise.clone(), 1);
        let mut s2 = NoiseStream::new(wire_a2, ini_noise, 2);
        let mut r2 = NoiseStream::new(wire_b2, res_noise, 2);

        s1.send(b"stream one msg a").await.unwrap();
        s2.send(b"stream two msg a").await.unwrap();
        s1.send(b"stream one msg b").await.unwrap();

        assert_eq!(r1.receive().await.unwrap(), b"stream one msg a");
        assert_eq!(r2.receive().await.unwrap(), b"stream two msg a");
        assert_eq!(r1.receive().await.unwrap(), b"stream one msg b");
    }
}
