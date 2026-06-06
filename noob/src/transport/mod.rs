pub mod duplex;
pub mod quic;
pub mod noise_stream;
pub mod xchacha_stream;
pub mod core_stream;
pub mod frame;
pub mod conn_manager;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::conn_manager::{Dispatcher, Peer, PeerId, PeerPool};
    use super::frame::{Frame, FrameKind};
    use super::noise_stream::NoiseStream;
    use super::test_utils::{chan_pair, noise_pair};
    use super::xchacha_stream::XChaChaStream;
    use crate::modules::ModuleId;
    use crate::traits::{FramedSender, FramedStream, SplittableStream, FramedReceiver};
    use secrecy::SecretBox;

    const ROUTE: ModuleId = ModuleId::Sysinfo;

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
    async fn split_noise_stream_concurrent_send_recv() {
        let (ini_noise, res_noise) = noise_pair();
        let (wire_a, wire_b) = chan_pair();

        let s_full = NoiseStream::new(wire_a, ini_noise, 1);
        let r_full = NoiseStream::new(wire_b, res_noise, 1);
        let (_, mut s_writer) = s_full.split();
        let (mut r_reader, _) = r_full.split();

        let send = tokio::spawn(async move {
            s_writer.send(b"hello from split").await.unwrap();
        });
        let recv = tokio::spawn(async move {
            r_reader.receive().await.unwrap()
        });

        send.await.unwrap();
        let got = recv.await.unwrap();
        assert_eq!(got, b"hello from split");
    }

    struct EchoDispatcher;

    impl Dispatcher for EchoDispatcher {
        async fn dispatch(&self, _peer: PeerId, frame: Frame) -> Option<Frame> {
            match frame.kind {
                FrameKind::Request => Some(Frame {
                    kind: FrameKind::Response,
                    route: frame.route,
                    request_id: frame.request_id,
                    payload: frame.payload,
                }),
                _ => None,
            }
        }
    }

    #[tokio::test]
    async fn pool_request_response_roundtrip() {
        let (a, b) = chan_pair();

        let pool = PeerPool::new(Arc::new(EchoDispatcher));
        pool.attach(42, a);

        let client = Peer::connect(b, Arc::new(EchoDispatcher));

        let resp = client.request(ROUTE, b"ping".to_vec()).await.unwrap();
        assert_eq!(resp, b"ping");

        let resp2 = client.request(ROUTE, b"pong".to_vec()).await.unwrap();
        assert_eq!(resp2, b"pong");

        assert_eq!(pool.peer_count(), 1);
    }

    #[tokio::test]
    async fn pool_broadcast_event_reaches_all_clients() {
        let pool = PeerPool::new(Arc::new(EchoDispatcher));

        let (a1, b1) = chan_pair();
        let (a2, b2) = chan_pair();
        pool.attach(1, a1);
        pool.attach(2, a2);

        let c1 = Peer::connect(b1, Arc::new(EchoDispatcher));
        let c2 = Peer::connect(b2, Arc::new(EchoDispatcher));
        let mut sub1 = c1.subscribe(ROUTE);
        let mut sub2 = c2.subscribe(ROUTE);

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        pool.broadcast_event(ROUTE, b"hello all".to_vec());

        let e1 = sub1.recv().await.unwrap();
        let e2 = sub2.recv().await.unwrap();
        assert_eq!(e1, b"hello all");
        assert_eq!(e2, b"hello all");
    }

    #[tokio::test]
    async fn pool_targeted_event_only_reaches_one_client() {
        let pool = PeerPool::new(Arc::new(EchoDispatcher));

        let (a1, b1) = chan_pair();
        let (a2, b2) = chan_pair();
        pool.attach(1, a1);
        pool.attach(2, a2);

        let c1 = Peer::connect(b1, Arc::new(EchoDispatcher));
        let c2 = Peer::connect(b2, Arc::new(EchoDispatcher));
        let mut sub1 = c1.subscribe(ROUTE);
        let mut sub2 = c2.subscribe(ROUTE);

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        pool.get(2).unwrap().send_event(ROUTE, b"hi 2".to_vec()).await.unwrap();

        let e2 = sub2.recv().await.unwrap();
        assert_eq!(e2, b"hi 2");

        let nothing = tokio::time::timeout(std::time::Duration::from_millis(30), sub1.recv()).await;
        assert!(nothing.is_err(), "client 1 should not have received the event");
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
