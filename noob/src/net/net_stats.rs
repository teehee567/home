//! Shared registry of live QUIC connections.
//!
//! The [`Node`](crate::net::Node) registers each peer connection here as it is
//! established and drops it on close. The metrics module reads it to surface
//! link quality (rtt, packet loss, throughput) without owning the transport.

use std::sync::Arc;

use parking_lot::RwLock;
use quinn::Connection;
use rustc_hash::FxHashMap;

use crate::transport::conn_manager::PeerId;

/// Cheaply cloneable handle to the live-connection registry.
#[derive(Clone, Default)]
pub struct NetStats {
    conns: Arc<RwLock<FxHashMap<PeerId, Connection>>>,
}

/// Aggregate of quinn path/udp counters across every live connection.
///
/// All byte/packet counters are cumulative since each connection opened;
/// the metrics module turns the byte counters into per-second throughput.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetSample {
    /// number of live peer connections
    pub peers: u32,
    /// mean round-trip time across connections, milliseconds
    pub rtt_ms: f64,
    /// mean congestion window across connections, bytes
    pub cwnd: u64,
    /// smallest current path MTU across connections, bytes (0 if no peers)
    pub mtu: u16,
    /// total packets sent (cumulative)
    pub sent_packets: u64,
    /// total packets lost (cumulative)
    pub lost_packets: u64,
    /// congestion events (cumulative)
    pub congestion_events: u64,
    /// black holes detected (cumulative)
    pub black_holes: u64,
    /// total bytes sent over UDP (cumulative)
    pub tx_bytes: u64,
    /// total bytes received over UDP (cumulative)
    pub rx_bytes: u64,
}

impl NetStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a connection until [`remove`](Self::remove) is called.
    pub fn insert(&self, peer: PeerId, conn: Connection) {
        self.conns.write().insert(peer, conn);
    }

    /// Stop tracking a connection (called when the peer closes).
    pub fn remove(&self, peer: PeerId) {
        self.conns.write().remove(&peer);
    }

    /// Snapshot quinn stats aggregated across all live connections.
    pub fn sample(&self) -> NetSample {
        let conns = self.conns.read();
        let mut s = NetSample::default();
        let n = conns.len();
        if n == 0 {
            return s;
        }

        let mut rtt_sum = 0.0_f64;
        let mut cwnd_sum = 0_u64;
        let mut mtu_min = u16::MAX;
        for conn in conns.values() {
            let st = conn.stats();
            rtt_sum += st.path.rtt.as_secs_f64() * 1000.0;
            cwnd_sum += st.path.cwnd;
            mtu_min = mtu_min.min(st.path.current_mtu);
            s.sent_packets += st.path.sent_packets;
            s.lost_packets += st.path.lost_packets;
            s.congestion_events += st.path.congestion_events;
            s.black_holes += st.path.black_holes_detected;
            s.tx_bytes += st.udp_tx.bytes;
            s.rx_bytes += st.udp_rx.bytes;
        }

        s.peers = n as u32;
        s.rtt_ms = rtt_sum / n as f64;
        s.cwnd = cwnd_sum / n as u64;
        s.mtu = if mtu_min == u16::MAX { 0 } else { mtu_min };
        s
    }
}
