use std::{process, thread, time::Duration};

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::time;

use crate::modules::{Context, Module, ModuleError};
use crate::net::NetStats;
use crate::storage::NodeDeps;

/// Resource usage of this node's own process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessMetrics {
    /// CPU usage normalized to a single core, percent (0–100)
    pub cpu: f32,
    /// resident set size, bytes
    pub memory: u64,
    /// virtual memory, bytes
    pub virtual_memory: u64,
    /// disk bytes read since the last sample
    pub disk_read: u64,
    /// disk bytes written since the last sample
    pub disk_written: u64,
    /// seconds the process has been running
    pub uptime: u64,
}

/// Whole-host resource usage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// global CPU usage across all cores, percent (0–100)
    pub cpu: f32,
    /// total physical memory, bytes
    pub total_memory: u64,
    /// used physical memory, bytes
    pub used_memory: u64,
    /// total swap, bytes
    pub total_swap: u64,
    /// used swap, bytes
    pub used_swap: u64,
    /// 1/5/15-minute load averages (zeros on platforms without it, e.g. Windows)
    pub load_avg: [f64; 3],
    /// host uptime, seconds
    pub uptime: u64,
}

/// Link quality across every live peer connection, from quinn's transport stats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// number of live peer connections
    pub peers: u32,
    /// mean round-trip time, milliseconds
    pub rtt_ms: f64,
    /// mean congestion window, bytes
    pub cwnd: u64,
    /// smallest current path MTU, bytes
    pub mtu: u16,
    /// packets sent (cumulative)
    pub sent_packets: u64,
    /// packets lost (cumulative)
    pub lost_packets: u64,
    /// packet loss, percent (lost / sent)
    pub packet_loss: f64,
    /// congestion events (cumulative)
    pub congestion_events: u64,
    /// black holes detected (cumulative)
    pub black_holes: u64,
    /// bytes sent since the last sample (≈ upload bytes/sec)
    pub tx_bps: u64,
    /// bytes received since the last sample (≈ download bytes/sec)
    pub rx_bps: u64,
    /// bytes sent (cumulative)
    pub tx_bytes: u64,
    /// bytes received (cumulative)
    pub rx_bytes: u64,
}

/// Everything a dev environment wants at a glance: process, host, and link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Metrics {
    pub process: ProcessMetrics,
    pub system: SystemMetrics,
    pub network: NetworkMetrics,
}

#[derive(Serialize, Deserialize)]
pub enum MetricsRequest {
    GetMetrics,
}

pub struct MetricsModule {
    sys: System,
    pid: Pid,
    num_cpus: f32,
    net: NetStats,
    // cumulative byte counters from the previous tick, for throughput deltas
    prev_tx: u64,
    prev_rx: u64,
    current: Metrics,
}

impl Module for MetricsModule {
    const NAME: &str = "metrics";

    type Request = MetricsRequest;
    type Response = Metrics;
    type Event = Metrics;

    async fn new(deps: &NodeDeps) -> Result<Self, ModuleError> {
        let num_cpus = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1) as f32;

        Ok(Self {
            sys: System::new(),
            pid: Pid::from_u32(process::id()),
            num_cpus,
            net: deps.net_stats(),
            prev_tx: 0,
            prev_rx: 0,
            current: Metrics::default(),
        })
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let mut tick = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => match req.payload {
                        MetricsRequest::GetMetrics => req.reply(Ok(self.current)),
                    },
                    None => break,
                },
                _ = tick.tick() => {
                    self.current = self.sample();
                    ctx.publish(self.current);
                }
            }
        }
    }
}

impl MetricsModule {
    fn sample(&mut self) -> Metrics {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory().with_disk_usage(),
        );
        self.sys.refresh_memory();
        self.sys.refresh_cpu_usage();

        let process = match self.sys.process(self.pid) {
            Some(p) => {
                let disk = p.disk_usage();
                ProcessMetrics {
                    cpu: (p.cpu_usage() / self.num_cpus * 100.0).round() / 100.0,
                    memory: p.memory(),
                    virtual_memory: p.virtual_memory(),
                    disk_read: disk.read_bytes,
                    disk_written: disk.written_bytes,
                    uptime: p.run_time(),
                }
            }
            None => self.current.process,
        };

        let load = System::load_average();
        let system = SystemMetrics {
            cpu: (self.sys.global_cpu_usage() * 100.0).round() / 100.0,
            total_memory: self.sys.total_memory(),
            used_memory: self.sys.used_memory(),
            total_swap: self.sys.total_swap(),
            used_swap: self.sys.used_swap(),
            load_avg: [load.one, load.five, load.fifteen],
            uptime: System::uptime(),
        };

        let ns = self.net.sample();
        let tx_bps = ns.tx_bytes.saturating_sub(self.prev_tx);
        let rx_bps = ns.rx_bytes.saturating_sub(self.prev_rx);
        self.prev_tx = ns.tx_bytes;
        self.prev_rx = ns.rx_bytes;
        let packet_loss = if ns.sent_packets > 0 {
            (ns.lost_packets as f64 / ns.sent_packets as f64 * 10_000.0).round() / 100.0
        } else {
            0.0
        };
        let network = NetworkMetrics {
            peers: ns.peers,
            rtt_ms: (ns.rtt_ms * 100.0).round() / 100.0,
            cwnd: ns.cwnd,
            mtu: ns.mtu,
            sent_packets: ns.sent_packets,
            lost_packets: ns.lost_packets,
            packet_loss,
            congestion_events: ns.congestion_events,
            black_holes: ns.black_holes,
            tx_bps,
            rx_bps,
            tx_bytes: ns.tx_bytes,
            rx_bytes: ns.rx_bytes,
        };

        Metrics { process, system, network }
    }
}
