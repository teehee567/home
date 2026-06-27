use std::collections::VecDeque;
use std::time::Duration;
use std::{process, thread};

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::time;

use crate::modules::{Context, Module, ModuleError};
use crate::net::{NetStats, Telemetry};
use crate::storage::NodeDeps;

// 1s snapshots ~1h
const HISTORY_CAP: usize = 3600;
// recent rtt samples for jitter
const RTT_WINDOW: usize = 64;

/// this process resource usage
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessMetrics {
    /// cpu percent, one core
    pub cpu: f32,
    /// rss bytes
    pub memory: u64,
    /// virtual bytes
    pub virtual_memory: u64,
    /// disk read since last sample
    pub disk_read: u64,
    /// disk written since last sample
    pub disk_written: u64,
    /// process uptime secs
    pub uptime: u64,
}

/// whole host resource usage
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// global cpu percent
    pub cpu: f32,
    /// total physical bytes
    pub total_memory: u64,
    /// used physical bytes
    pub used_memory: u64,
    /// total swap bytes
    pub total_swap: u64,
    /// used swap bytes
    pub used_swap: u64,
    /// 1/5/15m load avg, zeros on windows
    pub load_avg: [f64; 3],
    /// host uptime secs
    pub uptime: u64,
}

/// link quality across live peers, from quinn stats
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// live peer count
    pub peers: u32,
    /// mean rtt ms
    pub rtt_ms: f64,
    /// rtt jitter stddev ms
    pub jitter_ms: f64,
    /// mean cwnd bytes
    pub cwnd: u64,
    /// smallest path mtu bytes
    pub mtu: u16,
    /// packets sent cumulative
    pub sent_packets: u64,
    /// packets lost cumulative
    pub lost_packets: u64,
    /// packet loss percent
    pub packet_loss: f64,
    /// congestion events cumulative
    pub congestion_events: u64,
    /// black holes cumulative
    pub black_holes: u64,
    /// upload bytes/sec
    pub tx_bps: u64,
    /// download bytes/sec
    pub rx_bps: u64,
    /// bytes sent cumulative
    pub tx_bytes: u64,
    /// bytes received cumulative
    pub rx_bytes: u64,
}

/// server request traffic, reliability, latency
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestMetrics {
    /// requests cumulative
    pub requests: u64,
    /// requests/sec
    pub req_per_sec: f64,
    /// error frames cumulative
    pub errors: u64,
    /// error rate percent
    pub error_rate: f64,
    /// request bytes cumulative
    pub bytes_in: u64,
    /// response bytes cumulative
    pub bytes_out: u64,
    /// request bytes/sec
    pub in_bps: u64,
    /// response bytes/sec
    pub out_bps: u64,
    /// proc time ms p50
    pub proc_p50_ms: f64,
    /// proc time ms p95
    pub proc_p95_ms: f64,
    /// proc time ms p99
    pub proc_p99_ms: f64,
}

/// process, host, link, traffic at a glance
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Metrics {
    pub process: ProcessMetrics,
    pub system: SystemMetrics,
    pub network: NetworkMetrics,
    pub request: RequestMetrics,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum MetricsRequest {
    // history downsampled to at most max_points, oldest -> newest
    GetHistory { max_points: u32 },
}

pub struct MetricsModule {
    sys: System,
    pid: Pid,
    num_cpus: f32,
    net: NetStats,
    telemetry: Telemetry,
    history: VecDeque<Metrics>,
    rtt_ring: VecDeque<f64>,
    // previous-tick counters, for per-second deltas
    prev_tx: u64,
    prev_rx: u64,
    prev_requests: u64,
    prev_errors: u64,
    prev_bytes_in: u64,
    prev_bytes_out: u64,
    current: Metrics,
}

impl Module for MetricsModule {
    const NAME: &str = "metrics";

    type Request = MetricsRequest;
    type Response = Vec<Metrics>;
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
            telemetry: deps.telemetry(),
            history: VecDeque::with_capacity(HISTORY_CAP),
            rtt_ring: VecDeque::with_capacity(RTT_WINDOW),
            prev_tx: 0,
            prev_rx: 0,
            prev_requests: 0,
            prev_errors: 0,
            prev_bytes_in: 0,
            prev_bytes_out: 0,
            current: Metrics::default(),
        })
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let mut tick = time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => match req.payload {
                        MetricsRequest::GetHistory { max_points } => {
                            req.reply(Ok(self.history_downsampled(max_points)));
                        }
                    },
                    None => break,
                },
                _ = tick.tick() => {
                    self.current = self.sample();
                    if self.history.len() == HISTORY_CAP {
                        self.history.pop_front();
                    }
                    self.history.push_back(self.current);
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

        let network = self.sample_network();
        let request = self.sample_requests();

        Metrics { process, system, network, request }
    }

    fn sample_network(&mut self) -> NetworkMetrics {
        let ns = self.net.sample();
        let tx_bps = ns.tx_bytes.saturating_sub(self.prev_tx);
        let rx_bps = ns.rx_bytes.saturating_sub(self.prev_rx);
        self.prev_tx = ns.tx_bytes;
        self.prev_rx = ns.rx_bytes;

        let rtt_ms = (ns.rtt_ms * 100.0).round() / 100.0;
        if ns.peers > 0 {
            if self.rtt_ring.len() == RTT_WINDOW {
                self.rtt_ring.pop_front();
            }
            self.rtt_ring.push_back(rtt_ms);
        }

        let packet_loss = if ns.sent_packets > 0 {
            (ns.lost_packets as f64 / ns.sent_packets as f64 * 10_000.0).round() / 100.0
        } else {
            0.0
        };

        NetworkMetrics {
            peers: ns.peers,
            rtt_ms,
            jitter_ms: self.jitter(),
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
        }
    }

    fn sample_requests(&mut self) -> RequestMetrics {
        let s = self.telemetry.snapshot();
        let req_delta = s.requests.saturating_sub(self.prev_requests);
        let err_delta = s.errors.saturating_sub(self.prev_errors);
        let in_bps = s.bytes_in.saturating_sub(self.prev_bytes_in);
        let out_bps = s.bytes_out.saturating_sub(self.prev_bytes_out);
        self.prev_requests = s.requests;
        self.prev_errors = s.errors;
        self.prev_bytes_in = s.bytes_in;
        self.prev_bytes_out = s.bytes_out;

        let error_rate = if req_delta > 0 {
            (err_delta as f64 / req_delta as f64 * 10_000.0).round() / 100.0
        } else {
            0.0
        };

        RequestMetrics {
            requests: s.requests,
            req_per_sec: req_delta as f64,
            errors: s.errors,
            error_rate,
            bytes_in: s.bytes_in,
            bytes_out: s.bytes_out,
            in_bps,
            out_bps,
            proc_p50_ms: us_to_ms(s.p50_us),
            proc_p95_ms: us_to_ms(s.p95_us),
            proc_p99_ms: us_to_ms(s.p99_us),
        }
    }

    // stddev of recent rtt
    fn jitter(&self) -> f64 {
        let n = self.rtt_ring.len();
        if n < 2 {
            return 0.0;
        }
        let mean = self.rtt_ring.iter().sum::<f64>() / n as f64;
        let var = self.rtt_ring.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
        (var.sqrt() * 100.0).round() / 100.0
    }

    // stride down to at most max_points, always keep newest
    fn history_downsampled(&self, max_points: u32) -> Vec<Metrics> {
        let n = self.history.len();
        let max = (max_points as usize).max(1);
        if n <= max {
            return self.history.iter().copied().collect();
        }
        let step = (n / max).max(1);
        let mut out: Vec<Metrics> = self.history.iter().step_by(step).copied().collect();
        if !(n - 1).is_multiple_of(step) {
            out.push(*self.history.back().unwrap());
        }
        out
    }
}

fn us_to_ms(us: u32) -> f64 {
    (us as f64 / 10.0).round() / 100.0
}
