//! Shared request-telemetry collector. Written by the dispatcher per request,
//! read by the metrics module each tick. Cloneable handle over shared atomics
//! plus a ring of recent processing times for percentiles, like [`NetStats`].

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

// recent proc-time samples (micros) for percentiles
const LATENCY_WINDOW: usize = 4096;

#[derive(Default)]
struct Inner {
    requests: AtomicU64,
    errors: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    // recent proc times micros, newest at back
    latencies: Mutex<VecDeque<u32>>,
}

/// cloneable handle to the telemetry counters
#[derive(Clone, Default)]
pub struct Telemetry {
    inner: Arc<Inner>,
}

/// cumulative counters plus proc-time percentiles
#[derive(Clone, Copy, Debug, Default)]
pub struct TelemetrySnapshot {
    /// requests cumulative
    pub requests: u64,
    /// error frames cumulative
    pub errors: u64,
    /// request bytes cumulative
    pub bytes_in: u64,
    /// response bytes cumulative
    pub bytes_out: u64,
    /// proc time micros
    pub p50_us: u32,
    pub p95_us: u32,
    pub p99_us: u32,
}

impl Telemetry {
    pub fn new() -> Self {
        Self::default()
    }

    // record one dispatch: payload sizes, module time, error or not
    pub fn record(&self, bytes_in: usize, bytes_out: usize, elapsed: Duration, is_error: bool) {
        self.inner.requests.fetch_add(1, Ordering::Relaxed);
        if is_error {
            self.inner.errors.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.bytes_in.fetch_add(bytes_in as u64, Ordering::Relaxed);
        self.inner.bytes_out.fetch_add(bytes_out as u64, Ordering::Relaxed);

        let micros = elapsed.as_micros().min(u32::MAX as u128) as u32;
        let mut lat = self.inner.latencies.lock();
        if lat.len() == LATENCY_WINDOW {
            lat.pop_front();
        }
        lat.push_back(micros);
    }

    // snapshot counters and compute percentiles
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let mut samples: Vec<u32> = self.inner.latencies.lock().iter().copied().collect();
        samples.sort_unstable();

        TelemetrySnapshot {
            requests: self.inner.requests.load(Ordering::Relaxed),
            errors: self.inner.errors.load(Ordering::Relaxed),
            bytes_in: self.inner.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.inner.bytes_out.load(Ordering::Relaxed),
            p50_us: percentile(&samples, 0.50),
            p95_us: percentile(&samples, 0.95),
            p99_us: percentile(&samples, 0.99),
        }
    }
}

// nearest-rank percentile over sorted slice, 0 when empty
fn percentile(sorted: &[u32], q: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (q * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}
