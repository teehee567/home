//! Server metrics panel. Drives the dashboard card and the metrics tab. History
//! is primed from the server ring on connect then grown from the live event stream.

use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use noob::modules::metrics::{Metrics, MetricsModule, MetricsRequest};
use noob::net::RemoteHandle;
use slint::{Color, ComponentHandle, VecModel};

use crate::node::DesktopNode;
use crate::{App, GraphData, MetricStat};

// chart points, ~3 min at 1/sec
const POINTS: usize = 180;

// github-dark accents
const BLUE: (u8, u8, u8) = (88, 166, 255);
const GREEN: (u8, u8, u8) = (63, 185, 80);
const PURPLE: (u8, u8, u8) = (188, 140, 255);
const ORANGE: (u8, u8, u8) = (210, 153, 34);
const TEAL: (u8, u8, u8) = (57, 197, 207);
const RED: (u8, u8, u8) = (248, 81, 73);
const GOLD: (u8, u8, u8) = (200, 169, 110);

// shared by the net task (appends) and the resize callback (repaints)
struct Shared {
    data: Mutex<Vec<Metrics>>,
    // plot pixel size, shared by every chart column
    plot: Mutex<(f32, f32)>,
}

pub fn setup(app: &App, node: Arc<DesktopNode>) {
    let shared = Arc::new(Shared {
        data: Mutex::new(Vec::with_capacity(POINTS)),
        plot: Mutex::new((320.0, 58.0)), // default until first layout pass
    });

    // repaint on resize so paths match the new pixel size
    {
        let shared = shared.clone();
        let weak = app.as_weak();
        app.on_metrics_resized(move |w, h| {
            {
                let mut plot = shared.plot.lock().unwrap();
                if (plot.0 - w).abs() < 0.5 && (plot.1 - h).abs() < 0.5 {
                    return; // unchanged
                }
                *plot = (w, h);
            }
            // defer past slint change-handler iteration, avoids use-after-free
            let weak = weak.clone();
            let shared = shared.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = weak.upgrade() {
                    let data = shared.data.lock().unwrap().clone();
                    paint(&app, &data, (w, h));
                }
            });
        });
    }

    let app_weak = app.as_weak();
    let task_shared = shared.clone();
    tokio::spawn(async move {
        if let Err(e) = run(&app_weak, node, task_shared).await {
            eprintln!("metrics link failed: {e}");
        }
        let _ = app_weak.upgrade_in_event_loop(|app| {
            app.set_server_status("Disconnected".into());
            app.set_server_connected(false);
            app.set_metrics_status("Disconnected".into());
            app.set_metrics_connected(false);
        });
    });
}

async fn run(app: &slint::Weak<App>, node: Arc<DesktopNode>, shared: Arc<Shared>) -> Result<()> {
    let peer = node.connect_server().await?;
    let metrics = RemoteHandle::<MetricsModule>::new(peer);

    // backfill so charts aren't empty on open
    if let Ok(hist) = metrics.request(MetricsRequest::GetHistory { max_points: POINTS as u32 }).await
    {
        {
            let mut ring = shared.data.lock().unwrap();
            *ring = hist;
            let len = ring.len();
            if len > POINTS {
                ring.drain(0..len - POINTS);
            }
        }
        render(app, &shared);
    }

    let mut events = metrics.subscribe();
    while let Ok(m) = events.recv().await {
        {
            let mut ring = shared.data.lock().unwrap();
            ring.push(m);
            if ring.len() > POINTS {
                ring.remove(0);
            }
        }
        render(app, &shared);
    }
    Ok(())
}

fn render(app: &slint::Weak<App>, shared: &Arc<Shared>) {
    let data: Vec<Metrics> = shared.data.lock().unwrap().clone();
    let plot = *shared.plot.lock().unwrap();
    let _ = app.upgrade_in_event_loop(move |app| paint(&app, &data, plot));
}

fn paint(app: &App, data: &[Metrics], plot: (f32, f32)) {
    let Some(last) = data.last().copied() else { return };

    // dashboard card
    app.set_server_value(
        format!("{:.1}%  ·  {} MB", last.process.cpu, last.process.memory / 1_000_000).into(),
    );
    app.set_server_status(
        format!("{:.2} ms · {:.1}% loss", last.network.rtt_ms, last.network.packet_loss).into(),
    );
    app.set_server_connected(true);

    // metrics tab
    app.set_metrics_status(
        format!("{} peer(s) · {} reqs", last.network.peers, last.request.requests).into(),
    );
    app.set_metrics_connected(true);
    app.set_metrics_stats(Rc::new(VecModel::from(stat_cards(&last))).into());

    let (left, right) = chart_series(data, &last, plot);
    app.set_metrics_left(Rc::new(VecModel::from(left)).into());
    app.set_metrics_right(Rc::new(VecModel::from(right)).into());
}

fn stat_cards(m: &Metrics) -> Vec<MetricStat> {
    vec![
        stat("CPU", format!("{:.1}%", m.process.cpu), BLUE),
        stat("MEM", format!("{} MB", m.process.memory / 1_000_000), PURPLE),
        stat("CONNS", format!("{}", m.network.peers), TEAL),
        stat("REQ/S", format!("{:.0}", m.request.req_per_sec), ORANGE),
        stat("ERR", format!("{:.1}%", m.request.error_rate), RED),
        stat("RTT", format!("{:.2} ms", m.network.rtt_ms), GREEN),
        stat("LOSS", format!("{:.2}%", m.network.packet_loss), RED),
        stat("JITTER", format!("{:.1} ms", m.network.jitter_ms), GOLD),
    ]
}

fn chart_series(data: &[Metrics], last: &Metrics, plot: (f32, f32)) -> (Vec<GraphData>, Vec<GraphData>) {
    // axis label formatters, unit lives in the title
    let plain = |v: f64| format!("{v:.0}");
    let one_dp = |v: f64| format!("{v:.1}");
    let two_dp = |v: f64| format!("{v:.2}");
    let bytes = |v: f64| human_bytes(v as u64);

    let left = vec![
        series("CPU %", format!("{:.1}%", last.process.cpu), BLUE, data, Some(100.0), plot,
            |m| m.process.cpu as f64, plain),
        series("RTT ms", format!("{:.2} ms", last.network.rtt_ms), GREEN, data, None, plot,
            |m| m.network.rtt_ms, two_dp),
        series("Requests/s", format!("{:.0}", last.request.req_per_sec), ORANGE, data, None, plot,
            |m| m.request.req_per_sec, plain),
        series("Proc latency (p95)",
            format!("p50 {:.1} / p95 {:.1} / p99 {:.1} ms",
                last.request.proc_p50_ms, last.request.proc_p95_ms, last.request.proc_p99_ms),
            GOLD, data, None, plot, |m| m.request.proc_p95_ms, one_dp),
        series("Download/s", format!("{}/s", human_bytes(last.network.rx_bps)), TEAL, data, None, plot,
            |m| m.network.rx_bps as f64, bytes),
    ];
    let right = vec![
        series("Memory MB", format!("{} MB", last.process.memory / 1_000_000), PURPLE, data, None, plot,
            |m| m.process.memory as f64 / 1_000_000.0, plain),
        series("Packet loss %", format!("{:.2}%", last.network.packet_loss), RED, data, None, plot,
            |m| m.network.packet_loss, one_dp),
        series("Jitter ms", format!("{:.1} ms", last.network.jitter_ms), GOLD, data, None, plot,
            |m| m.network.jitter_ms, one_dp),
        series("Upload/s", format!("{}/s", human_bytes(last.network.tx_bps)), TEAL, data, None, plot,
            |m| m.network.tx_bps as f64, bytes),
    ];
    (left, right)
}

fn stat(label: &str, value: String, c: (u8, u8, u8)) -> MetricStat {
    MetricStat { label: label.into(), value: value.into(), accent: rgb(c) }
}

#[allow(clippy::too_many_arguments)]
fn series(
    title: &str,
    value: String,
    c: (u8, u8, u8),
    data: &[Metrics],
    fixed_max: Option<f64>,
    plot: (f32, f32),
    f: impl Fn(&Metrics) -> f64,
    fmt: impl Fn(f64) -> String,
) -> GraphData {
    let values: Vec<f64> = data.iter().map(&f).collect();
    // fixed or auto axis max, rounded to a nice number
    let raw_max = fixed_max.unwrap_or_else(|| values.iter().copied().fold(0.0_f64, f64::max));
    let max = nice_max(raw_max);
    let last_val = values.last().copied().unwrap_or(0.0);
    GraphData {
        title: title.into(),
        value: value.into(),
        commands: path_for(&values, max, plot).into(),
        accent: rgb(c),
        y_top: fmt(max).into(),
        y_mid: fmt(max / 2.0).into(),
        last_norm: (last_val / max).clamp(0.0, 1.0) as f32,
    }
}

// round up to 1/2/5 x 10^n for clean gridline labels and discrete scale steps
fn nice_max(raw: f64) -> f64 {
    if raw <= 0.0 || raw.is_nan() {
        return 1.0;
    }
    let pow = 10f64.powf(raw.log10().floor());
    let frac = raw / pow; // [1, 10)
    let nice = if frac <= 1.0 {
        1.0
    } else if frac <= 2.0 {
        2.0
    } else if frac <= 5.0 {
        5.0
    } else {
        10.0
    };
    nice * pow
}

// svg polyline in plot pixels, newest pinned right, older steps left by a fixed
// amount so a new sample scrolls one step instead of respacing. viewbox is 1:1.
fn path_for(values: &[f64], max: f64, (w, h): (f32, f32)) -> String {
    let n = values.len();
    if n < 2 || w <= 0.0 || h <= 0.0 {
        return String::new();
    }
    let (w, h) = (w as f64, h as f64);
    let max = if max <= 0.0 { 1.0 } else { max };
    let step = w / (POINTS - 1) as f64;

    let mut s = String::with_capacity(n * 16);
    for (i, v) in values.iter().enumerate() {
        let x = w - (n - 1 - i) as f64 * step;
        let norm = (v / max).clamp(0.0, 1.0);
        let y = h - norm * h;
        if i == 0 {
            s.push_str(&format!("M {x:.2} {y:.2}"));
        } else {
            s.push_str(&format!(" L {x:.2} {y:.2}"));
        }
    }
    s
}

fn rgb((r, g, b): (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(r, g, b)
}

fn human_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    match b {
        0..KB => format!("{b} B"),
        KB..MB => format!("{:.1} KB", b as f64 / KB as f64),
        _ => format!("{:.1} MB", b as f64 / MB as f64),
    }
}
