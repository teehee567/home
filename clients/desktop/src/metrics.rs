//! Server-metrics panel — consumes the *remote* metrics module hosted on the
//! home server, over the node's server peer. The network figures are the
//! server's view of the link to this client.

use std::sync::Arc;

use anyhow::Result;
use noob::modules::metrics::{Metrics, MetricsModule, MetricsRequest};
use noob::net::RemoteHandle;
use slint::ComponentHandle;

use crate::App;
use crate::node::DesktopNode;

pub fn setup(app: &App, node: Arc<DesktopNode>) {
    let app_weak = app.as_weak();
    tokio::spawn(async move {
        if let Err(e) = run(&app_weak, node).await {
            eprintln!("server link failed: {e}");
        }
        let _ = app_weak.upgrade_in_event_loop(|app| {
            app.set_server_status("Disconnected".into());
            app.set_server_connected(false);
        });
    });
}

async fn run(app: &slint::Weak<App>, node: Arc<DesktopNode>) -> Result<()> {
    let peer = node.connect_server().await?;
    let metrics = RemoteHandle::<MetricsModule>::new(peer);

    let mut events = metrics.subscribe();
    if let Ok(m) = metrics.request(MetricsRequest::GetMetrics).await {
        push(app, m);
    }
    while let Ok(m) = events.recv().await {
        push(app, m);
    }
    Ok(())
}

fn push(app: &slint::Weak<App>, m: Metrics) {
    let value: slint::SharedString =
        format!("{:.1}%  ·  {} MB", m.process.cpu, m.process.memory / 1_000_000).into();
    let status: slint::SharedString = format!(
        "{:.0} ms · {:.1}% loss · ↓{}/s ↑{}/s",
        m.network.rtt_ms,
        m.network.packet_loss,
        human_bytes(m.network.rx_bps),
        human_bytes(m.network.tx_bps),
    )
    .into();
    let _ = app.upgrade_in_event_loop(move |app| {
        app.set_server_value(value);
        app.set_server_status(status);
        app.set_server_connected(true);
    });
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
