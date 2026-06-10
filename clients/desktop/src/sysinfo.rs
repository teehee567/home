//! Server-stats panel — consumes the *remote* sysinfo module hosted on the
//! home server, over the node's server peer.

use std::sync::Arc;

use anyhow::Result;
use noob::modules::sys_info::{ProcStats, SysinfoModule, SysinfoRequest};
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
    let sysinfo = RemoteHandle::<SysinfoModule>::new(peer);

    let mut events = sysinfo.subscribe();
    if let Ok(stats) = sysinfo.request(SysinfoRequest::GetStats).await {
        push(app, stats);
    }
    while let Ok(stats) = events.recv().await {
        push(app, stats);
    }
    Ok(())
}

fn push(app: &slint::Weak<App>, stats: ProcStats) {
    let value: slint::SharedString =
        format!("{:.2}%  ·  {} MB", stats.cpu, stats.memory / 1_000_000).into();
    let _ = app.upgrade_in_event_loop(move |app| {
        app.set_server_value(value);
        app.set_server_status("Connected".into());
        app.set_server_connected(true);
    });
}
