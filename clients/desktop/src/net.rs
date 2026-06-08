// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
// ONLY FOR TESTING CHANGE BASE DESKTOPTO USE NET SO ALL MODULES CAN ACCESS
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use noob::modules::Modules;
use noob::modules::sys_info::{ProcStats, SysinfoModule, SysinfoRequest};
use noob::net::{Node, RemoteHandle};
use noob::transport::quic;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use slint::ComponentHandle;

use crate::App;

const CLIENT_CERT: &[u8] = include_bytes!("../../../out/certs/client-cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("../../../out/certs/client-key.der");
const PINNED_SERVER_CERT: &[u8] = include_bytes!("../../../out/certs/server-cert.der");

const DEFAULT_ADDR: &str = "127.0.0.1:4433";

pub fn setup(app: &App) {
    let app = app.as_weak();
    tokio::spawn(async move {
        if let Err(e) = run(app).await {
            eprintln!("server link failed: {e}");
        }
    });
}

async fn run(app: slint::Weak<App>) -> Result<()> {
    let addr: SocketAddr = env::var("NOOB_SERVER")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_string())
        .parse()?;

    let endpoint = quic::client_endpoint(
        "0.0.0.0:0".parse()?,
        CertificateDer::from(CLIENT_CERT),
        PrivatePkcs8KeyDer::from(CLIENT_KEY),
        CertificateDer::from(PINNED_SERVER_CERT),
    )?;

    let node = Node::new(endpoint, Arc::new(Modules::spawn()));
    let peer = node.connect(addr, "localhost").await?;
    let sysinfo = RemoteHandle::<SysinfoModule>::new(peer);

    let mut events = sysinfo.subscribe();
    if let Ok(stats) = sysinfo.request(SysinfoRequest::GetStats).await {
        push(&app, stats);
    }
    while let Ok(stats) = events.recv().await {
        push(&app, stats);
    }

    let _ = app.upgrade_in_event_loop(|app| {
        app.set_server_status("Disconnected".into());
        app.set_server_connected(false);
    });
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
