#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;

#[cfg(windows)]
use noob::modules::genshin::GenshinModule;
use noob::storage::node_data_dir;
use tokio::runtime::Runtime;

mod app_watcher;
#[cfg(windows)]
mod genshin;
mod metrics;
mod node;

slint::include_modules!();

// log panics to <data-dir>/noob/desktop/crash.log, release build has no stderr
fn install_crash_logger() {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let log_path = node_data_dir("desktop").join("crash.log");
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let entry = format!("\n=== panic (unix {secs}) ===\n{info}\n\nbacktrace:\n{bt}\n");
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = f.write_all(entry.as_bytes());
        }
        default_hook(info); // stderr too, debug builds
    }));
}

fn main() {
    if env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { env::set_var("RUST_BACKTRACE", "1") };
    }
    install_crash_logger();

    // not sure if needed
    unsafe { env::set_var("SLINT_BACKEND", "winit-skia") };

    let rt = Runtime::new().unwrap();
    let _guard = rt.enter();

    let app = App::new().unwrap();
    // block on load state first
    let node = rt.block_on(node::DesktopNode::new()).expect("build desktop node");

    #[cfg(windows)]
    genshin::setup(&app, node.clone());
    app_watcher::setup(&app, node.clone());
    metrics::setup(&app, node);

    app.window().on_close_requested(move || {
        #[cfg(windows)]
        GenshinModule::stop_etw();
        slint::CloseRequestResponse::HideWindow
    });

    app.run().unwrap();
}
