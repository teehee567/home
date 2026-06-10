#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;

#[cfg(windows)]
use noob::modules::genshin::GenshinModule;
use tokio::runtime::Runtime;

mod app_watcher;
#[cfg(windows)]
mod genshin;
mod node;
mod sysinfo;

slint::include_modules!();

fn main() {
    // not sure if needed
    unsafe { env::set_var("SLINT_BACKEND", "winit-skia") };

    let rt = Runtime::new().unwrap();
    let _guard = rt.enter();

    let app = App::new().unwrap();
    let node = node::DesktopNode::new().expect("build desktop node");

    #[cfg(windows)]
    genshin::setup(&app, node.clone());
    app_watcher::setup(&app, node.clone());
    sysinfo::setup(&app, node);

    app.window().on_close_requested(move || {
        #[cfg(windows)]
        GenshinModule::stop_etw();
        slint::CloseRequestResponse::HideWindow
    });

    app.run().unwrap();
}
