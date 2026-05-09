#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;

use noob::modules::genshin::GenshinModule;
use tokio::runtime::Runtime;

mod app_watcher;
mod genshin;

slint::include_modules!();

fn main() {
    // not sure if needed
    unsafe { env::set_var("SLINT_BACKEND", "winit-skia") };

    let rt = Runtime::new().unwrap();
    let _guard = rt.enter();

    let app = App::new().unwrap();

    genshin::setup(&app);
    app_watcher::setup(&app);

    app.window().on_close_requested(move || {
        GenshinModule::stop_etw();
        slint::CloseRequestResponse::HideWindow
    });

    app.run().unwrap();
}
