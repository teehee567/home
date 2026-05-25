#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;

#[cfg(windows)]
use noob::modules::genshin::GenshinModule;
use tokio::runtime::Runtime;

mod app_watcher;
#[cfg(windows)]
mod genshin;

slint::include_modules!();

fn main() {
    // not sure if needed
    unsafe { env::set_var("SLINT_BACKEND", "winit-skia") };

    let rt = Runtime::new().unwrap();
    let _guard = rt.enter();

    let app = App::new().unwrap();

    #[cfg(windows)]
    genshin::setup(&app);
    app_watcher::setup(&app);

    app.window().on_close_requested(move || {
        #[cfg(windows)]
        GenshinModule::stop_etw();
        slint::CloseRequestResponse::HideWindow
    });

    app.run().unwrap();
}
