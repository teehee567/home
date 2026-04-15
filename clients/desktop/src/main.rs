use noob::modules::genshin::GenshinModule;

mod app_watcher;
mod genshin;

slint::include_modules!();

fn main() {
    // not sure if needed
    unsafe { std::env::set_var("SLINT_BACKEND", "winit-skia") };

    let rt = tokio::runtime::Runtime::new().unwrap();
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
