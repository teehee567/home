use noob::modules::genshin::GenshinModule;

slint::include_modules!();

fn main() {
    // not sure if needed
    unsafe { std::env::set_var("SLINT_BACKEND", "winit-skia") };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let app = App::new().unwrap();
    let app_weak = app.as_weak();

    tokio::spawn(async move {
        GenshinModule::start(move |state| {
            app_weak
                .upgrade_in_event_loop(move |app| {
                    app.set_running(state.running);
                    app.set_fps_text(
                        state
                            .fps
                            .map(|f| f.to_string())
                            .unwrap_or_else(|| "---".into())
                            .into(),
                    );
                    app.set_status_text(
                        if state.running {
                            "Running"
                        } else {
                            "Genshin Impact not running"
                        }
                        .into(),
                    );
                })
                .ok();
        })
        .await;
    });

    app.window().on_close_requested(move || {
        GenshinModule::stop_etw();
        slint::CloseRequestResponse::HideWindow
    });

    app.run().unwrap();
}
