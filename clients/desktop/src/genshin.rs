use noob::modules::genshin::GenshinModule;
use slint::ComponentHandle;

use crate::App;

pub fn setup(app: &App) {
    let app_weak = app.as_weak();
    tokio::spawn(async move {
        GenshinModule::start(move |state| {
            app_weak
                .upgrade_in_event_loop(move |app: App| {
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
}
