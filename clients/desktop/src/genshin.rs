use noob::modules::{self, genshin::GenshinModule};
use slint::ComponentHandle;
use tokio::sync::broadcast::error::RecvError;

use crate::App;

pub fn setup(app: &App) {
    let app_weak = app.as_weak();
    tokio::spawn(async move {
        // Keep `handle` alive for the task's lifetime: dropping the last handle
        // shuts the module down.
        let handle = modules::spawn::<GenshinModule>();
        let mut events = handle.subscribe();
        loop {
            let state = match events.recv().await {
                Ok(state) => state,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            };
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
        }
    });
}
