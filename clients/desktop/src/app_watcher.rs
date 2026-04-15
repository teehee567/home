use noob::modules::app_watcher::{self, WatcherCommand};
use slint::ComponentHandle;

use crate::{App, WatchedAppData};

pub fn setup(app: &App) {
    let app_weak = app.as_weak();
    let cmd_tx = app_watcher::start(move |apps| {
        app_weak
            .upgrade_in_event_loop(move |app: App| {
                let items: Vec<WatchedAppData> = apps
                    .into_iter()
                    .map(|a| WatchedAppData {
                        display_name: a.display_name.into(),
                        exe_path: a.exe_path.into(),
                        is_online: a.is_running,
                        has_error: !a.error.is_empty(),
                        error_text: a.error.into(),
                    })
                    .collect();
                app.set_watcher_apps(std::rc::Rc::new(slint::VecModel::from(items)).into());
            })
            .ok();
    });

    let cmd_tx_add = cmd_tx.clone();
    app.on_watcher_add_app(move || {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Executable", &["exe"])
            .set_title("Select application to watch")
            .pick_file()
        {
            let _ = cmd_tx_add.send(WatcherCommand::Add(path));
        }
    });

    app.on_watcher_remove_app(move |idx| {
        let _ = cmd_tx.send(WatcherCommand::Remove(idx as usize));
    });
}
