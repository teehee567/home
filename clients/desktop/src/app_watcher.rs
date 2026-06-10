use std::rc::Rc;
use std::sync::Arc;

use noob::modules::app_watcher::{AppState, AppWatcherRequest, AppWatcherResponse};
use slint::ComponentHandle;
use tokio::sync::broadcast::error::RecvError;

use crate::node::DesktopNode;
use crate::{App, WatchedAppData};

pub fn setup(app: &App, node: Arc<DesktopNode>) {
    let handle = node.modules().AppWatcher.clone().expect("app watcher hosted on desktop");

    let app_weak = app.as_weak();
    let events_handle = handle.clone();
    tokio::spawn(async move {
        let mut events = events_handle.subscribe();
        if let Ok(AppWatcherResponse::State(apps)) =
            events_handle.request(AppWatcherRequest::GetState).await
        {
            push(&app_weak, apps);
        }
        loop {
            let apps = match events.recv().await {
                Ok(apps) => apps,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            };
            push(&app_weak, apps);
        }
    });

    let add_handle = handle.clone();
    app.on_watcher_add_app(move || {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Executable", &["exe"])
            .set_title("Select application to watch")
            .pick_file()
        {
            let handle = add_handle.clone();
            tokio::spawn(async move {
                let _ = handle.request(AppWatcherRequest::Add(path)).await;
            });
        }
    });

    app.on_watcher_remove_app(move |idx| {
        let handle = handle.clone();
        tokio::spawn(async move {
            let _ = handle.request(AppWatcherRequest::Remove(idx as usize)).await;
        });
    });
}

fn push(app_weak: &slint::Weak<App>, apps: Vec<AppState>) {
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
            app.set_watcher_apps(Rc::new(slint::VecModel::from(items)).into());
        })
        .ok();
}
