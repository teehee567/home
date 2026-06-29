use std::rc::Rc;
use std::sync::Arc;

use noob::modules::genshin::{
    ExportStatus, GenshinEvent, GenshinRequest, GenshinResponse, GenshinState,
};
use noob::modules::genshin::wish::WishStats;
use slint::ComponentHandle;
use tokio::sync::broadcast::error::RecvError;

use crate::node::DesktopNode;
use crate::{App, WishBannerStat};

pub fn setup(app: &App, node: Arc<DesktopNode>) {
    let app_weak = app.as_weak();
    let handle = node.modules().Genshin.clone().expect("genshin hosted on desktop");

    // event stream: FPS state + wish-export progress
    let events_handle = handle.clone();
    let events_weak = app_weak.clone();
    tokio::spawn(async move {
        // seed banner stats from persisted history
        if let Ok(GenshinResponse::Stats(stats)) =
            events_handle.request(GenshinRequest::GetStats).await
        {
            push_stats(&events_weak, stats);
        }

        // Keep `handle` alive for the task's lifetime: dropping the last handle
        // shuts the module down.
        let mut events = events_handle.subscribe();
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            };
            match event {
                GenshinEvent::Fps(state) => push_fps(&events_weak, state),
                GenshinEvent::Export(progress) => {
                    let busy = progress.status == ExportStatus::Running;
                    let status = progress.message;
                    events_weak
                        .upgrade_in_event_loop(move |app: App| {
                            app.set_wish_busy(busy);
                            app.set_wish_status(status.into());
                        })
                        .ok();
                    if let Some(stats) = progress.stats {
                        push_stats(&events_weak, stats);
                    }
                }
            }
        }
    });

    let export_handle = handle.clone();
    app.on_genshin_export_wishes(move |full| {
        let handle = export_handle.clone();
        tokio::spawn(async move {
            let _ = handle.request(GenshinRequest::ExportWishes { full }).await;
        });
    });

    app.on_genshin_export_file(move || {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("UIGF JSON", &["json"])
            .set_file_name("genshin_wishes_uigf.json")
            .set_title("Export wish history (UIGF v4)")
            .save_file()
        else {
            return;
        };
        let handle = handle.clone();
        let weak = app_weak.clone();
        tokio::spawn(async move {
            let msg = match handle.request(GenshinRequest::ExportToFile { path }).await {
                Ok(_) => "Exported UIGF file.".to_string(),
                Err(e) => format!("Export failed: {e}"),
            };
            weak.upgrade_in_event_loop(move |app: App| app.set_wish_status(msg.into())).ok();
        });
    });
}

fn push_fps(app_weak: &slint::Weak<App>, state: GenshinState) {
    app_weak
        .upgrade_in_event_loop(move |app: App| {
            app.set_running(state.running);
            app.set_fps_text(
                state.fps.map(|f| f.to_string()).unwrap_or_else(|| "---".into()).into(),
            );
            app.set_status_text(
                if state.running { "Running" } else { "Genshin Impact not running" }.into(),
            );
        })
        .ok();
}

fn push_stats(app_weak: &slint::Weak<App>, stats: WishStats) {
    app_weak
        .upgrade_in_event_loop(move |app: App| {
            let items: Vec<WishBannerStat> = stats
                .banners
                .into_iter()
                .map(|b| WishBannerStat {
                    name: b.name.into(),
                    total: b.total as i32,
                    pity: b.pity as i32,
                    five_star: b.five_star as i32,
                    four_star: b.four_star as i32,
                    avg_pity: if b.last_five.is_empty() {
                        "-".into()
                    } else {
                        format!("{:.1}", b.avg_pity).into()
                    },
                })
                .collect();
            app.set_wish_banners(Rc::new(slint::VecModel::from(items)).into());
        })
        .ok();
}
