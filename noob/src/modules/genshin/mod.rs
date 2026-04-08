mod fps_etw;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use sysinfo::System;
use tokio::time;

use fps_etw::EtwSession;

#[derive(Clone, PartialEq)]
pub struct GenshinState {
    pub fps: Option<u32>,
    pub running: bool,
}

pub struct GenshinModule;

impl GenshinModule {
    pub async fn start(on_state: impl Fn(GenshinState) + Send + 'static) {
        Self::run_poll_loop(on_state).await;
    }

    pub fn stop_etw() {
        EtwSession::stop_session();
    }

    async fn run_poll_loop(on_state: impl Fn(GenshinState) + Send + 'static) {
        let mut tracked_pid: Option<u32> = None;
        let mut etw: Option<(Arc<AtomicU32>, EtwSession)> = None;
        let mut last = GenshinState { fps: None, running: false };
        let mut tick = time::interval(Duration::from_millis(100));
        let mut scan_counter: u32 = 0;

        loop {
            tick.tick().await;
            scan_counter += 1;

            if scan_counter >= 20 {
                scan_counter = 0;

                let found_pid = tokio::task::spawn_blocking(|| {
                    let mut sys = System::new();
                    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
                    sys.processes_by_name("GenshinImpact.exe".as_ref())
                        .next()
                        .map(|p| p.pid().as_u32())
                })
                .await
                .unwrap();

                match found_pid {
                    Some(pid) if tracked_pid != Some(pid) => {
                        tracked_pid = Some(pid);
                        etw = EtwSession::start(pid).await.ok();
                    }
                    None if tracked_pid.is_some() => {
                        tracked_pid = None;
                        etw = None;
                    }
                    _ => {}
                }
            }

            let next = if tracked_pid.is_some() {
                let fps = etw.as_ref()
                    .map(|(a, _)| a.load(Ordering::Relaxed))
                    .filter(|&v| v != 0);
                GenshinState { fps, running: true }
            } else {
                GenshinState { fps: None, running: false }
            };

            if next != last {
                on_state(next.clone());
                last = next;
            }
        }
    }
}
