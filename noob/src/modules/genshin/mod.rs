#[cfg(windows)]
mod fps_etw;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::time;

use fps_etw::EtwSession;

use crate::modules::{Context, Module};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GenshinState {
    pub fps: Option<u32>,
    pub running: bool,
}

#[derive(Serialize, Deserialize)]
pub enum GenshinRequest {
    GetState,
}

pub struct GenshinModule {
    current: GenshinState,
    tracked_pid: Option<u32>,
    etw: Option<(Arc<AtomicU32>, EtwSession)>,
    scan_counter: u32,
}

impl Module for GenshinModule {
    const NAME: &str = "genshin";

    type Request = GenshinRequest;
    type Response = GenshinState;
    type Event = GenshinState;

    fn new() -> Self {
        Self {
            current: GenshinState { fps: None, running: false },
            tracked_pid: None,
            etw: None,
            scan_counter: 0,
        }
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let mut tick = time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => match req.payload {
                        GenshinRequest::GetState => req.reply(Ok(self.current.clone())),
                    },
                    None => break, // every handle dropped → shut down
                },
                _ = tick.tick() => {
                    if self.poll_once().await {
                        ctx.publish(self.current.clone());
                    }
                }
            }
        }
    }
}

impl GenshinModule {
    pub fn stop_etw() {
        EtwSession::stop_session();
    }

    async fn poll_once(&mut self) -> bool {
        self.scan_counter += 1;
        if self.scan_counter >= 20 {
            self.scan_counter = 0;

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
                Some(pid) if self.tracked_pid != Some(pid) => {
                    self.tracked_pid = Some(pid);
                    self.etw = EtwSession::start(pid).await.ok();
                }
                None if self.tracked_pid.is_some() => {
                    self.tracked_pid = None;
                    self.etw = None;
                }
                _ => {}
            }
        }

        let next = if self.tracked_pid.is_some() {
            let fps = self
                .etw
                .as_ref()
                .map(|(a, _)| a.load(Ordering::Relaxed))
                .filter(|&v| v != 0);
            GenshinState { fps, running: true }
        } else {
            GenshinState { fps: None, running: false }
        };

        if next != self.current {
            self.current = next;
            true
        } else {
            false
        }
    }
}
