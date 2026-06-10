use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time;

use crate::modules::{Context, Module, ModuleError};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppState {
    pub exe_path: String,
    pub display_name: String,
    pub is_running: bool,
    pub error: String,
}

#[derive(Serialize, Deserialize)]
pub enum AppWatcherRequest {
    Add(PathBuf),
    Remove(usize),
    GetState,
}

#[derive(Serialize, Deserialize)]
pub enum AppWatcherResponse {
    Ack,
    State(Vec<AppState>),
}

// no persistence yet — the watch list starts empty each run (revisit with the
// storage backend).
pub struct AppWatcherModule {
    paths: Vec<PathBuf>,
}

impl Module for AppWatcherModule {
    const NAME: &str = "app_watcher";

    type Request = AppWatcherRequest;
    type Response = AppWatcherResponse;
    type Event = Vec<AppState>;

    fn new() -> Self {
        Self { paths: Vec::new() }
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let mut tick = time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => {
                        let resp = match req.payload {
                            AppWatcherRequest::Add(ref path) => {
                                launch_if_offline(path);
                                self.paths.push(path.clone());
                                ctx.publish(self.snapshot());
                                Ok(AppWatcherResponse::Ack)
                            }
                            AppWatcherRequest::Remove(i) if i < self.paths.len() => {
                                self.paths.remove(i);
                                ctx.publish(self.snapshot());
                                Ok(AppWatcherResponse::Ack)
                            }
                            AppWatcherRequest::Remove(_) => {
                                Err(ModuleError::Other("watch index out of range".into()))
                            }
                            AppWatcherRequest::GetState => {
                                Ok(AppWatcherResponse::State(self.snapshot()))
                            }
                        };
                        req.reply(resp);
                    }
                    None => break, // every handle dropped → shut down
                },
                _ = tick.tick() => ctx.publish(self.snapshot()),
            }
        }
    }
}

impl AppWatcherModule {
    fn snapshot(&self) -> Vec<AppState> {
        self.paths.iter().map(state_of).collect()
    }
}

fn state_of(path: &PathBuf) -> AppState {
    AppState {
        exe_path: path.to_string_lossy().into_owned(),
        display_name: path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
        is_running: is_running(path),
        error: if path.exists() { String::new() } else { "File not found".into() },
    }
}

fn is_running(path: &Path) -> bool {
    if !path.exists() { return false; }
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        matches!(OpenOptions::new().write(true).open(path), Err(e) if e.raw_os_error() == Some(32))
    }
    #[cfg(not(windows))]
    {
        let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        sys.processes_by_name(name.as_ref()).next().is_some()
    }
}

fn launch_if_offline(path: &Path) {
    if !path.exists() || is_running(path) { return; }
    let mut cmd = Command::new(path);
    #[cfg(windows)]
    { cmd.creation_flags(0x00000008); }
    let _ = cmd.spawn();
}
