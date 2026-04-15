use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::{fs, time};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Clone, Debug)]
pub struct AppState {
    pub exe_path: String,
    pub display_name: String,
    pub is_running: bool,
    pub error: String,
}

pub enum WatcherCommand {
    Add(PathBuf),
    Remove(usize),
}

pub fn start(
    on_state: impl Fn(Vec<AppState>) + Send + 'static,
) -> UnboundedSender<WatcherCommand> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let store = store_path();
        let mut paths: Vec<PathBuf> = fs::read_to_string(&store)
            .await
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(PathBuf::from).collect())
            .unwrap_or_default();

        for p in &paths {
            launch_if_offline(p);
        }

        let mut tick = time::interval(Duration::from_secs(60));
        loop {
            on_state(paths.iter().map(state_of).collect());
            tokio::select! {
                _ = tick.tick() => {}
                Some(cmd) = rx.recv() => {
                    match cmd {
                        WatcherCommand::Add(p) => { launch_if_offline(&p); paths.push(p); }
                        WatcherCommand::Remove(i) if i < paths.len() => { paths.remove(i); }
                        _ => continue,
                    }
                    save(&store, &paths).await;
                }
            }
        }
    });
    tx
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

fn store_path() -> PathBuf {
    let mut p = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push("noob");
    p.push("watched_apps.txt");
    p
}

async fn save(path: &Path, paths: &[PathBuf]) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    let data = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join("\n");
    let _ = fs::write(path, data).await;
}
