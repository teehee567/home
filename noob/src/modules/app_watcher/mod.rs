pub mod app_watcher_store;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sea_orm::sea_query::TableCreateStatement;
use sea_orm::{
    ActiveModelTrait, ActiveValue, DatabaseConnection, EntityTrait, QueryOrder, Schema,
};
use serde::{Deserialize, Serialize};
use tokio::time;

use crate::modules::{Context, Module, ModuleError};
use crate::storage::NodeDeps;

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

pub struct AppWatcherModule {
    /// row id maps remove delete
    apps: Vec<(i32, PathBuf)>,
    db: DatabaseConnection,
}

impl Module for AppWatcherModule {
    const NAME: &str = "app_watcher";

    type Request = AppWatcherRequest;
    type Response = AppWatcherResponse;
    type Event = Vec<AppState>;

    fn tables(schema: &Schema) -> Vec<TableCreateStatement> {
        vec![schema.create_table_from_entity(app_watcher_store::Entity)]
    }

    async fn new(deps: &NodeDeps) -> Result<Self, ModuleError> {
        let db = deps.db();
        let apps = app_watcher_store::Entity::find()
            .order_by_asc(app_watcher_store::Column::Id)
            .all(&db)
            .await?
            .into_iter()
            .map(|m| (m.id, PathBuf::from(m.exe_path)))
            .collect();
        Ok(Self { apps, db })
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let mut tick = time::interval(Duration::from_secs(60));
        self.launch_all_offline();
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => {
                        let resp = match req.payload {
                            AppWatcherRequest::Add(ref path) => {
                                launch_if_offline(path);
                                self.add(path.clone()).await.map(|()| {
                                    ctx.publish(self.snapshot());
                                    AppWatcherResponse::Ack
                                })
                            }
                            AppWatcherRequest::Remove(i) if i < self.apps.len() => {
                                self.remove(i).await.map(|()| {
                                    ctx.publish(self.snapshot());
                                    AppWatcherResponse::Ack
                                })
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
    async fn add(&mut self, path: PathBuf) -> Result<(), ModuleError> {
        let inserted = app_watcher_store::ActiveModel {
            exe_path: ActiveValue::Set(path.to_string_lossy().into_owned()),
            ..Default::default()
        }
        .insert(&self.db)
        .await?;
        self.apps.push((inserted.id, path));
        Ok(())
    }

    async fn remove(&mut self, i: usize) -> Result<(), ModuleError> {
        app_watcher_store::Entity::delete_by_id(self.apps[i].0).exec(&self.db).await?;
        self.apps.remove(i);
        Ok(())
    }

    fn snapshot(&self) -> Vec<AppState> {
        self.apps.iter().map(|(_, path)| state_of(path)).collect()
    }

    fn launch_all_offline(&self) {
        for (_, path) in &self.apps {
            launch_if_offline(path);
        }
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
