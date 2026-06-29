#[cfg(windows)]
mod fps_etw;
pub mod genshin_store;
pub mod wish;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sea_orm::sea_query::{OnConflict, TableCreateStatement};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, Iterable, QueryFilter,
    QueryOrder, Schema,
};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::sync::mpsc;
use tokio::time;

use fps_etw::EtwSession;

use crate::modules::{Context, Module, ModuleError, Request};
use crate::storage::NodeDeps;
use genshin_store::Model as WishRecord;
use wish::{FetchResult, Game, GameProfile, WishStats};

/// Process to watch for the live FPS counter.
const GAME_PROCESS: &str = "GenshinImpact.exe";
/// Rescan the process list every N ticks of the 100ms loop (~2s).
const RESCAN_EVERY_TICKS: u32 = 20;
/// Rows per insert, kept well under SQLite's 999-bind-variable limit.
const DB_CHUNK: usize = 50;

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ExportStatus {
    Running,
    Success,
    Failure,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GenshinState {
    pub fps: Option<u32>,
    pub running: bool,
}

/// progress for an in-flight (or finished) wish export, streamed as an event.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExportProgress {
    pub status: ExportStatus,
    pub message: String,
    /// populated on `Success`
    pub stats: Option<WishStats>,
}

impl ExportProgress {
    fn running(message: impl Into<String>) -> Self {
        Self { status: ExportStatus::Running, message: message.into(), stats: None }
    }

    fn failure(message: impl Into<String>) -> Self {
        Self { status: ExportStatus::Failure, message: message.into(), stats: None }
    }

    fn success(message: impl Into<String>, stats: WishStats) -> Self {
        Self { status: ExportStatus::Success, message: message.into(), stats: Some(stats) }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum GenshinEvent {
    /// live FPS / running state (100ms tick)
    Fps(GenshinState),
    /// wish-export progress + final result, per game
    Export { game: Game, progress: ExportProgress },
}

#[derive(Serialize, Deserialize)]
pub enum GenshinRequest {
    GetState,
    GetStats { game: Game },
    /// pull wish history; `full` re-fetches everything instead of just new pulls
    ExportWishes { game: Game, full: bool },
    /// write the stored history to `path` as a UIGF v4 document
    ExportToFile { game: Game, path: PathBuf },
}

#[derive(Serialize, Deserialize)]
pub enum GenshinResponse {
    State(GenshinState),
    Stats { game: Game, stats: WishStats },
    Ack,
}

/// task → run-loop messages for the background fetch
enum ExportMsg {
    Progress(Game, String),
    Done(Game, Result<FetchResult, String>),
}

/// Stored wish history for one game, plus its in-flight export bookkeeping.
struct GameData {
    records: Vec<WishRecord>,
    timezone: i32,
    exporting: bool,
}

impl GameData {
    /// highest stored id per banner, used to fetch only newer pulls
    fn last_ids(&self) -> HashMap<String, String> {
        let mut highest: HashMap<String, String> = HashMap::new();
        for r in &self.records {
            let entry = highest.entry(r.gacha_type.clone()).or_default();
            if r.id > *entry {
                *entry = r.id.clone();
            }
        }
        highest
    }

    /// add fetched rows we don't already hold, keeping the list in id order
    fn merge_records(&mut self, fetched: Vec<WishRecord>) {
        let known: HashSet<&String> = self.records.iter().map(|r| &r.id).collect();
        let new: Vec<WishRecord> = fetched.into_iter().filter(|r| !known.contains(&r.id)).collect();
        self.records.extend(new);
        self.records.sort_by(|a, b| a.id.cmp(&b.id));
    }
}

/// shared exporter profile for a game
fn profile_for(game: Game) -> &'static GameProfile {
    match game {
        Game::Genshin => &wish::GENSHIN,
        Game::StarRail => &wish::STAR_RAIL,
    }
}

pub struct GenshinModule {
    current: GenshinState,
    tracked_pid: Option<u32>,
    etw: Option<(Arc<AtomicU32>, EtwSession)>,
    scan_counter: u32,

    db: DatabaseConnection,
    genshin: GameData,
    star_rail: GameData,
    result_tx: Option<mpsc::UnboundedSender<ExportMsg>>,
}

impl Module for GenshinModule {
    const NAME: &str = "genshin";

    type Request = GenshinRequest;
    type Response = GenshinResponse;
    type Event = GenshinEvent;

    fn tables(schema: &Schema) -> Vec<TableCreateStatement> {
        vec![schema.create_table_from_entity(genshin_store::Entity)]
    }

    async fn new(deps: &NodeDeps) -> Result<Self, ModuleError> {
        let db = deps.db();
        let load = |game: Game| {
            let db = db.clone();
            async move {
                genshin_store::Entity::find()
                    .filter(genshin_store::Column::Game.eq(game.tag()))
                    .order_by_asc(genshin_store::Column::Id)
                    .all(&db)
                    .await
            }
        };
        let genshin = GameData { records: load(Game::Genshin).await?, timezone: 8, exporting: false };
        let star_rail =
            GameData { records: load(Game::StarRail).await?, timezone: 8, exporting: false };
        Ok(Self {
            current: GenshinState { fps: None, running: false },
            tracked_pid: None,
            etw: None,
            scan_counter: 0,
            db,
            genshin,
            star_rail,
            result_tx: None,
        })
    }

    async fn run(mut self, mut ctx: Context<Self>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.result_tx = Some(tx);

        let mut tick = time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                msg = ctx.recv() => match msg {
                    Some(req) => self.handle_request(req, &ctx).await,
                    None => break, // every handle dropped → shut down
                },
                Some(msg) = rx.recv() => self.handle_export_msg(msg, &ctx).await,
                _ = tick.tick() => {
                    if self.poll_once().await {
                        ctx.publish(GenshinEvent::Fps(self.current.clone()));
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

    async fn handle_request(&mut self, req: Request<Self>, ctx: &Context<Self>) {
        match &req.payload {
            GenshinRequest::GetState => {
                req.reply(Ok(GenshinResponse::State(self.current.clone())));
            }
            &GenshinRequest::GetStats { game } => {
                let stats = wish::compute_stats(profile_for(game), &self.game(game).records);
                req.reply(Ok(GenshinResponse::Stats { game, stats }));
            }
            GenshinRequest::ExportToFile { game, path } => {
                let resp = self.write_uigf(*game, path).map(|()| GenshinResponse::Ack);
                req.reply(resp);
            }
            &GenshinRequest::ExportWishes { game, full } => {
                self.start_export(game, full, ctx);
                req.reply(Ok(GenshinResponse::Ack));
            }
        }
    }

    fn game(&self, game: Game) -> &GameData {
        match game {
            Game::Genshin => &self.genshin,
            Game::StarRail => &self.star_rail,
        }
    }

    fn game_mut(&mut self, game: Game) -> &mut GameData {
        match game {
            Game::Genshin => &mut self.genshin,
            Game::StarRail => &mut self.star_rail,
        }
    }

    /// Kick off a background fetch unless one is already running for this game.
    /// The fetch runs off the actor loop and reports back over `result_tx`;
    /// persistence happens in `handle_export_msg` when the `Done` message arrives.
    fn start_export(&mut self, game: Game, full: bool, ctx: &Context<Self>) {
        let data = self.game_mut(game);
        if data.exporting {
            return;
        }
        data.exporting = true;
        let last_ids = if full { HashMap::new() } else { data.last_ids() };
        ctx.publish(GenshinEvent::Export { game, progress: ExportProgress::running("starting export") });

        let tx = self.result_tx.clone().expect("result channel set in run()");
        tokio::spawn(async move {
            let send = |m: String| {
                let _ = tx.send(ExportMsg::Progress(game, m));
            };
            let result = run_export(game, last_ids, &send).await.map_err(|e| e.to_string());
            let _ = tx.send(ExportMsg::Done(game, result));
        });
    }

    async fn handle_export_msg(&mut self, msg: ExportMsg, ctx: &Context<Self>) {
        let (game, progress) = match msg {
            ExportMsg::Progress(game, message) => (game, ExportProgress::running(message)),

            ExportMsg::Done(game, Ok(result)) => {
                let imported = result.records.len();
                let progress = match persist(&self.db, &result.records).await {
                    Ok(()) => {
                        let data = self.game_mut(game);
                        data.exporting = false;
                        data.timezone = result.timezone;
                        data.merge_records(result.records);
                        let stats = wish::compute_stats(profile_for(game), &data.records);
                        ExportProgress::success(format!("imported {imported} new pull(s)"), stats)
                    }
                    Err(e) => {
                        self.game_mut(game).exporting = false;
                        ExportProgress::failure(format!("save failed: {e}"))
                    }
                };
                (game, progress)
            }

            ExportMsg::Done(game, Err(e)) => {
                self.game_mut(game).exporting = false;
                (game, ExportProgress::failure(e))
            }
        };
        ctx.publish(GenshinEvent::Export { game, progress });
    }

    fn write_uigf(&self, game: Game, path: &Path) -> Result<(), ModuleError> {
        let data = self.game(game);
        let uid = data.records.first().map(|r| r.uid.clone()).unwrap_or_default();
        let lang = data.records.first().map(|r| r.lang.clone()).unwrap_or_default();
        let doc = wish::to_uigf_v4(profile_for(game), &data.records, &uid, &lang, data.timezone);
        let text =
            serde_json::to_string_pretty(&doc).map_err(|e| ModuleError::Other(e.to_string()))?;
        std::fs::write(path, text).map_err(|e| ModuleError::Other(e.to_string()))?;
        Ok(())
    }

    /// One tick of the FPS loop. Periodically rescans for the game process and
    /// (re)starts the ETW session, then reads the current FPS. Returns `true`
    /// when the published state changed.
    async fn poll_once(&mut self) -> bool {
        self.scan_counter += 1;
        if self.scan_counter >= RESCAN_EVERY_TICKS {
            self.scan_counter = 0;
            self.rescan_process().await;
        }

        let next = if self.tracked_pid.is_some() {
            // a reading of 0 means "no frames counted yet", surface it as unknown.
            // fps is None too if the ETW session failed to start.
            let fps = self.etw.as_ref().map(|(fps, _)| fps.load(Ordering::Relaxed)).filter(|&v| v != 0);
            GenshinState { fps, running: true }
        } else {
            GenshinState { fps: None, running: false }
        };

        let changed = next != self.current;
        self.current = next;
        changed
    }

    /// Find the game process and start/stop the ETW FPS session to match.
    async fn rescan_process(&mut self) {
        let found_pid = tokio::task::spawn_blocking(|| {
            let mut sys = System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            sys.processes_by_name(GAME_PROCESS.as_ref()).next().map(|p| p.pid().as_u32())
        })
        .await
        .unwrap();

        match found_pid {
            // newly seen (or changed) pid → attach a fresh ETW session
            Some(pid) if self.tracked_pid != Some(pid) => {
                self.tracked_pid = Some(pid);
                self.etw = EtwSession::start(pid).await.ok();
            }
            // game closed → drop the session (its Drop stops the trace)
            None if self.tracked_pid.is_some() => {
                self.tracked_pid = None;
                self.etw = None;
            }
            _ => {}
        }
    }
}

/// run the whole fetch off the actor loop (network only; persistence happens
/// back in the run loop on `ExportMsg::Done`).
async fn run_export(
    game: Game,
    last_ids: HashMap<String, String>,
    progress: &(dyn Fn(String) + Send + Sync),
) -> Result<FetchResult, wish::FetchError> {
    let profile = profile_for(game);
    let url = wish::find_url(profile).ok_or(wish::FetchError::NoUrl)?;
    let (endpoint, query) = wish::clean_query(profile, &url).ok_or(wish::FetchError::NoUrl)?;
    let client = reqwest::Client::new();
    wish::fetch_all(&client, profile, &endpoint, &query, &last_ids, progress).await
}

/// upsert fetched rows by primary key, chunked to stay under SQLite's bind limit
async fn persist(db: &DatabaseConnection, records: &[WishRecord]) -> Result<(), ModuleError> {
    use genshin_store::Column as C;
    // on a duplicate id, refresh every column except the primary key
    let conflict = OnConflict::columns([C::Game, C::Id])
        .update_columns(C::iter().filter(|c| !matches!(c, C::Id | C::Game)))
        .to_owned();
    for chunk in records.chunks(DB_CHUNK) {
        let models = chunk.iter().cloned().map(IntoActiveModel::into_active_model);
        genshin_store::Entity::insert_many(models)
            .on_conflict(conflict.clone())
            .exec(db)
            .await?;
    }
    Ok(())
}
