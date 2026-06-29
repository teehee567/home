use std::rc::Rc;
use std::sync::{Arc, Mutex};

use noob::modules::genshin::wish::{self, BannerStats, Game, WishStats};
use noob::modules::genshin::{
    ExportStatus, GenshinEvent, GenshinRequest, GenshinResponse, GenshinState,
};
use slint::{Color, ComponentHandle, ModelRc, SharedString, VecModel};
use tokio::sync::broadcast::error::RecvError;

use crate::node::DesktopNode;
use crate::{App, WishBreakdown, WishGraphData, WishPill, WishStatCard};

// rarity accents, must match Rarity global in wishes.slint
const C_THREE: (u8, u8, u8) = (88, 166, 255);
const C_FOUR: (u8, u8, u8) = (188, 140, 255);
const C_FIVE: (u8, u8, u8) = (210, 153, 34);

/// UI state for one game: the full computed stats, the selected banner index and
/// the chart plot pixel size (so paths can be rebuilt 1:1 with the viewbox).
struct GameUi {
    game: Game,
    stats: Mutex<WishStats>,
    selected: Mutex<usize>,
    plot: Mutex<(f32, f32)>,
}

impl GameUi {
    fn new(game: Game) -> Self {
        Self {
            game,
            stats: Mutex::new(WishStats::default()),
            selected: Mutex::new(0),
            plot: Mutex::new((360.0, 150.0)),
        }
    }
}

struct Shared {
    gi: GameUi,
    hsr: GameUi,
}

impl Shared {
    fn of(&self, game: Game) -> &GameUi {
        match game {
            Game::Genshin => &self.gi,
            Game::StarRail => &self.hsr,
        }
    }
}

pub fn setup(app: &App, node: Arc<DesktopNode>) {
    let handle = node.modules().Genshin.clone().expect("genshin hosted on desktop");
    let shared = Arc::new(Shared { gi: GameUi::new(Game::Genshin), hsr: GameUi::new(Game::StarRail) });

    register_game_callbacks(app, &handle, &shared, Game::Genshin);
    register_game_callbacks(app, &handle, &shared, Game::StarRail);

    // event stream: FPS state + per-game wish-export progress
    let events_handle = handle.clone();
    let weak = app.as_weak();
    let task_shared = shared.clone();
    tokio::spawn(async move {
        // seed both games' stats from persisted history
        for game in [Game::Genshin, Game::StarRail] {
            if let Ok(GenshinResponse::Stats { game, stats }) =
                events_handle.request(GenshinRequest::GetStats { game }).await
            {
                store_and_paint(&weak, &task_shared, game, stats);
            }
        }

        // hold `events_handle` for the task's lifetime; dropping the last handle
        // shuts the module down.
        let mut events = events_handle.subscribe();
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            };
            match event {
                GenshinEvent::Fps(state) => push_fps(&weak, state),
                GenshinEvent::Export { game, progress } => {
                    let busy = progress.status == ExportStatus::Running;
                    let status: SharedString = progress.message.into();
                    let _ = weak.upgrade_in_event_loop(move |app| set_status(&app, game, busy, status));
                    if let Some(stats) = progress.stats {
                        store_and_paint(&weak, &task_shared, game, stats);
                    }
                }
            }
        }
    });
}

/// register the update / refresh / export / select / resize callbacks for one game.
fn register_game_callbacks(
    app: &App,
    handle: &noob::modules::Handle<noob::modules::genshin::GenshinModule>,
    shared: &Arc<Shared>,
    game: Game,
) {
    // Update / Full refresh
    let h = handle.clone();
    let on_export = move |full: bool| {
        let h = h.clone();
        tokio::spawn(async move {
            let _ = h.request(GenshinRequest::ExportWishes { game, full }).await;
        });
    };
    let e1 = on_export.clone();
    let e2 = on_export;
    // Export UIGF to file
    let h_file = handle.clone();
    let weak_file = app.as_weak();
    let on_file = move || {
        let (filter, default_name, title) = match game {
            Game::Genshin => ("UIGF JSON", "genshin_wishes_uigf.json", "Export wish history (UIGF v4)"),
            Game::StarRail => ("UIGF JSON", "starrail_warps_uigf.json", "Export warp history (UIGF v4)"),
        };
        let Some(path) = rfd::FileDialog::new()
            .add_filter(filter, &["json"])
            .set_file_name(default_name)
            .set_title(title)
            .save_file()
        else {
            return;
        };
        let h = h_file.clone();
        let weak = weak_file.clone();
        tokio::spawn(async move {
            let msg: SharedString = match h.request(GenshinRequest::ExportToFile { game, path }).await {
                Ok(_) => "Exported UIGF file.".into(),
                Err(e) => format!("Export failed: {e}").into(),
            };
            let _ = weak.upgrade_in_event_loop(move |app| set_status(&app, game, false, msg));
        });
    };

    // Banner selection — repaint immediately on the UI thread
    let sel_shared = shared.clone();
    let sel_weak = app.as_weak();
    let on_select = move |idx: i32| {
        *sel_shared.of(game).selected.lock().unwrap() = idx.max(0) as usize;
        if let Some(app) = sel_weak.upgrade() {
            paint(&app, sel_shared.of(game));
        }
    };

    // Plot resized — guard unchanged sizes, then repaint deferred (avoids
    // re-entrancy with slint's layout pass, same as the metrics charts).
    let rs_shared = shared.clone();
    let rs_weak = app.as_weak();
    let on_resized = move |w: f32, h: f32| {
        {
            let mut plot = rs_shared.of(game).plot.lock().unwrap();
            if (plot.0 - w).abs() < 0.5 && (plot.1 - h).abs() < 0.5 {
                return;
            }
            *plot = (w, h);
        }
        let weak = rs_weak.clone();
        let shared = rs_shared.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(app) = weak.upgrade() {
                paint(&app, shared.of(game));
            }
        });
    };

    match game {
        Game::Genshin => {
            app.on_gi_update(move || e1(false));
            app.on_gi_full_refresh(move || e2(true));
            app.on_gi_export_file(on_file);
            app.on_gi_select_banner(on_select);
            app.on_gi_wish_resized(on_resized);
        }
        Game::StarRail => {
            app.on_hsr_update(move || e1(false));
            app.on_hsr_full_refresh(move || e2(true));
            app.on_hsr_export_file(on_file);
            app.on_hsr_select_banner(on_select);
            app.on_hsr_wish_resized(on_resized);
        }
    }
}

fn store_and_paint(weak: &slint::Weak<App>, shared: &Arc<Shared>, game: Game, stats: WishStats) {
    *shared.of(game).stats.lock().unwrap() = stats;
    let shared = shared.clone();
    let _ = weak.upgrade_in_event_loop(move |app| paint(&app, shared.of(game)));
}

fn set_status(app: &App, game: Game, busy: bool, status: SharedString) {
    match game {
        Game::Genshin => {
            app.set_gi_wish_busy(busy);
            app.set_gi_wish_status(status);
        }
        Game::StarRail => {
            app.set_hsr_wish_busy(busy);
            app.set_hsr_wish_status(status);
        }
    }
}

fn push_fps(weak: &slint::Weak<App>, state: GenshinState) {
    let _ = weak.upgrade_in_event_loop(move |app: App| {
        app.set_running(state.running);
        app.set_fps_text(state.fps.map(|f| f.to_string()).unwrap_or_else(|| "---".into()).into());
        app.set_status_text(
            if state.running { "Running" } else { "Genshin Impact not running" }.into(),
        );
    });
}

/// Build every display model for the selected banner and push it to the app.
fn paint(app: &App, gu: &GameUi) {
    let stats = gu.stats.lock().unwrap();
    let banners = &stats.banners;
    let names: Vec<SharedString> = banners.iter().map(|b| b.name.clone().into()).collect();
    let mut sel = *gu.selected.lock().unwrap();
    if sel >= banners.len() {
        sel = 0;
    }
    let plot = *gu.plot.lock().unwrap();

    let (overview, graph, breakdown, pills) = match banners.get(sel) {
        Some(b) => (
            overview_cards(gu.game, b),
            graph_data(b, plot),
            breakdown_of(b),
            pill_list(b),
        ),
        None => (vec![], WishGraphData::default(), WishBreakdown::default(), vec![]),
    };

    match gu.game {
        Game::Genshin => {
            app.set_gi_banner_names(model(names));
            app.set_gi_selected(sel as i32);
            app.set_gi_overview(model(overview));
            app.set_gi_graph(graph);
            app.set_gi_breakdown(breakdown);
            app.set_gi_pills(model(pills));
        }
        Game::StarRail => {
            app.set_hsr_banner_names(model(names));
            app.set_hsr_selected(sel as i32);
            app.set_hsr_overview(model(overview));
            app.set_hsr_graph(graph);
            app.set_hsr_breakdown(breakdown);
            app.set_hsr_pills(model(pills));
        }
    }
}

fn overview_cards(game: Game, b: &BannerStats) -> Vec<WishStatCard> {
    let primos = b.total as u64 * wish::PULL_COST as u64;
    vec![
        card("Total Pulls", commas(b.total as u64), "lifetime", C_THREE),
        card(wish::currency_name(game), commas(primos), "spent", C_FIVE),
        card("5★ Pity", b.pity.to_string(), format!("Guaranteed at {}", b.five_cap), C_FIVE),
        card("4★ Pity", b.four_pity.to_string(), format!("Guaranteed at {}", b.four_cap), C_FOUR),
    ]
}

fn graph_data(b: &BannerStats, (w, h): (f32, f32)) -> WishGraphData {
    let months = &b.months;
    let n = months.len();
    let three: Vec<u32> = months.iter().map(|m| m.three).collect();
    let four: Vec<u32> = months.iter().map(|m| m.four).collect();
    let five: Vec<u32> = months.iter().map(|m| m.five).collect();

    let peak = months.iter().map(|m| m.three.max(m.four).max(m.five)).max().unwrap_or(0);
    let max = nice_max(peak as f64);
    let (w, h) = (w as f64, h as f64);

    let (three_line, three_fill) = series_paths(&three, max, w, h);
    let (four_line, four_fill) = series_paths(&four, max, w, h);
    let (five_line, five_fill) = series_paths(&five, max, w, h);

    // five evenly-spaced month labels along the x-axis
    let label = |i: usize| months.get(i).map(|m| m.label.clone()).unwrap_or_default().into();
    let last = n.saturating_sub(1);

    WishGraphData {
        three_line: three_line.into(),
        three_fill: three_fill.into(),
        four_line: four_line.into(),
        four_fill: four_fill.into(),
        five_line: five_line.into(),
        five_fill: five_fill.into(),
        y_top: (max as u64).to_string().into(),
        y_mid: ((max / 2.0) as u64).to_string().into(),
        x0: label(0),
        x1: label(last / 4),
        x2: label(last / 2),
        x3: label(3 * last / 4),
        x4: label(last),
        has_data: n > 0 && b.total > 0,
    }
}

fn breakdown_of(b: &BannerStats) -> WishBreakdown {
    WishBreakdown {
        five_total: b.five_star.to_string().into(),
        five_percent: pct(b.five_star, b.total).into(),
        five_pity: avg(b.avg_pity).into(),
        five_win_total: b.five_win.to_string().into(),
        five_win_percent: pct(b.five_win, b.five_attempts).into(),
        four_total: b.four_star.to_string().into(),
        four_percent: pct(b.four_star, b.total).into(),
        four_pity: avg(b.four_avg_pity).into(),
        four_char_total: b.four_char.to_string().into(),
        four_char_percent: pct(b.four_char, b.total).into(),
        four_weapon_total: b.four_weapon.to_string().into(),
        four_weapon_percent: pct(b.four_weapon, b.total).into(),
        four_win_total: b.four_win.to_string().into(),
        four_win_percent: pct(b.four_win, b.four_attempts).into(),
    }
}

fn pill_list(b: &BannerStats) -> Vec<WishPill> {
    b.last_five
        .iter()
        .map(|f| WishPill {
            name: f.name.clone().into(),
            pity: f.pity.to_string().into(),
            color: pity_color(f.pity),
            featured: f.won,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn card(label: &str, value: String, sub: impl Into<String>, c: (u8, u8, u8)) -> WishStatCard {
    WishStatCard {
        label: label.into(),
        value: value.into(),
        sub: sub.into().into(),
        accent: rgb(c),
    }
}

/// svg polyline (line) + closed polygon (fill) across the full plot width.
fn series_paths(values: &[u32], max: f64, w: f64, h: f64) -> (String, String) {
    let n = values.len();
    if n == 0 || w <= 0.0 || h <= 0.0 {
        return (String::new(), String::new());
    }
    let max = if max <= 0.0 { 1.0 } else { max };
    let x_at = |i: usize| if n == 1 { 0.0 } else { i as f64 / (n - 1) as f64 * w };
    let y_at = |v: u32| h - (v as f64 / max).clamp(0.0, 1.0) * h;

    let mut line = String::with_capacity(n * 16);
    for (i, &v) in values.iter().enumerate() {
        let (x, y) = (x_at(i), y_at(v));
        if i == 0 {
            line.push_str(&format!("M {x:.2} {y:.2}"));
        } else {
            line.push_str(&format!(" L {x:.2} {y:.2}"));
        }
    }
    if n == 1 {
        // a single month: extend flat so the line/area is visible
        line.push_str(&format!(" L {w:.2} {:.2}", y_at(values[0])));
    }
    let fill = format!("{line} L {w:.2} {h:.2} L 0.00 {h:.2} Z");
    (line, fill)
}

/// round up to 1/2/5 × 10ⁿ for clean gridline labels
fn nice_max(raw: f64) -> f64 {
    if raw <= 0.0 || raw.is_nan() {
        return 1.0;
    }
    let pow = 10f64.powf(raw.log10().floor());
    let frac = raw / pow;
    let nice = if frac <= 1.0 {
        1.0
    } else if frac <= 2.0 {
        2.0
    } else if frac <= 5.0 {
        5.0
    } else {
        10.0
    };
    nice * pow
}

fn pct(num: u32, den: u32) -> String {
    if den == 0 {
        "—".into()
    } else {
        format!("{:.2}%", num as f64 / den as f64 * 100.0)
    }
}

fn avg(v: f32) -> String {
    if v <= 0.0 {
        "—".into()
    } else {
        format!("{v:.2}")
    }
}

fn pity_color(pity: u32) -> Color {
    let c = if pity <= 40 {
        (63, 185, 80) // green
    } else if pity <= 65 {
        (227, 179, 65) // yellow
    } else if pity <= 80 {
        (240, 136, 62) // orange
    } else {
        (248, 81, 73) // red
    };
    rgb(c)
}

fn commas(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn rgb((r, g, b): (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(r, g, b)
}

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    Rc::new(VecModel::from(v)).into()
}
