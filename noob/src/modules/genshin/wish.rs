//! miHoYo gacha-history export, shared by Genshin Impact (hk4e) and Honkai:
//! Star Rail (hkrpg).
//!
//! The network flow is identical for both games — locate the game install from
//! the player log, recover the signed gacha URL (`authkey`) from the game's
//! browser cache, then paginate the `getGachaLog` endpoint — so it lives here
//! once and is parameterized by [`GameProfile`]. Only the constants differ
//! (paths, hosts, API path, banner types, `game_biz`). Use [`GENSHIN`] or
//! [`STAR_RAIL`] to pick a game; both are modeled on Starward's
//! `GenshinGachaClient` / `StarRailGachaClient`.

use std::collections::HashMap;
use std::{env, fmt, fs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use super::genshin_store::Model as WishRecord;

const MAX_RETRY: usize = 5;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const PAGE_SIZE: u32 = 20;
/// UTC+8 (Asia), used when the server doesn't tell us the region's timezone.
const DEFAULT_TIMEZONE: i32 = 8;

// ---------------------------------------------------------------------------
// game profiles
// ---------------------------------------------------------------------------

/// Which game a record / fetch belongs to. The tag is the stable discriminator
/// stored in the `wish_record.game` column and used as the UIGF v4 block key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Game {
    Genshin,
    StarRail,
}

impl Game {
    pub fn tag(self) -> &'static str {
        match self {
            Game::Genshin => "hk4e",
            Game::StarRail => "hkrpg",
        }
    }
}

/// Everything that differs between the two games' gacha exporters. The shared
/// functions below take a `&GameProfile`; the two concrete profiles are the
/// [`GENSHIN`] and [`STAR_RAIL`] consts.
pub struct GameProfile {
    pub game: Game,
    /// `game_biz` stem matched in the cache URL and used to build the API host
    /// (`hk4e` / `hkrpg`).
    biz: &'static str,
    /// `*_Data` directory names that appear in the player log.
    data_dirs: &'static [&'static str],
    /// player-log locations under `%USERPROFILE%/AppData/LocalLow`.
    log_subpaths: &'static [&'static str],
    /// API host for the mainland-CN / oversea servers.
    api_cn: &'static str,
    api_os: &'static str,
    /// endpoint path under the host.
    api_path: &'static str,
    /// banner types queried, in fetch order.
    gacha_types: &'static [&'static str],
    /// banner types that must be queried through the `getLdGachaLog` endpoint
    /// (Star Rail collaboration warps); empty for Genshin.
    ld_gacha_types: &'static [&'static str],
    /// an always-present banner used only to probe the server timezone.
    probe_type: &'static str,
    /// display grouping, in order. Each entry maps a representative gacha_type
    /// to the raw types it collapses (Genshin merges the rerun `400` into `301`).
    display_groups: &'static [(&'static str, &'static [&'static str])],
}

/// Genshin Impact (hk4e). The character-event banner is queried as `301` only:
/// the API returns both `301` and its rerun sub-banner `400` in that one stream,
/// so `400` is not queried separately (matches Starward / the UIGF convention).
pub const GENSHIN: GameProfile = GameProfile {
    game: Game::Genshin,
    biz: "hk4e",
    data_dirs: &["GenshinImpact_Data", "YuanShen_Data"],
    log_subpaths: &["miHoYo/Genshin Impact/output_log.txt", "miHoYo/原神/output_log.txt"],
    api_cn: "https://public-operation-hk4e.mihoyo.com",
    api_os: "https://public-operation-hk4e-sg.hoyoverse.com",
    api_path: "/gacha_info/api/getGachaLog",
    gacha_types: &["100", "200", "301", "302", "500"],
    ld_gacha_types: &[],
    probe_type: "200",
    display_groups: &[
        ("100", &["100"]),
        ("200", &["200"]),
        ("301", &["301", "400"]),
        ("302", &["302"]),
        ("500", &["500"]),
    ],
};

/// Honkai: Star Rail (hkrpg). The collaboration warps (`21`/`22`) live behind a
/// separate `getLdGachaLog` endpoint; every other banner uses `getGachaLog`.
pub const STAR_RAIL: GameProfile = GameProfile {
    game: Game::StarRail,
    biz: "hkrpg",
    data_dirs: &["StarRail_Data"],
    log_subpaths: &["Cognosphere/Star Rail/Player.log", "miHoYo/崩坏：星穹铁道/Player.log"],
    api_cn: "https://public-operation-hkrpg.mihoyo.com",
    api_os: "https://public-operation-hkrpg-sg.hoyoverse.com",
    api_path: "/common/gacha_record/api/getGachaLog",
    gacha_types: &["1", "2", "11", "12", "21", "22"],
    ld_gacha_types: &["21", "22"],
    probe_type: "1",
    display_groups: &[
        ("1", &["1"]),
        ("2", &["2"]),
        ("11", &["11"]),
        ("12", &["12"]),
        ("21", &["21"]),
        ("22", &["22"]),
    ],
};

pub fn banner_name(game: Game, gacha_type: &str) -> &'static str {
    match game {
        Game::Genshin => match gacha_type {
            "100" => "Beginners' Wish",
            "200" => "Standard Wish",
            "301" | "400" => "Character Event Wish",
            "302" => "Weapon Event Wish",
            "500" => "Chronicled Wish",
            _ => "Unknown",
        },
        Game::StarRail => match gacha_type {
            "1" => "Stellar Warp",
            "2" => "Departure Warp",
            "11" => "Character Event Warp",
            "12" => "Light Cone Event Warp",
            "21" => "Collaboration Warp",
            "22" => "Collaboration Light Cone Warp",
            _ => "Unknown",
        },
    }
}

#[derive(Debug)]
pub enum FetchError {
    /// no signed gacha URL found (game not run / records not opened)
    NoUrl,
    /// retcode -101: authkey expired, user must reopen the in-game history
    AuthExpired,
    /// API returned a non-zero retcode
    Api(String),
    /// transport failure after retries
    Network(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::NoUrl => write!(f, "no gacha URL found — open the wish history in-game first"),
            FetchError::AuthExpired => write!(f, "authentication expired — reopen the in-game wish history"),
            FetchError::Api(m) => write!(f, "api error: {m}"),
            FetchError::Network(m) => write!(f, "network error: {m}"),
        }
    }
}

pub struct FetchResult {
    pub records: Vec<WishRecord>,
    pub uid: String,
    pub lang: String,
    pub timezone: i32,
}

// ---------------------------------------------------------------------------
// game + cache discovery
// ---------------------------------------------------------------------------

/// candidate game data directories (each ends in one of `profile.data_dirs`),
/// parsed from the player log. ⟵ `detect_game_locale`
pub fn detect_game_paths(profile: &GameProfile) -> Vec<PathBuf> {
    let Some(profile_dir) = env::var_os("USERPROFILE") else { return Vec::new() };
    let pattern =
        format!(r"\w:[\\/].*?[\\/](?:{})[\\/]", profile.data_dirs.join("|"));
    let re = Regex::new(&pattern).unwrap();
    let mut out: Vec<PathBuf> = Vec::new();
    for sub in profile.log_subpaths {
        let log = PathBuf::from(&profile_dir).join("AppData/LocalLow").join(sub);
        let Ok(content) = fs::read_to_string(&log) else { continue };
        for m in re.find_iter(&content) {
            let p = PathBuf::from(m.as_str());
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// newest `webCaches/*/Cache/Cache_Data/data_2` blob, scanned for the latest
/// signed gacha URL. ⟵ `get_url_from_cache_text`
pub fn url_from_cache(profile: &GameProfile, game_path: &Path) -> Option<String> {
    // pick the most recently written data_2 across each version dir under webCaches
    let latest = fs::read_dir(game_path.join("webCaches"))
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("Cache/Cache_Data/data_2"))
        .filter(|data| data.is_file())
        .max_by_key(|data| fs::metadata(data).and_then(|m| m.modified()).ok())?;

    // the cache file is often held open by the game; copy it out first
    // (CopyFileExW under the hood, like the Python win32api.CopyFile).
    let tmp = env::temp_dir().join(format!("noob_{}_cache_{}.bin", profile.biz, std::process::id()));
    fs::copy(&latest, &tmp).ok()?;
    let bytes = fs::read(&tmp).ok()?;
    let _ = fs::remove_file(&tmp);

    let text = String::from_utf8_lossy(&bytes);
    let pattern = format!(
        r"https.+?&auth_appid=webview_gacha&.+?authkey=.+?&game_biz={}_\w+",
        profile.biz,
    );
    let re = Regex::new(&pattern).unwrap();
    re.find_iter(&text).last().map(|m| m.as_str().to_string())
}

/// first usable signed URL across all detected game paths. ⟵ `get_url`
pub fn find_url(profile: &GameProfile) -> Option<String> {
    for path in detect_game_paths(profile) {
        if let Some(url) = url_from_cache(profile, &path) {
            return Some(url);
        }
    }
    None
}

/// Build the API endpoint (host + path) for the captured URL's server and strip
/// pagination params, preserving the original encoding of everything we keep
/// (notably `authkey`). Returns `(endpoint, query)`. ⟵ `remove_query_params`
pub fn clean_query(profile: &GameProfile, url: &str) -> Option<(String, String)> {
    let (base, query) = url.split_once('?')?;
    let host = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or("");
    // CN servers live on *.mihoyo.com, oversea on *.hoyoverse.com.
    let api_host = if host.contains("hoyoverse") { profile.api_os } else { profile.api_cn };
    let endpoint = format!("{api_host}{}", profile.api_path);

    const DROP: [&str; 4] = ["page", "size", "gacha_type", "end_id"];
    let kept: Vec<&str> = query
        .split('&')
        .filter(|kv| {
            let k = kv.split('=').next().unwrap_or("");
            !DROP.contains(&k)
        })
        .collect();
    Some((endpoint, kept.join("&")))
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ApiEnvelope {
    retcode: i32,
    #[serde(default)]
    message: String,
    data: Option<GachaData>,
}

#[derive(Deserialize)]
struct GachaData {
    #[serde(default)]
    list: Vec<ApiItem>,
    #[serde(default)]
    region: String,
    #[serde(default)]
    region_time_zone: Option<i32>,
}

#[derive(Deserialize)]
struct ApiItem {
    uid: String,
    gacha_type: String,
    /// Star Rail only; absent on Genshin.
    #[serde(default)]
    gacha_id: String,
    #[serde(default)]
    item_id: String,
    #[serde(default)]
    count: String,
    time: String,
    name: String,
    #[serde(default)]
    lang: String,
    item_type: String,
    rank_type: String,
    id: String,
}

impl ApiItem {
    fn into_record(self, game: Game) -> WishRecord {
        WishRecord {
            game: game.tag().to_string(),
            id: self.id,
            uid: self.uid,
            gacha_type: self.gacha_type,
            gacha_id: self.gacha_id,
            item_id: self.item_id,
            count: self.count,
            time: self.time,
            name: self.name,
            item_type: self.item_type,
            rank_type: self.rank_type,
            lang: self.lang,
        }
    }
}

fn tz_from_region(region: &str) -> i32 {
    // substring match covers both games' region strings (Genshin `os_usa` /
    // `os_euro`, Star Rail `prod_official_usa` / `prod_official_eur`, …).
    if region.contains("usa") {
        -5
    } else if region.contains("eu") {
        1
    } else {
        DEFAULT_TIMEZONE // asia / cht / cn
    }
}

async fn get_gacha_log(
    client: &reqwest::Client,
    profile: &GameProfile,
    endpoint: &str,
    gacha_type: &str,
    query: &str,
    page: u32,
    end_id: &str,
    progress: &(dyn Fn(String) + Send + Sync),
) -> Result<GachaData, FetchError> {
    // Star Rail's collaboration warps are served from a sibling endpoint.
    let endpoint = if profile.ld_gacha_types.contains(&gacha_type) {
        endpoint.replace("getGachaLog", "getLdGachaLog")
    } else {
        endpoint.to_string()
    };
    let url = format!(
        "{endpoint}?{query}\
         &gacha_type={gacha_type}&page={page}&size={PAGE_SIZE}&end_id={end_id}"
    );
    for attempt in 0..MAX_RETRY {
        // send → check HTTP status → parse body; any of these can be a transient
        // reqwest error, so they share one retry path below.
        let response = async {
            let resp = client.get(&url).send().await?.error_for_status()?;
            resp.json::<ApiEnvelope>().await
        }
        .await;

        match response {
            Ok(env) => {
                return match env.retcode {
                    0 => env.data.ok_or_else(|| FetchError::Api("empty data".into())),
                    -101 => Err(FetchError::AuthExpired),
                    _ => Err(FetchError::Api(env.message)),
                };
            }
            Err(e) => {
                progress(format!("retrying ({} left): {e}", MAX_RETRY - attempt - 1));
                sleep(RETRY_DELAY).await;
            }
        }
    }
    Err(FetchError::Network("max retries exceeded".into()))
}

/// page through one banner, newest→oldest, stopping at `last_id` (exclusive).
/// returns records newest→oldest; caller reverses for chronological order.
async fn fetch_one_type(
    client: &reqwest::Client,
    profile: &GameProfile,
    endpoint: &str,
    gacha_type: &str,
    query: &str,
    last_id: &str,
    progress: &(dyn Fn(String) + Send + Sync),
) -> Result<Vec<WishRecord>, FetchError> {
    let mut out: Vec<WishRecord> = Vec::new();
    let mut page = 1u32;
    let mut end_id = String::from("0");
    loop {
        if page.is_multiple_of(10) {
            sleep(Duration::from_secs(1)).await;
        }
        progress(format!("fetching {} page {page}", banner_name(profile.game, gacha_type)));
        let data =
            get_gacha_log(client, profile, endpoint, gacha_type, query, page, &end_id, progress).await?;
        sleep(Duration::from_millis(300)).await;

        if data.list.is_empty() {
            break;
        }
        end_id = data.list.last().unwrap().id.clone();
        for item in data.list {
            if item.id.as_str() > last_id {
                out.push(item.into_record(profile.game));
            } else {
                return Ok(out);
            }
        }
        page += 1;
    }
    Ok(out)
}

/// fetch every banner. `last_ids` maps gacha_type→highest stored id for
/// incremental pulls; pass an empty map for a full re-fetch.
pub async fn fetch_all(
    client: &reqwest::Client,
    profile: &GameProfile,
    endpoint: &str,
    query: &str,
    last_ids: &HashMap<String, String>,
    progress: &(dyn Fn(String) + Send + Sync),
) -> Result<FetchResult, FetchError> {
    let mut records: Vec<WishRecord> = Vec::new();
    let mut uid = String::new();
    let mut lang = String::new();

    for &gtype in profile.gacha_types {
        let last_id = last_ids.get(gtype).map(String::as_str).unwrap_or("0");
        let mut fetched =
            fetch_one_type(client, profile, endpoint, gtype, query, last_id, progress).await?;
        // uid/lang are the same on every pull; take them from the first row we see
        if let Some(first) = fetched.first() {
            if uid.is_empty() {
                uid = first.uid.clone();
            }
            if lang.is_empty() {
                lang = first.lang.clone();
            }
        }
        // the API returns newest→oldest; store chronologically
        fetched.reverse();
        records.append(&mut fetched);
    }

    // only worth a probe call once we know there's history to stamp
    let timezone = if records.is_empty() {
        DEFAULT_TIMEZONE
    } else {
        probe_timezone(client, profile, endpoint, query, progress).await
    };

    Ok(FetchResult { records, uid, lang, timezone })
}

/// Individual pulls carry no timezone, so derive it from one extra request:
/// prefer the explicit `region_time_zone`, else infer it from the region.
async fn probe_timezone(
    client: &reqwest::Client,
    profile: &GameProfile,
    endpoint: &str,
    query: &str,
    progress: &(dyn Fn(String) + Send + Sync),
) -> i32 {
    match get_gacha_log(client, profile, endpoint, profile.probe_type, query, 1, "0", progress).await {
        Ok(data) => data.region_time_zone.unwrap_or_else(|| tz_from_region(&data.region)),
        Err(_) => DEFAULT_TIMEZONE,
    }
}

// ---------------------------------------------------------------------------
// stats  ⟵ data_to_html / warp_analyze
// ---------------------------------------------------------------------------

/// primogems / stellar jade spent per pull (both games cost 160).
pub const PULL_COST: u32 = 160;

/// premium-currency name, for overview labels.
pub fn currency_name(game: Game) -> &'static str {
    match game {
        Game::Genshin => "Primogems",
        Game::StarRail => "Stellar Jade",
    }
}

/// `(five_star_cap, four_star_cap)` hard-pity thresholds for a banner. Weapon /
/// light-cone banners reach the 5★ guarantee at 80; everything else at 90.
pub fn pity_caps(game: Game, gacha_type: &str) -> (u32, u32) {
    match game {
        Game::Genshin => match gacha_type {
            "302" => (80, 10), // weapon
            _ => (90, 10),
        },
        Game::StarRail => match gacha_type {
            "12" | "22" => (80, 10), // light cone / collab light cone
            _ => (90, 10),
        },
    }
}

// permanent ("standard pool") units, used to tell a 50:50 win (featured) from a
// loss (off-banner). English names only — matches the export `lang` we read.
const GI_STD5: &[&str] = &["Diluc", "Jean", "Keqing", "Mona", "Qiqi", "Tighnari", "Dehya"];
const HSR_STD5: &[&str] =
    &["Bailu", "Bronya", "Clara", "Gepard", "Himeko", "Welt", "Yanqing"];
const GI_STD4: &[&str] = &[
    "Amber", "Barbara", "Beidou", "Bennett", "Chongyun", "Diona", "Fischl", "Kaeya", "Lisa",
    "Ningguang", "Noelle", "Razor", "Rosaria", "Sayu", "Sucrose", "Xiangling", "Xingqiu",
    "Xinyan", "Yanfei",
];
const HSR_STD4: &[&str] = &[
    "Arlan", "Asta", "Dan Heng", "Herta", "March 7th", "Natasha", "Pela", "Qingque", "Sampo",
    "Serval", "Sushang", "Hook", "Yukong", "Tingyun",
];

fn is_standard_5star(game: Game, name: &str) -> bool {
    match game {
        Game::Genshin => GI_STD5.contains(&name),
        Game::StarRail => HSR_STD5.contains(&name),
    }
}

fn is_standard_4star(game: Game, name: &str) -> bool {
    match game {
        Game::Genshin => GI_STD4.contains(&name),
        Game::StarRail => HSR_STD4.contains(&name),
    }
}

/// 4★/5★ item_type discriminator. Weapons / light cones are never featured
/// character rate-ups, so they're treated as the non-character class.
fn is_character(item_type: &str) -> bool {
    !matches!(item_type, "Weapon" | "Light Cone")
}

/// Walk a chronological sequence of 50:50 outcomes (`true` = featured win) and
/// return `(wins, attempts)`. The pull right after a loss is a guarantee and is
/// excluded from both counts, matching how trackers report 50:50 win rate.
fn fifty_fifty(outcomes: impl Iterator<Item = bool>) -> (u32, u32) {
    let mut guaranteed = false;
    let mut wins = 0;
    let mut attempts = 0;
    for won in outcomes {
        if guaranteed {
            guaranteed = false; // the guaranteed pull doesn't count as a coin flip
        } else {
            attempts += 1;
            if won {
                wins += 1;
            } else {
                guaranteed = true;
            }
        }
    }
    (wins, attempts)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FiveStar {
    pub name: String,
    pub pity: u32,
    /// won the 50:50 (a featured unit, not from the standard pool)
    pub won: bool,
}

/// one month's pull counts, used for the time-series graph. Months are
/// contiguous across the banner's lifetime (gaps appear as zero).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MonthBucket {
    pub label: String, // "YYYY-MM"
    pub three: u32,
    pub four: u32,
    pub five: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BannerStats {
    pub gacha_type: String,
    pub name: String,
    pub total: u32,
    /// pulls since the last 5★ (current pity)
    pub pity: u32,
    /// pulls since the last 4★ or 5★ (current 4★ pity)
    pub four_pity: u32,
    pub five_star: u32,
    pub four_star: u32,
    pub three_star: u32,
    /// average pulls between 5★ / 4★
    pub avg_pity: f32,
    pub four_avg_pity: f32,
    /// 4★ split by item class
    pub four_char: u32,
    pub four_weapon: u32,
    /// 50:50 results (wins out of non-guaranteed attempts)
    pub five_win: u32,
    pub five_attempts: u32,
    pub four_win: u32,
    pub four_attempts: u32,
    /// hard-pity caps for this banner
    pub five_cap: u32,
    pub four_cap: u32,
    pub last_five: Vec<FiveStar>,
    pub months: Vec<MonthBucket>,
    pub start_time: String,
    pub end_time: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WishStats {
    pub banners: Vec<BannerStats>,
}

pub fn compute_stats(profile: &GameProfile, records: &[WishRecord]) -> WishStats {
    let mut banners = Vec::new();
    for (key, types) in profile.display_groups {
        let mut group: Vec<&WishRecord> =
            records.iter().filter(|r| types.contains(&r.gacha_type.as_str())).collect();
        if group.is_empty() {
            continue;
        }
        group.sort_by(|a, b| a.id.cmp(&b.id)); // chronological

        let (five_cap, four_cap) = pity_caps(profile.game, key);
        let mut stats = BannerStats {
            gacha_type: (*key).to_string(),
            name: banner_name(profile.game, key).to_string(),
            total: group.len() as u32,
            five_cap,
            four_cap,
            start_time: group.first().map(|r| r.time.clone()).unwrap_or_default(),
            end_time: group.last().map(|r| r.time.clone()).unwrap_or_default(),
            ..Default::default()
        };

        let mut since_five = 0u32;
        let mut since_four = 0u32;
        let mut five_sum = 0u32;
        let mut four_sum = 0u32;
        let mut five_outcomes: Vec<bool> = Vec::new();
        let mut four_outcomes: Vec<bool> = Vec::new();
        for r in &group {
            since_five += 1;
            since_four += 1;
            match r.rank_type.as_str() {
                "5" => {
                    stats.five_star += 1;
                    let won = !is_standard_5star(profile.game, &r.name);
                    five_outcomes.push(won);
                    stats.last_five.push(FiveStar { name: r.name.clone(), pity: since_five, won });
                    five_sum += since_five;
                    since_five = 0;
                    since_four = 0; // a 5★ also resets the 4★ counter
                }
                "4" => {
                    stats.four_star += 1;
                    let is_char = is_character(&r.item_type);
                    if is_char {
                        stats.four_char += 1;
                    } else {
                        stats.four_weapon += 1;
                    }
                    four_outcomes.push(is_char && !is_standard_4star(profile.game, &r.name));
                    four_sum += since_four;
                    since_four = 0;
                }
                _ => stats.three_star += 1,
            }
        }
        stats.pity = since_five; // remaining pulls after the last 5★
        stats.four_pity = since_four;
        if stats.five_star > 0 {
            stats.avg_pity = five_sum as f32 / stats.five_star as f32;
        }
        if stats.four_star > 0 {
            stats.four_avg_pity = four_sum as f32 / stats.four_star as f32;
        }
        (stats.five_win, stats.five_attempts) = fifty_fifty(five_outcomes.into_iter());
        (stats.four_win, stats.four_attempts) = fifty_fifty(four_outcomes.into_iter());
        stats.months = month_buckets(&group);
        banners.push(stats);
    }
    WishStats { banners }
}

/// Bucket a chronological banner group into contiguous calendar months.
fn month_buckets(group: &[&WishRecord]) -> Vec<MonthBucket> {
    let parse = |t: &str| -> Option<(i32, u32)> {
        let y = t.get(0..4)?.parse().ok()?;
        let m = t.get(5..7)?.parse().ok()?;
        Some((y, m))
    };
    let mut first = None;
    let mut last = None;
    for r in group {
        if let Some(ym) = parse(&r.time) {
            first.get_or_insert(ym);
            last = Some(ym);
        }
    }
    let (Some((fy, fm)), Some((ly, lm))) = (first, last) else { return Vec::new() };

    let mut buckets: Vec<MonthBucket> = Vec::new();
    let mut index: HashMap<(i32, u32), usize> = HashMap::new();
    let (mut y, mut m) = (fy, fm);
    loop {
        index.insert((y, m), buckets.len());
        buckets.push(MonthBucket { label: format!("{y:04}-{m:02}"), ..Default::default() });
        if (y, m) == (ly, lm) || buckets.len() > 1200 {
            break;
        }
        m += 1;
        if m > 12 {
            m = 1;
            y += 1;
        }
    }
    for r in group {
        if let Some(i) = parse(&r.time).and_then(|ym| index.get(&ym)).copied() {
            match r.rank_type.as_str() {
                "5" => buckets[i].five += 1,
                "4" => buckets[i].four += 1,
                _ => buckets[i].three += 1,
            }
        }
    }
    buckets
}

// ---------------------------------------------------------------------------
// UIGF v4 export  ⟵ srgf/uigf helpers
// ---------------------------------------------------------------------------

/// serialize records as a UIGF v4.0 document under the game's block (`hk4e` /
/// `hkrpg`). Genshin rerun `400` pulls are remapped to `uigf_gacha_type=301`;
/// Star Rail records carry their `gacha_id` instead.
pub fn to_uigf_v4(
    profile: &GameProfile,
    records: &[WishRecord],
    uid: &str,
    lang: &str,
    timezone: i32,
) -> serde_json::Value {
    let list: Vec<serde_json::Value> = records
        .iter()
        .map(|r| match profile.game {
            Game::Genshin => {
                // uigf_gacha_type collapses the second character banner (400→301)
                let uigf_type = if r.gacha_type == "400" { "301" } else { r.gacha_type.as_str() };
                serde_json::json!({
                    "uigf_gacha_type": uigf_type,
                    "gacha_type": r.gacha_type,
                    "item_id": r.item_id,
                    "count": r.count,
                    "time": r.time,
                    "name": r.name,
                    "item_type": r.item_type,
                    "rank_type": r.rank_type,
                    "id": r.id,
                })
            }
            Game::StarRail => serde_json::json!({
                "gacha_id": r.gacha_id,
                "gacha_type": r.gacha_type,
                "item_id": r.item_id,
                "count": r.count,
                "time": r.time,
                "name": r.name,
                "item_type": r.item_type,
                "rank_type": r.rank_type,
                "id": r.id,
            }),
        })
        .collect();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let block = serde_json::json!([{
        "uid": uid,
        "timezone": timezone,
        "lang": lang,
        "list": list,
    }]);

    let mut doc = serde_json::Map::new();
    doc.insert(
        "info".into(),
        serde_json::json!({
            "export_timestamp": ts,
            "export_app": "noob",
            "export_app_version": env!("CARGO_PKG_VERSION"),
            "version": "v4.0",
        }),
    );
    doc.insert(profile.game.tag().to_string(), block);
    serde_json::Value::Object(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(game: Game, id: &str, gacha_type: &str, rank: &str, name: &str) -> WishRecord {
        WishRecord {
            game: game.tag().into(),
            id: id.into(),
            uid: "1".into(),
            gacha_type: gacha_type.into(),
            gacha_id: String::new(),
            item_id: String::new(),
            count: "1".into(),
            time: format!("2024-01-01 00:00:{id:0>2}"),
            name: name.into(),
            item_type: "Character".into(),
            rank_type: rank.into(),
            lang: "en".into(),
        }
    }

    #[test]
    fn clean_query_strips_pagination_and_picks_oversea_endpoint() {
        let url = "https://hk4e-api-os.hoyoverse.com/gacha?authkey=ABC&page=3&size=20\
                   &gacha_type=301&end_id=999&lang=en&game_biz=hk4e_global";
        let (endpoint, query) = clean_query(&GENSHIN, url).unwrap();
        assert_eq!(
            endpoint,
            "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog"
        );
        assert!(query.contains("authkey=ABC"));
        assert!(query.contains("lang=en"));
        assert!(!query.contains("page="));
        assert!(!query.contains("size="));
        assert!(!query.contains("gacha_type="));
        assert!(!query.contains("end_id="));
    }

    #[test]
    fn clean_query_picks_cn_endpoint_for_mihoyo_host() {
        let url = "https://webstatic.mihoyo.com/gacha?authkey=Z&game_biz=hk4e_cn";
        let (endpoint, _) = clean_query(&GENSHIN, url).unwrap();
        assert_eq!(endpoint, "https://public-operation-hk4e.mihoyo.com/gacha_info/api/getGachaLog");
    }

    #[test]
    fn clean_query_uses_star_rail_endpoint() {
        let os = "https://gs.hoyoverse.com/gacha?authkey=A&game_biz=hkrpg_global";
        let (endpoint, _) = clean_query(&STAR_RAIL, os).unwrap();
        assert_eq!(
            endpoint,
            "https://public-operation-hkrpg-sg.hoyoverse.com/common/gacha_record/api/getGachaLog"
        );
        let cn = "https://webstatic.mihoyo.com/gacha?authkey=A&game_biz=hkrpg_cn";
        let (endpoint, _) = clean_query(&STAR_RAIL, cn).unwrap();
        assert_eq!(
            endpoint,
            "https://public-operation-hkrpg.mihoyo.com/common/gacha_record/api/getGachaLog"
        );
    }

    #[test]
    fn stats_count_pity_and_merge_301_400() {
        // chronological by id: 3★,4★,5★(pity3),3★,3★ on 301; one 5★ on 400 → merged
        let records = vec![
            rec(Game::Genshin, "01", "301", "3", "a"),
            rec(Game::Genshin, "02", "301", "4", "b"),
            rec(Game::Genshin, "03", "301", "5", "Diluc"),
            rec(Game::Genshin, "04", "400", "3", "c"),
            rec(Game::Genshin, "05", "400", "5", "Klee"),
            rec(Game::Genshin, "06", "301", "3", "d"),
        ];
        let stats = compute_stats(&GENSHIN, &records);
        assert_eq!(stats.banners.len(), 1, "301 and 400 collapse into one banner");
        let b = &stats.banners[0];
        assert_eq!(b.gacha_type, "301");
        assert_eq!(b.total, 6);
        assert_eq!(b.five_star, 2);
        assert_eq!(b.last_five.len(), 2);
        assert_eq!(b.last_five[0].pity, 3); // 3 pulls to first 5★
        assert_eq!(b.last_five[1].pity, 2); // 2 more pulls to second 5★
        assert_eq!(b.pity, 1); // one 3★ after the last 5★
        assert!((b.avg_pity - 2.5).abs() < 1e-6);
    }

    #[test]
    fn star_rail_banners_are_not_merged() {
        let records = vec![
            rec(Game::StarRail, "01", "11", "5", "Seele"),
            rec(Game::StarRail, "02", "12", "5", "Cone"),
            rec(Game::StarRail, "03", "21", "5", "Collab"),
        ];
        let stats = compute_stats(&STAR_RAIL, &records);
        assert_eq!(stats.banners.len(), 3, "each warp type is its own banner");
        assert_eq!(stats.banners[0].name, "Character Event Warp");
        assert_eq!(stats.banners[2].name, "Collaboration Warp");
    }

    #[test]
    fn uigf_maps_400_to_301() {
        let records = vec![rec(Game::Genshin, "05", "400", "5", "Klee")];
        let doc = to_uigf_v4(&GENSHIN, &records, "1", "en", 8);
        assert_eq!(doc["hk4e"][0]["list"][0]["uigf_gacha_type"], "301");
        assert_eq!(doc["hk4e"][0]["list"][0]["gacha_type"], "400");
    }

    #[test]
    fn uigf_star_rail_block_carries_gacha_id() {
        let mut r = rec(Game::StarRail, "07", "11", "5", "Seele");
        r.gacha_id = "2003".into();
        let doc = to_uigf_v4(&STAR_RAIL, &[r], "1", "en", 8);
        assert_eq!(doc["hkrpg"][0]["list"][0]["gacha_id"], "2003");
        assert_eq!(doc["hkrpg"][0]["list"][0]["gacha_type"], "11");
        // no Genshin-only remap field on Star Rail rows
        assert!(doc["hkrpg"][0]["list"][0].get("uigf_gacha_type").is_none());
    }
}
