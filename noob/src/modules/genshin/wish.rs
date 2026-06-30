use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use super::genshin_store::Model as WishRecord;

/// banner types queried, in fetch order. `301` and `400` are both the rotating
/// character banner and are merged for display (Genshin convention).
pub const GACHA_TYPES: &[&str] = &["100", "200", "301", "302", "400", "500"];

const MAX_RETRY: usize = 5;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const PAGE_SIZE: u32 = 20;
/// UTC+8 (Asia), used when the server doesn't tell us the region's timezone.
const DEFAULT_TIMEZONE: i32 = 8;

/// `output_log.txt` locations under `%USERPROFILE%/AppData/LocalLow`.
const LOG_SUBPATHS: &[&str] =
    &["miHoYo/Genshin Impact/output_log.txt", "miHoYo/原神/output_log.txt"];

pub fn banner_name(gacha_type: &str) -> &'static str {
    match gacha_type {
        "100" => "Beginners' Wish",
        "200" => "Standard Wish",
        "301" | "400" => "Character Event Wish",
        "302" => "Weapon Event Wish",
        "500" => "Chronicled Wish",
        _ => "Unknown",
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

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// candidate game data directories (each ends in `GenshinImpact_Data` /
/// `YuanShen_Data`), parsed from the player log. ⟵ `detect_game_locale`
pub fn detect_game_paths() -> Vec<PathBuf> {
    let Some(profile) = std::env::var_os("USERPROFILE") else { return Vec::new() };
    let re = Regex::new(r"\w:[\\/].*?[\\/](?:GenshinImpact_Data|YuanShen_Data)[\\/]").unwrap();
    let mut out: Vec<PathBuf> = Vec::new();
    for sub in LOG_SUBPATHS {
        let log = PathBuf::from(&profile).join("AppData/LocalLow").join(sub);
        let Ok(content) = std::fs::read_to_string(&log) else { continue };
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
pub fn url_from_cache(game_path: &Path) -> Option<String> {
    // pick the most recently written data_2 across each version dir under webCaches
    let latest = std::fs::read_dir(game_path.join("webCaches"))
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("Cache/Cache_Data/data_2"))
        .filter(|data| data.is_file())
        .max_by_key(|data| std::fs::metadata(data).and_then(|m| m.modified()).ok())?;

    // the cache file is often held open by the game; copy it out first
    // (CopyFileExW under the hood, like the Python win32api.CopyFile).
    let tmp = std::env::temp_dir().join(format!("noob_genshin_cache_{}.bin", std::process::id()));
    std::fs::copy(&latest, &tmp).ok()?;
    let bytes = std::fs::read(&tmp).ok()?;
    let _ = std::fs::remove_file(&tmp);

    let text = String::from_utf8_lossy(&bytes);
    let re = Regex::new(
        r"https.+?&auth_appid=webview_gacha&.+?authkey=.+?&game_biz=hk4e_\w+",
    )
    .unwrap();
    re.find_iter(&text).last().map(|m| m.as_str().to_string())
}

/// first usable signed URL across all detected game paths. ⟵ `get_url`
pub fn find_url() -> Option<String> {
    for path in detect_game_paths() {
        if let Some(url) = url_from_cache(&path) {
            return Some(url);
        }
    }
    None
}

/// pick the hk4e API host and strip pagination params, preserving the original
/// encoding of everything we keep (notably `authkey`). ⟵ `remove_query_params`
pub fn clean_query(url: &str) -> Option<(String, String)> {
    let (base, query) = url.split_once('?')?;
    let host = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or("");
    let oversea = ["webstatic-sea", "hk4e-api-os", "api-os-takumi", "hoyoverse.com"]
        .iter()
        .any(|m| host.contains(m));
    let api_domain = if oversea {
        "https://public-operation-hk4e-sg.hoyoverse.com"
    } else {
        "https://public-operation-hk4e.mihoyo.com"
    };

    const DROP: [&str; 4] = ["page", "size", "gacha_type", "end_id"];
    let kept: Vec<&str> = query
        .split('&')
        .filter(|kv| {
            let k = kv.split('=').next().unwrap_or("");
            !DROP.contains(&k)
        })
        .collect();
    Some((api_domain.to_string(), kept.join("&")))
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
    fn into_record(self) -> WishRecord {
        WishRecord {
            id: self.id,
            uid: self.uid,
            gacha_type: self.gacha_type,
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
    match region {
        "os_usa" => -5,
        "os_euro" => 1,
        _ => DEFAULT_TIMEZONE, // os_asia / os_cht / cn
    }
}

async fn get_gacha_log(
    client: &reqwest::Client,
    api_domain: &str,
    gacha_type: &str,
    query: &str,
    page: u32,
    end_id: &str,
    progress: &(dyn Fn(String) + Send + Sync),
) -> Result<GachaData, FetchError> {
    let url = format!(
        "{api_domain}/gacha_info/api/getGachaLog?{query}\
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
    api_domain: &str,
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
        progress(format!("fetching {} page {page}", banner_name(gacha_type)));
        let data = get_gacha_log(client, api_domain, gacha_type, query, page, &end_id, progress).await?;
        sleep(Duration::from_millis(300)).await;

        if data.list.is_empty() {
            break;
        }
        end_id = data.list.last().unwrap().id.clone();
        for item in data.list {
            if item.id.as_str() > last_id {
                out.push(item.into_record());
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
    api_domain: &str,
    query: &str,
    last_ids: &HashMap<String, String>,
    progress: &(dyn Fn(String) + Send + Sync),
) -> Result<FetchResult, FetchError> {
    let mut records: Vec<WishRecord> = Vec::new();
    let mut uid = String::new();
    let mut lang = String::new();

    for &gtype in GACHA_TYPES {
        let last_id = last_ids.get(gtype).map(String::as_str).unwrap_or("0");
        let mut fetched = fetch_one_type(client, api_domain, gtype, query, last_id, progress).await?;
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
        probe_timezone(client, api_domain, query, progress).await
    };

    Ok(FetchResult { records, uid, lang, timezone })
}

/// Individual pulls carry no timezone, so derive it from one extra request:
/// prefer the explicit `region_time_zone`, else infer it from the region.
async fn probe_timezone(
    client: &reqwest::Client,
    api_domain: &str,
    query: &str,
    progress: &(dyn Fn(String) + Send + Sync),
) -> i32 {
    match get_gacha_log(client, api_domain, "200", query, 1, "0", progress).await {
        Ok(data) => data.region_time_zone.unwrap_or_else(|| tz_from_region(&data.region)),
        Err(_) => DEFAULT_TIMEZONE,
    }
}

// ---------------------------------------------------------------------------
// stats  ⟵ data_to_html / warp_analyze
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FiveStar {
    pub name: String,
    pub pity: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BannerStats {
    pub gacha_type: String,
    pub name: String,
    pub total: u32,
    /// pulls since the last 5★ (current pity)
    pub pity: u32,
    pub five_star: u32,
    pub four_star: u32,
    pub three_star: u32,
    pub avg_pity: f32,
    pub last_five: Vec<FiveStar>,
    pub start_time: String,
    pub end_time: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WishStats {
    pub banners: Vec<BannerStats>,
}

/// display groups, in order. 301 and 400 collapse into one character banner.
const DISPLAY_GROUPS: &[(&str, &[&str])] = &[
    ("100", &["100"]),
    ("200", &["200"]),
    ("301", &["301", "400"]),
    ("302", &["302"]),
    ("500", &["500"]),
];

pub fn compute_stats(records: &[WishRecord]) -> WishStats {
    let mut banners = Vec::new();
    for (key, types) in DISPLAY_GROUPS {
        let mut group: Vec<&WishRecord> =
            records.iter().filter(|r| types.contains(&r.gacha_type.as_str())).collect();
        if group.is_empty() {
            continue;
        }
        group.sort_by(|a, b| a.id.cmp(&b.id)); // chronological

        let mut stats = BannerStats {
            gacha_type: (*key).to_string(),
            name: banner_name(key).to_string(),
            total: group.len() as u32,
            start_time: group.first().map(|r| r.time.clone()).unwrap_or_default(),
            end_time: group.last().map(|r| r.time.clone()).unwrap_or_default(),
            ..Default::default()
        };

        let mut since_five = 0u32;
        for r in &group {
            since_five += 1;
            match r.rank_type.as_str() {
                "5" => {
                    stats.five_star += 1;
                    stats.last_five.push(FiveStar { name: r.name.clone(), pity: since_five });
                    since_five = 0;
                }
                "4" => stats.four_star += 1,
                _ => stats.three_star += 1,
            }
        }
        stats.pity = since_five; // remaining pulls after the last 5★
        if !stats.last_five.is_empty() {
            let sum: u32 = stats.last_five.iter().map(|f| f.pity).sum();
            stats.avg_pity = sum as f32 / stats.last_five.len() as f32;
        }
        banners.push(stats);
    }
    WishStats { banners }
}

// ---------------------------------------------------------------------------
// UIGF v4 export  ⟵ srgf/uigf helpers
// ---------------------------------------------------------------------------

/// serialize records as a UIGF v4.0 `hk4e` document.
pub fn to_uigf_v4(records: &[WishRecord], uid: &str, lang: &str, timezone: i32) -> serde_json::Value {
    let list: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
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
        })
        .collect();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    serde_json::json!({
        "info": {
            "export_timestamp": ts,
            "export_app": "noob",
            "export_app_version": env!("CARGO_PKG_VERSION"),
            "version": "v4.0",
        },
        "hk4e": [{
            "uid": uid,
            "timezone": timezone,
            "lang": lang,
            "list": list,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, gacha_type: &str, rank: &str, name: &str) -> WishRecord {
        WishRecord {
            id: id.into(),
            uid: "1".into(),
            gacha_type: gacha_type.into(),
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
    fn clean_query_strips_pagination_and_picks_oversea_domain() {
        let url = "https://hk4e-api-os.hoyoverse.com/gacha?authkey=ABC&page=3&size=20\
                   &gacha_type=301&end_id=999&lang=en&game_biz=hk4e_global";
        let (domain, query) = clean_query(url).unwrap();
        assert_eq!(domain, "https://public-operation-hk4e-sg.hoyoverse.com");
        assert!(query.contains("authkey=ABC"));
        assert!(query.contains("lang=en"));
        assert!(!query.contains("page="));
        assert!(!query.contains("size="));
        assert!(!query.contains("gacha_type="));
        assert!(!query.contains("end_id="));
    }

    #[test]
    fn clean_query_picks_cn_domain_for_mihoyo_host() {
        let url = "https://webstatic.mihoyo.com/gacha?authkey=Z&game_biz=hk4e_cn";
        let (domain, _) = clean_query(url).unwrap();
        assert_eq!(domain, "https://public-operation-hk4e.mihoyo.com");
    }

    #[test]
    fn stats_count_pity_and_merge_301_400() {
        // chronological by id: 3★,4★,5★(pity3),3★,3★ on 301; one 5★ on 400 → merged
        let records = vec![
            rec("01", "301", "3", "a"),
            rec("02", "301", "4", "b"),
            rec("03", "301", "5", "Diluc"),
            rec("04", "400", "3", "c"),
            rec("05", "400", "5", "Klee"),
            rec("06", "301", "3", "d"),
        ];
        let stats = compute_stats(&records);
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
    fn uigf_maps_400_to_301() {
        let records = vec![rec("05", "400", "5", "Klee")];
        let doc = to_uigf_v4(&records, "1", "en", 8);
        assert_eq!(doc["hk4e"][0]["list"][0]["uigf_gacha_type"], "301");
        assert_eq!(doc["hk4e"][0]["list"][0]["gacha_type"], "400");
    }
}
