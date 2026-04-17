//! Plan tier checking for CLI users.
//!
//! Fetches the user's plan from the ScanRook API and caches it locally
//! at `~/.scanrook/plan.json` with a 1-hour TTL. Used to gate enrichment
//! sources and output formats based on the user's subscription tier.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::usercli::{load_config, ScanRookConfig};

const PLAN_CACHE_TTL_SECS: u64 = 3600; // 1 hour

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEnrichment {
    #[serde(default = "default_true")]
    pub osv: bool,
    #[serde(default)]
    pub nvd: bool,
    #[serde(default)]
    pub oval: bool,
    #[serde(default)]
    pub epss: bool,
    #[serde(default)]
    pub kev: bool,
    #[serde(default)]
    pub distro_trackers: bool,
}

fn default_true() -> bool {
    true
}

impl Default for PlanEnrichment {
    fn default() -> Self {
        Self {
            osv: true,
            nvd: false,
            oval: false,
            epss: false,
            kev: false,
            distro_trackers: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanInfo {
    #[serde(default = "default_free")]
    pub tier: String,
    #[serde(default)]
    pub enrichment: PlanEnrichment,
    #[serde(default = "default_text_formats")]
    pub output_formats: Vec<String>,
    #[serde(default = "default_free")]
    pub db_tier: String,
}

fn default_free() -> String {
    "free".to_string()
}

fn default_text_formats() -> Vec<String> {
    vec!["text".to_string()]
}

impl Default for PlanInfo {
    fn default() -> Self {
        Self {
            tier: "free".to_string(),
            enrichment: PlanEnrichment::default(),
            output_formats: vec!["text".to_string()],
            db_tier: "free".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPlan {
    plan: PlanInfo,
    fetched_at: u64,
}

fn plan_cache_path() -> PathBuf {
    if let Ok(path) = std::env::var("SCANROOK_CONFIG") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if let Some(parent) = p.parent() {
                return parent.join("plan.json");
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".scanrook").join("plan.json")
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Load cached plan if it exists and is within TTL.
fn load_cached_plan() -> Option<PlanInfo> {
    let path = plan_cache_path();
    let raw = fs::read_to_string(&path).ok()?;
    let cached: CachedPlan = serde_json::from_str(&raw).ok()?;
    let age = now_epoch_secs().saturating_sub(cached.fetched_at);
    if age <= PLAN_CACHE_TTL_SECS {
        Some(cached.plan)
    } else {
        None
    }
}

/// Save plan to cache file.
fn save_cached_plan(plan: &PlanInfo) {
    let cached = CachedPlan {
        plan: plan.clone(),
        fetched_at: now_epoch_secs(),
    };
    let path = plan_cache_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&cached) {
        let _ = fs::write(&path, json);
    }
}

/// Fetch plan from the ScanRook API using stored credentials.
fn fetch_plan_from_api(cfg: &ScanRookConfig) -> Option<PlanInfo> {
    let api_key = cfg.api_key.as_ref().filter(|k| !k.trim().is_empty())?;
    let base = resolve_api_base(cfg);

    let url = format!("{}/api/cli/plan", base);
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("scanrook-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {}", api_key))
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    resp.json::<PlanInfo>().ok()
}

fn resolve_api_base(cfg: &ScanRookConfig) -> String {
    if let Ok(v) = std::env::var("SCANROOK_API_BASE") {
        let s = v.trim().trim_end_matches('/').to_string();
        if !s.is_empty() {
            return s;
        }
    }
    if let Some(v) = &cfg.api_base {
        let s = v.trim().trim_end_matches('/').to_string();
        if !s.is_empty() {
            return s;
        }
    }
    "https://scanrook.io".to_string()
}

/// Get the current plan, using cache with 1-hour TTL.
/// Falls back to free tier if no API key or fetch fails.
pub fn get_plan() -> PlanInfo {
    // Check cache first
    if let Some(cached) = load_cached_plan() {
        return cached;
    }

    let cfg = load_config();

    // No API key → free tier
    if cfg.api_key.as_ref().filter(|k| !k.trim().is_empty()).is_none() {
        return PlanInfo::default();
    }

    // Fetch from API
    match fetch_plan_from_api(&cfg) {
        Some(plan) => {
            save_cached_plan(&plan);
            plan
        }
        None => PlanInfo::default(),
    }
}

/// Refresh the plan cache (called after login).
pub fn refresh_plan_cache() {
    let cfg = load_config();
    if let Some(plan) = fetch_plan_from_api(&cfg) {
        save_cached_plan(&plan);
    }
}

/// Apply plan enrichment gates by setting environment variables.
/// This should be called early in main() before any scan starts.
pub fn apply_plan_enrichment_gates(plan: &PlanInfo) {
    if !plan.enrichment.nvd {
        std::env::set_var("SCANNER_NVD_ENRICH", "0");
    }
    if !plan.enrichment.epss {
        std::env::set_var("SCANNER_EPSS_ENRICH", "0");
    }
    if !plan.enrichment.kev {
        std::env::set_var("SCANNER_KEV_ENRICH", "0");
    }
    if !plan.enrichment.oval {
        std::env::set_var("SCANNER_OVAL_ENRICH", "0");
    }
    if !plan.enrichment.distro_trackers {
        std::env::set_var("SCANNER_DISTRO_FEED_ENRICH", "0");
    }

    // Log which sources are gated
    let gated: Vec<&str> = [
        (!plan.enrichment.nvd, "NVD"),
        (!plan.enrichment.epss, "EPSS"),
        (!plan.enrichment.kev, "KEV"),
        (!plan.enrichment.oval, "OVAL"),
        (!plan.enrichment.distro_trackers, "distro_trackers"),
    ]
    .iter()
    .filter(|(disabled, _)| *disabled)
    .map(|(_, name)| *name)
    .collect();

    if !gated.is_empty() {
        crate::utils::progress(
            "plan.enrichment.gated",
            &format!(
                "tier={} gated=[{}] upgrade at https://scanrook.io/pricing",
                plan.tier,
                gated.join(", ")
            ),
        );
    }
}

/// Check if an output format is allowed by the plan.
/// Returns an error message if not allowed.
pub fn check_output_format(plan: &PlanInfo, format: &str) -> Result<(), String> {
    let allowed = &plan.output_formats;
    if allowed.iter().any(|f| f.eq_ignore_ascii_case(format)) {
        return Ok(());
    }
    Err(format!(
        "Output format '{}' is not available on the {} tier. Allowed formats: [{}]. Upgrade at https://scanrook.io/pricing",
        format,
        plan.tier,
        allowed.join(", ")
    ))
}
