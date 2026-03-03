//! PostgreSQL caching helpers for vulnerability enrichment data.
//!
//! Extracted from `vuln/mod.rs` — provides connect/init/get/put operations for all
//! enrichment cache tables (NVD, OSV, Red Hat CSAF, Red Hat CVE, RHEL CVEs).

use chrono::{DateTime, NaiveDateTime, Utc};
use postgres::{Client as PgClient, NoTls};
use rand::Rng;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::utils::progress;

use super::cluster_mode;

// --- Postgres helpers ---
pub fn pg_connect() -> Option<PgClient> {
    let raw_url = std::env::var("SCANROOK_ENRICHMENT_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    // Support schema in URL via ?schema=..., but strip it before connecting (postgres crate rejects unknown params)
    let (clean_url, schema_in_url) = strip_param_from_url(&raw_url, "schema");
    progress("nvd.cache.pg.connect.start", "");
    match PgClient::connect(&clean_url, NoTls) {
        Ok(mut client) => {
            // Determine schema from URL or env override
            let schema = schema_in_url.or_else(|| std::env::var("SCANNER_PG_SCHEMA").ok());
            if let Some(schema) = schema {
                let _ = client.execute(&*format!("SET search_path TO {}", schema), &[]);
                progress("nvd.cache.pg.search_path", &schema);
            }
            progress("nvd.cache.pg.connect.ok", "");
            Some(client)
        }
        Err(e) => {
            progress("nvd.cache.pg.connect.err", &format!("{}", e));
            None
        }
    }
}

pub fn pg_init_schema(client: &mut PgClient) {
    let res = client.batch_execute(
        "CREATE TABLE IF NOT EXISTS nvd_cve_cache (\n            cve_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            nvd_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS osv_vuln_cache (\n            vuln_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            osv_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS redhat_csaf_cache (\n            errata_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            redhat_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS redhat_cve_cache (\n            cve_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            redhat_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS rhel_cves (\n            cve_id TEXT NOT NULL,\n            package TEXT NOT NULL,\n            rhel_version TEXT NOT NULL,\n            state TEXT,\n            fix_state TEXT,\n            advisory TEXT,\n            fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n            PRIMARY KEY (cve_id, package, rhel_version)\n        );\n        CREATE INDEX IF NOT EXISTS idx_nvd_cve_cache_last_checked ON nvd_cve_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_osv_vuln_cache_last_checked ON osv_vuln_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_redhat_csaf_cache_last_checked ON redhat_csaf_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_redhat_cve_cache_last_checked ON redhat_cve_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_rhel_cves_package ON rhel_cves (package);\n        CREATE INDEX IF NOT EXISTS idx_rhel_cves_fetched_at ON rhel_cves (fetched_at);\n        CREATE TABLE IF NOT EXISTS epss_scores_cache (\n            cve_id TEXT PRIMARY KEY,\n            score REAL NOT NULL,\n            percentile REAL NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL\n        );\n        CREATE TABLE IF NOT EXISTS kev_entries_cache (\n            cve_id TEXT PRIMARY KEY,\n            last_checked_at TIMESTAMPTZ NOT NULL\n        );\n        CREATE TABLE IF NOT EXISTS debian_tracker_cache (\n            cve_id TEXT NOT NULL,\n            package TEXT NOT NULL,\n            release TEXT NOT NULL,\n            status TEXT,\n            urgency TEXT,\n            fixed_version TEXT,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            PRIMARY KEY (cve_id, package, release)\n        );\n        CREATE TABLE IF NOT EXISTS ubuntu_usn_cache (\n            cve_id TEXT NOT NULL,\n            package TEXT NOT NULL,\n            release TEXT NOT NULL,\n            status TEXT,\n            priority TEXT,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            PRIMARY KEY (cve_id, package, release)\n        );\n        CREATE TABLE IF NOT EXISTS alpine_secdb_cache (\n            cve_id TEXT NOT NULL,\n            package TEXT NOT NULL,\n            branch TEXT NOT NULL,\n            repo TEXT NOT NULL,\n            fixed_version TEXT,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            PRIMARY KEY (cve_id, package, branch, repo)\n        );\n        CREATE INDEX IF NOT EXISTS idx_debian_cache_pkg ON debian_tracker_cache (package, release);\n        CREATE INDEX IF NOT EXISTS idx_ubuntu_cache_pkg ON ubuntu_usn_cache (package, release);\n        CREATE INDEX IF NOT EXISTS idx_alpine_cache_pkg ON alpine_secdb_cache (package, branch);\n        ALTER TABLE ubuntu_usn_cache ADD COLUMN IF NOT EXISTS fixed_version TEXT;\
        CREATE TABLE IF NOT EXISTS osv_batch_chunk_cache (\
            chunk_digest TEXT PRIMARY KEY,\
            payload JSONB NOT NULL,\
            last_checked_at TIMESTAMPTZ NOT NULL\
        );\
        CREATE INDEX IF NOT EXISTS idx_osv_batch_chunk_cache_last_checked ON osv_batch_chunk_cache (last_checked_at);"
    );
    match res {
        Ok(_) => progress("nvd.cache.pg.init.ok", ""),
        Err(e) => progress("nvd.cache.pg.init.err", &format!("{}", e)),
    }
}

fn strip_param_from_url(url: &str, key: &str) -> (String, Option<String>) {
    let mut parts = url.splitn(2, '?');
    let base = parts.next().unwrap_or("");
    if let Some(query) = parts.next() {
        let mut kept: Vec<String> = Vec::new();
        let mut found: Option<String> = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == key {
                if !v.is_empty() {
                    found = Some(v.to_string());
                }
                continue;
            }
            kept.push(format!("{}={}", k, v));
        }
        if kept.is_empty() {
            (base.to_string(), found)
        } else {
            (format!("{}?{}", base, kept.join("&")), found)
        }
    } else {
        (url.to_string(), None)
    }
}

pub(super) fn parse_nvd_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let s = json["vulnerabilities"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|it| it["cve"]["lastModified"].as_str())?;
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // If missing timezone, try appending Z
    if !s.ends_with('Z') {
        let mut t = String::from(s);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    // Try naive formats
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

pub(super) fn parse_osv_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let s = json["modified"].as_str()?; // OSV schema top-level
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if !s.ends_with('Z') {
        let mut t = String::from(s);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

pub(super) fn parse_redhat_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let tracking = json.get("document").and_then(|d| d.get("tracking"));
    let ts = tracking
        .and_then(|t| t.get("current_release_date"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            tracking
                .and_then(|t| t.get("initial_release_date"))
                .and_then(|v| v.as_str())
        })?;
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.with_timezone(&Utc));
    }
    if !ts.ends_with('Z') {
        let mut t = String::from(ts);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

pub(super) fn parse_redhat_cve_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let ts = json
        .get("public_date")
        .and_then(|v| v.as_str())
        .or_else(|| {
            json.get("affected_release")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .filter_map(|x| x.get("release_date").and_then(|v| v.as_str()))
                        .max()
                })
        })?;
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.with_timezone(&Utc));
    }
    if !ts.ends_with('Z') {
        let mut t = String::from(ts);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

pub(super) fn compute_dynamic_ttl_days(last_mod: Option<DateTime<Utc>>, default_days: i64) -> i64 {
    let min_days: i64 = std::env::var("SCANNER_TTL_MIN_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    let max_days: i64 = std::env::var("SCANNER_TTL_MAX_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);
    if let Some(lm) = last_mod {
        let age_days = (Utc::now() - lm).num_days().clamp(1, 3650);
        age_days.clamp(min_days, max_days)
    } else {
        default_days.clamp(min_days, max_days)
    }
}

pub(super) fn pg_get_osv(
    client: &mut PgClient,
    vuln_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client.query_opt(
        "SELECT payload, last_checked_at, osv_last_modified FROM osv_vuln_cache WHERE vuln_id = $1",
        &[&vuln_id]
    ).ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let osv_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, osv_last_modified))
}

pub(super) fn pg_put_osv(
    client: &mut PgClient,
    vuln_id: &str,
    payload: &Value,
    osv_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO osv_vuln_cache (vuln_id, payload, last_checked_at, osv_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (vuln_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), osv_last_modified = EXCLUDED.osv_last_modified",
        &[&vuln_id, &payload, &osv_last_modified]
    );
    match res {
        Ok(_) => progress(
            "osv.cache.pg.put",
            &format!(
                "{} lm={}",
                vuln_id,
                osv_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("osv.cache.pg.put.err", &format!("{} {}", vuln_id, e)),
    }
}

pub(super) fn pg_get_cve(
    client: &mut PgClient,
    cve_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client.query_opt(
        "SELECT payload, last_checked_at, nvd_last_modified FROM nvd_cve_cache WHERE cve_id = $1",
        &[&cve_id]
    ).ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let nvd_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, nvd_last_modified))
}

pub(super) fn pg_get_redhat(
    client: &mut PgClient,
    errata_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client
        .query_opt(
            "SELECT payload, last_checked_at, redhat_last_modified FROM redhat_csaf_cache WHERE errata_id = $1",
            &[&errata_id],
        )
        .ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let redhat_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, redhat_last_modified))
}

pub(super) fn pg_get_redhat_cve(
    client: &mut PgClient,
    cve_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client
        .query_opt(
            "SELECT payload, last_checked_at, redhat_last_modified FROM redhat_cve_cache WHERE cve_id = $1",
            &[&cve_id],
        )
        .ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let redhat_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, redhat_last_modified))
}

pub(super) fn pg_put_cve(
    client: &mut PgClient,
    cve_id: &str,
    payload: &Value,
    nvd_last_modified: Option<DateTime<Utc>>,
) {
    // Normalize payload: always store the inner CVE object for consistency
    // with Python bulk import. NVD API returns {"vulnerabilities":[{"cve":{...}}]}
    // but Python import stores the inner {"id":"CVE-...","metrics":{...}} object.
    let normalized = if let Some(inner) = payload
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|it| it.get("cve"))
    {
        inner.clone()
    } else {
        payload.clone()
    };
    let res = client.execute(
        "INSERT INTO nvd_cve_cache (cve_id, payload, last_checked_at, nvd_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), nvd_last_modified = EXCLUDED.nvd_last_modified",
        &[&cve_id, &normalized, &nvd_last_modified]
    );
    match res {
        Ok(_) => progress(
            "nvd.cache.pg.put",
            &format!(
                "{} lm={}",
                cve_id,
                nvd_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("nvd.cache.pg.put.err", &format!("{} {}", cve_id, e)),
    }
}

pub(super) fn pg_put_redhat(
    client: &mut PgClient,
    errata_id: &str,
    payload: &Value,
    redhat_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO redhat_csaf_cache (errata_id, payload, last_checked_at, redhat_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (errata_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), redhat_last_modified = EXCLUDED.redhat_last_modified",
        &[&errata_id, &payload, &redhat_last_modified],
    );
    match res {
        Ok(_) => progress(
            "redhat.cache.pg.put",
            &format!(
                "{} lm={}",
                errata_id,
                redhat_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("redhat.cache.pg.put.err", &format!("{} {}", errata_id, e)),
    }
}

pub(super) fn pg_put_redhat_cve(
    client: &mut PgClient,
    cve_id: &str,
    payload: &Value,
    redhat_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO redhat_cve_cache (cve_id, payload, last_checked_at, redhat_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), redhat_last_modified = EXCLUDED.redhat_last_modified",
        &[&cve_id, &payload, &redhat_last_modified],
    );
    match res {
        Ok(_) => progress(
            "redhat.cve.cache.pg.put",
            &format!(
                "{} lm={}",
                cve_id,
                redhat_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("redhat.cve.cache.pg.put.err", &format!("{} {}", cve_id, e)),
    }
}

/// Query the `rhel_cves` table for previously cached structured RHEL CVE data for
/// a given package and RHEL major version. Returns rows that are still within the
/// configured TTL (defaults to 30 days).
pub(super) fn pg_get_rhel_cves(
    client: &mut PgClient,
    package: &str,
    rhel_version: &str,
    ttl_days: i64,
) -> Vec<(String, String, String, Option<String>)> {
    // Returns (cve_id, state, fix_state, advisory)
    let rows = client
        .query(
            "SELECT cve_id, state, fix_state, advisory FROM rhel_cves \
             WHERE package = $1 AND rhel_version = $2 \
             AND fetched_at > NOW() - make_interval(days => $3)",
            &[&package, &rhel_version, &(ttl_days as i32)],
        )
        .unwrap_or_default();
    rows.iter()
        .map(|row| {
            let cve_id: String = row.get(0);
            let state: String = row.get(1);
            let fix_state: String = row.get(2);
            let advisory: Option<String> = row.get(3);
            (cve_id, state, fix_state, advisory)
        })
        .collect()
}

/// Write a structured RHEL CVE row into the `rhel_cves` table. Uses upsert so that
/// re-scans update the state and fetched_at timestamp rather than creating duplicates.
pub(super) fn pg_put_rhel_cve(
    client: &mut PgClient,
    cve_id: &str,
    package: &str,
    rhel_version: &str,
    state: &str,
    fix_state: &str,
    advisory: Option<&str>,
) {
    let res = client.execute(
        "INSERT INTO rhel_cves (cve_id, package, rhel_version, state, fix_state, advisory, fetched_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
         ON CONFLICT (cve_id, package, rhel_version) DO UPDATE SET \
           state = EXCLUDED.state, fix_state = EXCLUDED.fix_state, \
           advisory = EXCLUDED.advisory, fetched_at = NOW()",
        &[&cve_id, &package, &rhel_version, &state, &fix_state, &advisory],
    );
    match res {
        Ok(_) => {}
        Err(e) => progress(
            "rhel_cves.pg.put.err",
            &format!("{} {} {}", cve_id, package, e),
        ),
    }
}

/// Returns the cache directory for enrichment functions to use from other modules.
/// Returns the cache directory for enrichment functions to use from other modules.
/// In cluster mode, returns None so the local file cache is never used -- PostgreSQL
/// serves as the shared enrichment cache across all workers.
pub fn resolve_enrich_cache_dir() -> Option<PathBuf> {
    if cluster_mode() {
        return None; // Skip file cache in cluster mode -- use PG directly
    }
    if let Ok(dir) = std::env::var("SCANNER_CACHE") {
        return Some(PathBuf::from(dir));
    }
    // Fall back to ~/.scanrook/cache/ (same default as cache.rs)
    if let Some(home) = std::env::var_os("HOME") {
        let default_dir = PathBuf::from(home).join(".scanrook").join("cache");
        let _ = std::fs::create_dir_all(&default_dir);
        return Some(default_dir);
    }
    None
}

// ---------------------------------------------------------------------------
// Jittered TTL computation (Phase 2 foundation)
// ---------------------------------------------------------------------------

/// Compute a TTL in days with a random jitter to prevent thundering herd
/// cache invalidation. Returns `(base_days + jitter).max(1)`.
///
/// # Arguments
/// * `base_days`   — The nominal TTL (e.g. 30 for monthly refresh)
/// * `jitter_days` — Maximum absolute jitter (e.g. 7 for ±7 days)
pub(crate) fn compute_jittered_ttl_days(base_days: i64, jitter_days: i64) -> i64 {
    let jitter = rand::thread_rng().gen_range(-jitter_days..=jitter_days);
    (base_days + jitter).max(1)
}

// ---------------------------------------------------------------------------
// OSV batch chunk cache helpers (Phase 2 foundation)
// ---------------------------------------------------------------------------

/// Retrieve a cached OSV batch query response for a sorted chunk of package
/// coordinates identified by `digest` (SHA256 of the sorted package list).
/// Returns None when the entry is missing or older than `ttl_days`.
pub(crate) fn pg_get_osv_batch_chunk(
    client: &mut PgClient,
    digest: &str,
    ttl_days: i64,
) -> Option<Value> {
    let row = client
        .query_opt(
            "SELECT payload FROM osv_batch_chunk_cache \
             WHERE chunk_digest = $1 \
             AND last_checked_at > NOW() - make_interval(days => $2)",
            &[&digest, &(ttl_days as i32)],
        )
        .ok()??;
    let payload: Value = row.get(0);
    Some(payload)
}

/// Upsert an OSV batch chunk response into the cache.
pub(crate) fn pg_put_osv_batch_chunk(client: &mut PgClient, digest: &str, payload: &Value) {
    let res = client.execute(
        "INSERT INTO osv_batch_chunk_cache (chunk_digest, payload, last_checked_at) \
         VALUES ($1, $2, NOW()) \
         ON CONFLICT (chunk_digest) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW()",
        &[&digest, payload],
    );
    match res {
        Ok(_) => progress("osv.batch_chunk.pg.put", digest),
        Err(e) => progress("osv.batch_chunk.pg.put.err", &format!("{} {}", digest, e)),
    }
}

// ---------------------------------------------------------------------------
// EPSS cache helpers (Phase 2 foundation)
// ---------------------------------------------------------------------------

/// Upsert a batch of EPSS scores into the `epss_scores_cache` table.
/// Each tuple is `(cve_id, score, percentile)`.
#[allow(dead_code)]
pub(super) fn pg_put_epss_scores(client: &mut PgClient, scores: &[(String, f32, f32)]) {
    for (cve_id, score, percentile) in scores {
        let res = client.execute(
            "INSERT INTO epss_scores_cache (cve_id, score, percentile, last_checked_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (cve_id) DO UPDATE SET score = EXCLUDED.score, \
               percentile = EXCLUDED.percentile, last_checked_at = NOW()",
            &[cve_id, score, percentile],
        );
        if let Err(e) = res {
            progress(
                "epss.cache.pg.put.err",
                &format!("{} {}", cve_id, e),
            );
        }
    }
}

/// Query EPSS scores for a batch of CVE IDs. Returns only entries whose
/// `last_checked_at` is within `ttl_days`. Missing CVEs are absent from the map.
#[allow(dead_code)]
pub(super) fn pg_get_epss_scores(
    client: &mut PgClient,
    cve_ids: &[&str],
    ttl_days: i64,
) -> HashMap<String, (f32, f32)> {
    if cve_ids.is_empty() {
        return HashMap::new();
    }
    let ids_owned: Vec<String> = cve_ids.iter().map(|s| s.to_string()).collect();
    let rows = client
        .query(
            "SELECT cve_id, score, percentile FROM epss_scores_cache \
             WHERE cve_id = ANY($1) \
             AND last_checked_at > NOW() - make_interval(days => $2)",
            &[&ids_owned, &(ttl_days as i32)],
        )
        .unwrap_or_default();
    rows.iter()
        .map(|row| {
            let cve_id: String = row.get(0);
            let score: f32 = row.get(1);
            let percentile: f32 = row.get(2);
            (cve_id, (score, percentile))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// KEV cache helpers (Phase 2 foundation)
// ---------------------------------------------------------------------------

/// Upsert a batch of CISA KEV CVE IDs into the `kev_entries_cache` table.
#[allow(dead_code)]
pub(super) fn pg_put_kev_entries(client: &mut PgClient, cve_ids: &[String]) {
    for cve_id in cve_ids {
        let res = client.execute(
            "INSERT INTO kev_entries_cache (cve_id, last_checked_at) \
             VALUES ($1, NOW()) \
             ON CONFLICT (cve_id) DO NOTHING",
            &[cve_id],
        );
        if let Err(e) = res {
            progress(
                "kev.cache.pg.put.err",
                &format!("{} {}", cve_id, e),
            );
        }
    }
}

/// Retrieve all KEV CVE IDs whose cache entry is still within `ttl_days`.
/// Returns an empty set when no entries exist or all are stale.
#[allow(dead_code)]
pub(super) fn pg_get_kev_entries(client: &mut PgClient, ttl_days: i64) -> HashSet<String> {
    let rows = client
        .query(
            "SELECT cve_id FROM kev_entries_cache \
             WHERE last_checked_at > NOW() - make_interval(days => $1)",
            &[&(ttl_days as i32)],
        )
        .unwrap_or_default();
    rows.iter().map(|row| row.get::<_, String>(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_jittered_ttl_days_range() {
        for _ in 0..100 {
            let result = compute_jittered_ttl_days(30, 7);
            assert!(
                result >= 23 && result <= 37,
                "expected [23,37], got {}",
                result
            );
        }
    }

    #[test]
    fn test_compute_jittered_ttl_days_min_clamp() {
        for _ in 0..100 {
            let result = compute_jittered_ttl_days(1, 5);
            assert!(result >= 1, "expected >= 1, got {}", result);
        }
    }
}
