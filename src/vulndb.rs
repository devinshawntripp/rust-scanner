//! Pre-compiled SQLite vulnerability database for offline/fast scanning.
//!
//! The DB is downloaded via `scanrook db fetch` or built via `scanrook db build`.
//! During scans, the enrichment pipeline checks SQLite first, falling back to
//! live APIs for any misses.

use crate::utils::progress;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::{params, Connection, OpenFlags};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Current schema version — bump when adding tables or changing columns.
const SCHEMA_VERSION: &str = "1";

// ─── Path helpers ────────────────────────────────────────────────────

/// Default vulndb path: `~/.scanrook/db/scanrook.db`
pub fn vulndb_path() -> PathBuf {
    if let Ok(p) = std::env::var("SCANROOK_DB") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".scanrook")
        .join("db")
        .join("scanrook.db")
}

/// Open the vulndb if it exists on disk. Returns None if absent or corrupt.
pub fn open_vulndb() -> Option<Connection> {
    let path = vulndb_path();
    if !path.exists() {
        return None;
    }
    Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
}

// ─── Schema ──────────────────────────────────────────────────────────

const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS osv_packages (ecosystem TEXT, name TEXT, PRIMARY KEY (ecosystem, name));

CREATE TABLE IF NOT EXISTS osv_vulns (
    id TEXT, ecosystem TEXT, name TEXT,
    modified TEXT,
    PRIMARY KEY (id, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_osv_eco_name ON osv_vulns (ecosystem, name);

CREATE TABLE IF NOT EXISTS osv_payloads (
    id TEXT PRIMARY KEY,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id TEXT PRIMARY KEY,
    payload BLOB NOT NULL,
    last_modified TEXT
);

CREATE TABLE IF NOT EXISTS epss_scores (cve_id TEXT PRIMARY KEY, score REAL, percentile REAL);

CREATE TABLE IF NOT EXISTS kev_entries (cve_id TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS debian_tracker (
    cve_id TEXT, package TEXT, release TEXT,
    status TEXT, urgency TEXT, fixed_version TEXT,
    PRIMARY KEY (cve_id, package, release)
);
CREATE INDEX IF NOT EXISTS idx_debian_pkg_release ON debian_tracker (package, release);

CREATE TABLE IF NOT EXISTS ubuntu_usn (
    cve_id TEXT NOT NULL, package TEXT NOT NULL, release TEXT NOT NULL,
    status TEXT, priority TEXT,
    PRIMARY KEY (cve_id, package, release)
);
CREATE INDEX IF NOT EXISTS idx_ubuntu_pkg_release ON ubuntu_usn (package, release);

CREATE TABLE IF NOT EXISTS alpine_secdb (
    cve_id TEXT NOT NULL, package TEXT NOT NULL, branch TEXT NOT NULL,
    repo TEXT NOT NULL, fixed_version TEXT,
    PRIMARY KEY (cve_id, package, branch, repo)
);
CREATE INDEX IF NOT EXISTS idx_alpine_pkg_branch ON alpine_secdb (package, branch);
"#;

// ─── Query functions ─────────────────────────────────────────────────

/// Get the build date from metadata.
pub fn db_build_date(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = 'build_date'",
        [],
        |row| row.get(0),
    )
    .ok()
}

/// Get schema version from metadata.
pub fn db_schema_version(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )
    .ok()
}

/// Check if a package is tracked in the DB (even if it has zero vulns).
pub fn has_package(conn: &Connection, ecosystem: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM osv_packages WHERE ecosystem = ?1 AND name = ?2",
        params![ecosystem, name],
        |_| Ok(()),
    )
    .is_ok()
}

/// Query OSV vulnerabilities for a specific package. Returns decompressed JSON values.
/// Handles both schema versions: new (osv_payloads JOIN) and old (payload in osv_vulns).
pub fn query_osv_vulns(conn: &Connection, ecosystem: &str, name: &str) -> Vec<Value> {
    // Try new schema first (osv_payloads table)
    let new_query = "SELECT p.payload FROM osv_vulns v JOIN osv_payloads p ON v.id = p.id WHERE v.ecosystem = ?1 AND v.name = ?2";
    if let Ok(mut stmt) = conn.prepare(new_query) {
        if let Ok(rows) = stmt.query_map(params![ecosystem, name], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        }) {
            let results: Vec<Value> = rows
                .flatten()
                .filter_map(|blob| decompress_json(&blob))
                .collect();
            if !results.is_empty() {
                return results;
            }
        }
    }
    // Fallback: old schema (payload column directly in osv_vulns)
    let old_query = "SELECT payload FROM osv_vulns WHERE ecosystem = ?1 AND name = ?2";
    if let Ok(mut stmt) = conn.prepare(old_query) {
        if let Ok(rows) = stmt.query_map(params![ecosystem, name], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        }) {
            return rows
                .flatten()
                .filter_map(|blob| decompress_json(&blob))
                .collect();
        }
    }
    vec![]
}

/// Query a single NVD CVE. Returns decompressed JSON payload.
pub fn query_nvd_cve(conn: &Connection, cve_id: &str) -> Option<Value> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM nvd_cves WHERE cve_id = ?1",
            params![cve_id],
            |row| row.get(0),
        )
        .ok()?;
    decompress_json(&blob)
}

/// Batch query EPSS scores. Returns map of cve_id -> (score, percentile).
pub fn query_epss(conn: &Connection, cve_ids: &[String]) -> HashMap<String, (f32, f32)> {
    let mut out = HashMap::new();
    // Use individual queries — rusqlite doesn't support dynamic IN clauses easily
    let mut stmt = match conn.prepare(
        "SELECT cve_id, score, percentile FROM epss_scores WHERE cve_id = ?1",
    ) {
        Ok(s) => s,
        Err(_) => return out,
    };
    for id in cve_ids {
        if let Ok((score, pct)) = stmt.query_row(params![id], |row| {
            Ok((row.get::<_, f64>(1)? as f32, row.get::<_, f64>(2)? as f32))
        }) {
            out.insert(id.clone(), (score, pct));
        }
    }
    out
}

/// Batch check KEV entries. Returns set of CVE IDs present in KEV.
pub fn query_kev(conn: &Connection, cve_ids: &[String]) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stmt = match conn.prepare("SELECT 1 FROM kev_entries WHERE cve_id = ?1") {
        Ok(s) => s,
        Err(_) => return out,
    };
    for id in cve_ids {
        if stmt.query_row(params![id], |_| Ok(())).is_ok() {
            out.insert(id.clone());
        }
    }
    out
}

// ─── DB creation & import functions (for `db build`) ─────────────────

/// Create a new empty vulndb at the given path with the full schema.
pub fn create_db(path: &std::path::Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove existing file to start fresh
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let conn = Connection::open(path)?;
    // Use DELETE journal mode for bulk builds — WAL creates a separate file that can grow to 20GB+.
    // After build completes, optimize_db() will switch to WAL for read performance.
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-64000;")?;
    conn.execute_batch(CREATE_SCHEMA)?;
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?1)",
        params![SCHEMA_VERSION],
    )?;
    Ok(conn)
}

/// Import a single OSV ecosystem zip (one vuln per JSON file inside the zip).
/// Returns the number of vulnerabilities imported.
pub fn import_osv_ecosystem(conn: &Connection, ecosystem: &str, zip_bytes: &[u8]) -> anyhow::Result<usize> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() || !file.name().ends_with(".json") {
            continue;
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let val: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let vuln_id = val.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        if vuln_id.is_empty() {
            continue;
        }
        let modified = val
            .get("modified")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // Store payload ONCE per vuln ID (not per package — saves 50-100x space)
        // Strip unused fields to reduce payload size by ~50-70%
        let stripped = strip_osv_unused_fields(&val);
        let stripped_bytes = serde_json::to_vec(&stripped).unwrap_or_else(|_| buf.clone());
        let compressed = compress_json(&stripped_bytes);
        tx.execute(
            "INSERT OR IGNORE INTO osv_payloads (id, payload) VALUES (?1, ?2)",
            params![vuln_id, compressed],
        )?;
        // Extract affected packages — lightweight mapping rows only
        let affected = val.get("affected").and_then(|a| a.as_array());
        if let Some(affected_arr) = affected {
            for aff in affected_arr {
                let pkg = aff.get("package");
                let pkg_eco = pkg
                    .and_then(|p| p.get("ecosystem"))
                    .and_then(|e| e.as_str())
                    .unwrap_or(ecosystem);
                let pkg_name = pkg
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or_default();
                if pkg_name.is_empty() {
                    continue;
                }
                tx.execute(
                    "INSERT OR IGNORE INTO osv_packages (ecosystem, name) VALUES (?1, ?2)",
                    params![pkg_eco, pkg_name],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO osv_vulns (id, ecosystem, name, modified) VALUES (?1, ?2, ?3, ?4)",
                    params![vuln_id, pkg_eco, pkg_name, modified],
                )?;
            }
        }
        count += 1;
    }
    tx.commit()?;
    Ok(count)
}

/// Import NVD CVEs from a paginated API response JSON (the `vulnerabilities` array).
/// Returns the number of CVEs imported.
pub fn import_nvd_page(conn: &Connection, json_bytes: &[u8]) -> anyhow::Result<usize> {
    let val: Value = serde_json::from_slice(json_bytes)?;
    let vulns = val
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing vulnerabilities array"))?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;
    for item in vulns {
        let cve = match item.get("cve") {
            Some(c) => c,
            None => continue,
        };
        let cve_id = cve
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if cve_id.is_empty() {
            continue;
        }
        let last_mod = cve
            .get("lastModified")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let payload = serde_json::to_vec(cve)?;
        let compressed = compress_json(&payload);
        tx.execute(
            "INSERT OR REPLACE INTO nvd_cves (cve_id, payload, last_modified) VALUES (?1, ?2, ?3)",
            params![cve_id, compressed, last_mod],
        )?;
        count += 1;
    }
    tx.commit()?;
    Ok(count)
}

/// Import EPSS CSV data. The CSV has headers: cve,epss,percentile.
/// Returns the number of scores imported.
pub fn import_epss_csv(conn: &Connection, csv_bytes: &[u8]) -> anyhow::Result<usize> {
    let text = std::str::from_utf8(csv_bytes)?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;
    for line in text.lines() {
        // Skip comment lines and header
        if line.starts_with('#') || line.starts_with("cve,") || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 3 {
            continue;
        }
        let cve_id = parts[0].trim();
        let score: f64 = match parts[1].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let percentile: f64 = match parts[2].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        tx.execute(
            "INSERT OR REPLACE INTO epss_scores (cve_id, score, percentile) VALUES (?1, ?2, ?3)",
            params![cve_id, score, percentile],
        )?;
        count += 1;
    }
    tx.commit()?;
    Ok(count)
}

/// Import KEV JSON (CISA catalog). Returns number of entries imported.
pub fn import_kev_json(conn: &Connection, json_bytes: &[u8]) -> anyhow::Result<usize> {
    let val: Value = serde_json::from_slice(json_bytes)?;
    let vulns = val
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing vulnerabilities array"))?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;
    for item in vulns {
        let cve_id = item
            .get("cveID")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if cve_id.is_empty() {
            continue;
        }
        tx.execute(
            "INSERT OR IGNORE INTO kev_entries (cve_id) VALUES (?1)",
            params![cve_id],
        )?;
        count += 1;
    }
    tx.commit()?;
    Ok(count)
}

/// Import Debian Security Tracker JSON. Returns number of entries imported.
pub fn import_debian_tracker(conn: &Connection, json_bytes: &[u8]) -> anyhow::Result<usize> {
    let val: Value = serde_json::from_slice(json_bytes)?;
    let obj = val
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("expected JSON object"))?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;
    // Debian tracker format: { "package_name": { "CVE-xxxx": { "releases": { "bookworm": { "status": ..., "urgency": ..., "fixed_version": ... } } } } }
    for (pkg, cves_val) in obj {
        let cves = match cves_val.as_object() {
            Some(c) => c,
            None => continue,
        };
        for (cve_id, info) in cves {
            let releases = match info.get("releases").and_then(|r| r.as_object()) {
                Some(r) => r,
                None => continue,
            };
            for (release, details) in releases {
                let status = details
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let urgency = details
                    .get("urgency")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let fixed_version = details
                    .get("fixed_version")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                tx.execute(
                    "INSERT OR REPLACE INTO debian_tracker (cve_id, package, release, status, urgency, fixed_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![cve_id, pkg, release, status, urgency, fixed_version],
                )?;
                count += 1;
            }
        }
    }
    tx.commit()?;
    Ok(count)
}

/// Import Ubuntu USN data (JSON array of notices). Returns number of entries imported.
pub fn import_ubuntu_usn(conn: &Connection, json_bytes: &[u8]) -> anyhow::Result<usize> {
    let val: Value = serde_json::from_slice(json_bytes)?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;

    // Ubuntu USN format from API: object with USN IDs as keys, each containing cves and packages
    let obj = match val.as_object() {
        Some(o) => o,
        None => return Ok(0),
    };
    for (_usn_id, notice) in obj {
        let cves = notice
            .get("cves")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let priority = notice
            .get("priority")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // Packages grouped by release
        if let Some(pkgs_obj) = notice.get("packages").and_then(|p| p.as_object()) {
            for (pkg_name, _pkg_info) in pkgs_obj {
                // Get releases this package applies to
                let releases: Vec<String> = notice
                    .get("releases")
                    .and_then(|r| r.as_object())
                    .map(|r| r.keys().cloned().collect())
                    .unwrap_or_default();
                for cve_val in &cves {
                    let cve_id = cve_val.as_str().unwrap_or_default();
                    if cve_id.is_empty() || !cve_id.starts_with("CVE-") {
                        continue;
                    }
                    for release in &releases {
                        tx.execute(
                            "INSERT OR REPLACE INTO ubuntu_usn (cve_id, package, release, status, priority) VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![cve_id, pkg_name, release, "fixed", priority],
                        )?;
                        count += 1;
                    }
                }
            }
        }
    }
    tx.commit()?;
    Ok(count)
}

/// Import Alpine SecDB data for a specific branch and repo. Returns number of entries imported.
pub fn import_alpine_secdb(
    conn: &Connection,
    branch: &str,
    repo: &str,
    json_bytes: &[u8],
) -> anyhow::Result<usize> {
    let val: Value = serde_json::from_slice(json_bytes)?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;

    // Alpine SecDB format: { "packages": [ { "pkg": { "name": ..., "secfixes": { "version": ["CVE-..."] } } } ] }
    let packages = val
        .get("packages")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    for pkg_entry in &packages {
        let pkg = match pkg_entry.get("pkg") {
            Some(p) => p,
            None => continue,
        };
        let pkg_name = pkg
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        if pkg_name.is_empty() {
            continue;
        }
        let secfixes = match pkg.get("secfixes").and_then(|s| s.as_object()) {
            Some(s) => s,
            None => continue,
        };
        for (fixed_version, cves_val) in secfixes {
            let cves = match cves_val.as_array() {
                Some(c) => c,
                None => continue,
            };
            for cve_val in cves {
                let cve_id = cve_val.as_str().unwrap_or_default();
                // Some entries are just comments or references, skip those
                if cve_id.is_empty() || (!cve_id.starts_with("CVE-") && !cve_id.starts_with("XSA-")) {
                    continue;
                }
                tx.execute(
                    "INSERT OR REPLACE INTO alpine_secdb (cve_id, package, branch, repo, fixed_version) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![cve_id, pkg_name, branch, repo, fixed_version],
                )?;
                count += 1;
            }
        }
    }
    tx.commit()?;
    Ok(count)
}

/// Set metadata key/value pair.
pub fn set_metadata(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

/// Get metadata value.
pub fn get_metadata(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .ok()
}

/// VACUUM and optimize the database after bulk imports.
pub fn optimize_db(conn: &Connection) -> anyhow::Result<()> {
    // Skip VACUUM — it rewrites the entire multi-GB DB and can OOM nodes.
    // The DB works fine without it, just slightly larger on disk.
    conn.execute_batch("PRAGMA optimize; PRAGMA journal_mode=WAL;")?;
    Ok(())
}

// ─── Build helpers ───────────────────────────────────────────────────

/// Known OSV ecosystem GCS zip names mapped to our ecosystem identifiers.
pub fn osv_ecosystem_zips() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Alpine", "Alpine"),
        ("Debian", "Debian"),
        ("Ubuntu", "Ubuntu"),
        ("AlmaLinux", "AlmaLinux"),
        ("Rocky Linux", "Rocky Linux"),
        ("SUSE", "SUSE"),
        ("Red Hat", "Red Hat"),
        ("crates.io", "crates.io"),
        ("Go", "Go"),
        ("npm", "npm"),
        ("PyPI", "PyPI"),
        ("Maven", "Maven"),
        ("NuGet", "NuGet"),
        ("Packagist", "Packagist"),
        ("RubyGems", "RubyGems"),
        ("Hex", "Hex"),
        ("Pub", "Pub"),
        ("SwiftURL", "SwiftURL"),
        ("Linux", "Linux"),
        ("OSS-Fuzz", "OSS-Fuzz"),
        ("GSD", "GSD"),
        ("GitHub Actions", "GitHub Actions"),
        ("Chainguard", "Chainguard"),
        ("Wolfi", "Wolfi"),
    ]
}

/// Download all OSV ecosystems from GCS and import them.
pub fn build_osv(conn: &Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let mut total = 0usize;
    for (eco_name, eco_id) in osv_ecosystem_zips() {
        let url = format!(
            "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip",
            urlencoding::encode(eco_name)
        );
        progress("vulndb.build.osv.download", &format!("ecosystem={}", eco_name));
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes()?;
                match import_osv_ecosystem(conn, eco_id, &bytes) {
                    Ok(n) => {
                        progress(
                            "vulndb.build.osv.imported",
                            &format!("ecosystem={} vulns={}", eco_name, n),
                        );
                        total += n;
                    }
                    Err(e) => {
                        progress(
                            "vulndb.build.osv.error",
                            &format!("ecosystem={} err={}", eco_name, e),
                        );
                    }
                }
            }
            Ok(resp) => {
                progress(
                    "vulndb.build.osv.skip",
                    &format!("ecosystem={} status={}", eco_name, resp.status()),
                );
            }
            Err(e) => {
                progress(
                    "vulndb.build.osv.error",
                    &format!("ecosystem={} err={}", eco_name, e),
                );
            }
        }
    }
    Ok(total)
}

/// Download all NVD CVEs via paginated API and import them.
pub fn build_nvd(
    conn: &Connection,
    client: &reqwest::blocking::Client,
    api_key: Option<&str>,
) -> anyhow::Result<usize> {
    let mut total = 0usize;
    let mut start_index = 0u64;
    let results_per_page = 2000u64;
    loop {
        let mut url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={}&resultsPerPage={}",
            start_index, results_per_page
        );
        let _ = url; // suppress unused warning in url building
        let mut req = client.get(&url);
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }
        progress(
            "vulndb.build.nvd.page",
            &format!("start_index={}", start_index),
        );
        match req.send() {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes()?;
                let page_count = import_nvd_page(conn, &bytes)?;
                total += page_count;
                // Check if there are more pages
                let val: Value = serde_json::from_slice(&bytes)?;
                let total_results = val
                    .get("totalResults")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                start_index += results_per_page;
                if start_index >= total_results {
                    break;
                }
                // Rate limit: 0.6s with key, 6s without
                let sleep_ms = if api_key.is_some() { 600 } else { 6000 };
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            }
            Ok(resp) => {
                let status = resp.status();
                if status.as_u16() == 403 || status.as_u16() == 429 {
                    progress(
                        "vulndb.build.nvd.rate_limit",
                        &format!("status={} sleeping 30s", status),
                    );
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    continue; // retry same page
                }
                progress(
                    "vulndb.build.nvd.error",
                    &format!("status={}", status),
                );
                break;
            }
            Err(e) => {
                progress("vulndb.build.nvd.error", &format!("{}", e));
                break;
            }
        }
    }
    Ok(total)
}

/// Download EPSS CSV and import.
pub fn build_epss(conn: &Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let url = "https://epss.cyentia.com/epss_scores-current.csv.gz";
    progress("vulndb.build.epss.download", url);
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("EPSS download failed: {}", resp.status());
    }
    let gz_bytes = resp.bytes()?;
    let mut decoder = GzDecoder::new(&gz_bytes[..]);
    let mut csv_bytes = Vec::new();
    decoder.read_to_end(&mut csv_bytes)?;
    let count = import_epss_csv(conn, &csv_bytes)?;
    progress(
        "vulndb.build.epss.done",
        &format!("scores={}", count),
    );
    Ok(count)
}

/// Download KEV catalog and import.
pub fn build_kev(conn: &Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    progress("vulndb.build.kev.download", url);
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("KEV download failed: {}", resp.status());
    }
    let bytes = resp.bytes()?;
    let count = import_kev_json(conn, &bytes)?;
    progress("vulndb.build.kev.done", &format!("entries={}", count));
    Ok(count)
}

/// Download Debian Security Tracker and import.
pub fn build_debian(conn: &Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let url = "https://security-tracker.debian.org/tracker/data/json";
    progress("vulndb.build.debian.download", url);
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("Debian tracker download failed: {}", resp.status());
    }
    let bytes = resp.bytes()?;
    let count = import_debian_tracker(conn, &bytes)?;
    progress(
        "vulndb.build.debian.done",
        &format!("entries={}", count),
    );
    Ok(count)
}

/// Download Ubuntu USN data and import.
pub fn build_ubuntu(conn: &Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    // Ubuntu Security Notices API — paginated, we fetch a reasonable amount
    let url = "https://ubuntu.com/security/notices.json?limit=10000&offset=0";
    progress("vulndb.build.ubuntu.download", url);
    let mut total = 0usize;
    let mut offset = 0u64;
    loop {
        let page_url = format!(
            "https://ubuntu.com/security/notices.json?limit=500&offset={}",
            offset
        );
        match client.get(&page_url).send() {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes()?;
                let val: Value = serde_json::from_slice(&bytes)?;
                // The API returns {"notices": [...], "total_results": N}
                let notices = val.get("notices").and_then(|n| n.as_array());
                if let Some(notices_arr) = notices {
                    if notices_arr.is_empty() {
                        break;
                    }
                    let tx = conn.unchecked_transaction()?;
                    for notice in notices_arr {
                        let cves = notice
                            .get("cves")
                            .and_then(|c| c.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let priority = notice
                            .get("priority")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let packages = notice
                            .get("packages")
                            .and_then(|p| p.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let releases = notice
                            .get("releases")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        for cve_val in &cves {
                            let cve_id = cve_val
                                .get("id")
                                .and_then(|v| v.as_str())
                                .or_else(|| cve_val.as_str())
                                .unwrap_or_default();
                            if cve_id.is_empty() || !cve_id.starts_with("CVE-") {
                                continue;
                            }
                            for pkg_val in &packages {
                                let pkg_name = pkg_val
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .or_else(|| pkg_val.as_str())
                                    .unwrap_or_default();
                                if pkg_name.is_empty() {
                                    continue;
                                }
                                for rel_val in &releases {
                                    let release = rel_val
                                        .get("codename")
                                        .and_then(|c| c.as_str())
                                        .or_else(|| rel_val.as_str())
                                        .unwrap_or_default();
                                    if release.is_empty() {
                                        continue;
                                    }
                                    tx.execute(
                                        "INSERT OR REPLACE INTO ubuntu_usn (cve_id, package, release, status, priority) VALUES (?1, ?2, ?3, ?4, ?5)",
                                        params![cve_id, pkg_name, release, "fixed", priority],
                                    )?;
                                    total += 1;
                                }
                            }
                        }
                    }
                    tx.commit()?;
                    offset += 500;
                    let total_results = val
                        .get("total_results")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if offset >= total_results {
                        break;
                    }
                } else {
                    break;
                }
            }
            _ => break,
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    progress(
        "vulndb.build.ubuntu.done",
        &format!("entries={}", total),
    );
    Ok(total)
}

/// Alpine SecDB branches to fetch.
pub fn alpine_branches() -> Vec<&'static str> {
    vec![
        "v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "edge",
    ]
}

/// Download Alpine SecDB and import.
pub fn build_alpine(conn: &Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let mut total = 0usize;
    for branch in alpine_branches() {
        for repo in &["main", "community"] {
            let url = format!(
                "https://secdb.alpinelinux.org/{}/{}.json",
                branch, repo
            );
            progress(
                "vulndb.build.alpine.download",
                &format!("branch={} repo={}", branch, repo),
            );
            match client.get(&url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes()?;
                    match import_alpine_secdb(conn, branch, repo, &bytes) {
                        Ok(n) => {
                            total += n;
                        }
                        Err(e) => {
                            progress(
                                "vulndb.build.alpine.error",
                                &format!("branch={} repo={} err={}", branch, repo, e),
                            );
                        }
                    }
                }
                _ => {
                    progress(
                        "vulndb.build.alpine.skip",
                        &format!("branch={} repo={}", branch, repo),
                    );
                }
            }
        }
    }
    progress(
        "vulndb.build.alpine.done",
        &format!("entries={}", total),
    );
    Ok(total)
}

/// Build the full vulndb — downloads all bulk sources and creates the SQLite file.
pub fn build_full_db(output: &str, nvd_api_key: Option<&str>) -> anyhow::Result<()> {
    let path = std::path::Path::new(output);
    let conn = create_db(path)?;
    let started = std::time::Instant::now();

    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("scanrook-db-builder/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(300))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()?;

    // OSV ecosystems
    let osv_count = build_osv(&conn, &client)?;
    progress("vulndb.build.osv.total", &format!("vulns={}", osv_count));

    // NVD
    let nvd_count = build_nvd(&conn, &client, nvd_api_key)?;
    progress("vulndb.build.nvd.total", &format!("cves={}", nvd_count));

    // EPSS
    let epss_count = build_epss(&conn, &client)?;
    progress("vulndb.build.epss.total", &format!("scores={}", epss_count));

    // KEV
    let kev_count = build_kev(&conn, &client)?;
    progress("vulndb.build.kev.total", &format!("entries={}", kev_count));

    // Debian
    let deb_count = build_debian(&conn, &client)?;
    progress(
        "vulndb.build.debian.total",
        &format!("entries={}", deb_count),
    );

    // Ubuntu
    let ubuntu_count = build_ubuntu(&conn, &client)?;
    progress(
        "vulndb.build.ubuntu.total",
        &format!("entries={}", ubuntu_count),
    );

    // Alpine
    let alpine_count = build_alpine(&conn, &client)?;
    progress(
        "vulndb.build.alpine.total",
        &format!("entries={}", alpine_count),
    );

    // Set metadata
    let build_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    set_metadata(&conn, "build_date", &build_date)?;
    set_metadata(&conn, "schema_version", SCHEMA_VERSION)?;
    set_metadata(&conn, "osv_count", &osv_count.to_string())?;
    set_metadata(&conn, "nvd_count", &nvd_count.to_string())?;
    set_metadata(&conn, "epss_count", &epss_count.to_string())?;
    set_metadata(&conn, "kev_count", &kev_count.to_string())?;
    set_metadata(&conn, "debian_count", &deb_count.to_string())?;
    set_metadata(&conn, "ubuntu_count", &ubuntu_count.to_string())?;
    set_metadata(&conn, "alpine_count", &alpine_count.to_string())?;

    // Optimize
    progress("vulndb.build.optimize", "vacuuming database");
    optimize_db(&conn)?;

    let elapsed = started.elapsed();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    progress(
        "vulndb.build.done",
        &format!(
            "path={} size_mb={:.1} elapsed_secs={:.0} osv={} nvd={} epss={} kev={} debian={} ubuntu={} alpine={}",
            output,
            size as f64 / 1_048_576.0,
            elapsed.as_secs_f64(),
            osv_count,
            nvd_count,
            epss_count,
            kev_count,
            deb_count,
            ubuntu_count,
            alpine_count,
        ),
    );
    println!(
        "vulndb built: {} ({:.1} MB) in {:.0}s",
        output,
        size as f64 / 1_048_576.0,
        elapsed.as_secs_f64()
    );
    println!("  OSV:     {} vulns", osv_count);
    println!("  NVD:     {} CVEs", nvd_count);
    println!("  EPSS:    {} scores", epss_count);
    println!("  KEV:     {} entries", kev_count);
    println!("  Debian:  {} entries", deb_count);
    println!("  Ubuntu:  {} entries", ubuntu_count);
    println!("  Alpine:  {} entries", alpine_count);
    Ok(())
}

/// Fetch the latest vulndb release from GitHub and install it.
pub fn fetch_db(force: bool) -> anyhow::Result<()> {
    let db_path = vulndb_path();

    // Check current DB build date
    if !force {
        if let Some(conn) = open_vulndb() {
            if let Some(date) = db_build_date(&conn) {
                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                if date == today {
                    println!("vulndb already up-to-date (build_date={})", date);
                    return Ok(());
                }
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("scanrook-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    // Determine API base URL (default: scanrook.io, overridable for dev)
    let api_base = std::env::var("SCANROOK_API_BASE")
        .unwrap_or_else(|_| "https://scanrook.io".to_string());
    let meta_url = format!("{}/api/db/latest", api_base);

    progress("vulndb.fetch.check", &format!("querying {}", meta_url));
    let resp = client.get(&meta_url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "failed to query vulndb metadata from {}: HTTP {}",
            meta_url,
            resp.status()
        );
    }
    let meta: Value = resp.json()?;
    let download_url = meta
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'url' in API response"))?;
    let build_date = meta
        .get("build_date")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let asset_size = meta.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

    // Skip download if local DB matches the remote build date
    if !force {
        if let Some(conn) = open_vulndb() {
            if let Some(local_date) = db_build_date(&conn) {
                if local_date == build_date {
                    println!("vulndb already up-to-date (build_date={})", local_date);
                    return Ok(());
                }
            }
        }
    }

    println!(
        "Downloading vulndb {} ({:.1} MB)...",
        build_date,
        asset_size as f64 / 1_048_576.0
    );
    progress(
        "vulndb.fetch.download",
        &format!("build_date={} size_mb={:.1}", build_date, asset_size as f64 / 1_048_576.0),
    );

    // The API returns a presigned S3 URL — follow redirect and download
    let dl_resp = client.get(download_url).send()?;
    if !dl_resp.status().is_success() {
        anyhow::bail!("download failed: HTTP {}", dl_resp.status());
    }
    let gz_bytes = dl_resp.bytes()?;

    // Decompress to temp file, then atomic rename
    progress("vulndb.fetch.decompress", "decompressing vulndb");
    let mut decoder = GzDecoder::new(&gz_bytes[..]);
    let parent = db_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid db path"))?;
    std::fs::create_dir_all(parent)?;
    let tmp_path = parent.join(".scanrook.db.tmp");
    {
        let mut tmp_file = std::fs::File::create(&tmp_path)?;
        std::io::copy(&mut decoder, &mut tmp_file)?;
        tmp_file.flush()?;
    }

    // Atomic rename
    std::fs::rename(&tmp_path, &db_path)?;

    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    // Verify by opening
    if let Some(conn) = open_vulndb() {
        let build_date = db_build_date(&conn).unwrap_or_default();
        println!(
            "vulndb installed: {} ({:.1} MB, build_date={})",
            db_path.display(),
            db_size as f64 / 1_048_576.0,
            build_date,
        );
    } else {
        println!(
            "vulndb installed: {} ({:.1} MB)",
            db_path.display(),
            db_size as f64 / 1_048_576.0
        );
    }
    Ok(())
}

/// Print vulndb status information.
pub fn print_db_status() {
    let path = vulndb_path();
    println!("vulndb_path={}", path.display());
    if path.exists() {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        println!("vulndb_size_mb={:.1}", size as f64 / 1_048_576.0);
        if let Some(conn) = open_vulndb() {
            if let Some(date) = db_build_date(&conn) {
                println!("vulndb_build_date={}", date);
            }
            if let Some(ver) = db_schema_version(&conn) {
                println!("vulndb_schema_version={}", ver);
            }
            // Print source counts from metadata
            for key in &[
                "osv_count",
                "nvd_count",
                "epss_count",
                "kev_count",
                "debian_count",
                "ubuntu_count",
                "alpine_count",
            ] {
                if let Some(val) = get_metadata(&conn, key) {
                    println!("vulndb_{}={}", key, val);
                }
            }
        }
    } else {
        println!("vulndb_status=not_found");
        println!("hint: run `scanrook db fetch` to download the pre-compiled vulnerability database");
    }
}

// ─── Compression helpers ─────────────────────────────────────────────

/// Strip unused fields from OSV advisory JSON to reduce storage.
/// Keeps: id, modified, summary, details, aliases, severity, references, affected, database_specific.severity
/// Drops: published, withdrawn, schema_version, related, credits, affected[].versions,
///        affected[].ecosystem_specific, affected[].database_specific, affected[].ranges[].repo, etc.
fn strip_osv_unused_fields(val: &Value) -> Value {
    let obj = match val.as_object() {
        Some(o) => o,
        None => return val.clone(),
    };
    let mut out = serde_json::Map::new();
    // Keep only the fields the scanner actually reads
    for key in &["id", "modified", "summary", "details", "aliases", "severity", "references"] {
        if let Some(v) = obj.get(*key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    // Keep database_specific.severity only
    if let Some(db_spec) = obj.get("database_specific").and_then(|d| d.as_object()) {
        if let Some(sev) = db_spec.get("severity") {
            out.insert(
                "database_specific".to_string(),
                serde_json::json!({ "severity": sev }),
            );
        }
    }
    // Strip affected[] — keep package, ranges (with only type + events.fixed), drop versions/ecosystem_specific/etc
    if let Some(affected) = obj.get("affected").and_then(|a| a.as_array()) {
        let stripped_affected: Vec<Value> = affected
            .iter()
            .map(|aff| {
                let mut stripped = serde_json::Map::new();
                if let Some(pkg) = aff.get("package") {
                    stripped.insert("package".to_string(), pkg.clone());
                }
                if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
                    let stripped_ranges: Vec<Value> = ranges
                        .iter()
                        .map(|range| {
                            let mut sr = serde_json::Map::new();
                            if let Some(t) = range.get("type") {
                                sr.insert("type".to_string(), t.clone());
                            }
                            if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                                let stripped_events: Vec<Value> = events
                                    .iter()
                                    .filter_map(|e| {
                                        if e.get("fixed").is_some() {
                                            Some(e.clone())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();
                                if !stripped_events.is_empty() {
                                    sr.insert("events".to_string(), Value::Array(stripped_events));
                                }
                            }
                            Value::Object(sr)
                        })
                        .collect();
                    stripped.insert("ranges".to_string(), Value::Array(stripped_ranges));
                }
                Value::Object(stripped)
            })
            .collect();
        out.insert("affected".to_string(), Value::Array(stripped_affected));
    }
    Value::Object(out)
}

fn compress_json(data: &[u8]) -> Vec<u8> {
    // Use zstd level 3 — 30-40% smaller than gzip with faster compression
    zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
}

/// Decompress a payload blob (tries zstd, gzip, and raw JSON).
pub fn decompress_payload(data: &[u8]) -> Option<Value> {
    decompress_json(data)
}

fn decompress_json(data: &[u8]) -> Option<Value> {
    // Try zstd first (new format)
    if let Ok(decompressed) = zstd::decode_all(data) {
        if let Ok(v) = serde_json::from_slice(&decompressed) {
            return Some(v);
        }
    }
    // Fallback: try gzip (old format / backwards compat)
    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    if decoder.read_to_end(&mut buf).is_ok() {
        if let Ok(v) = serde_json::from_slice(&buf) {
            return Some(v);
        }
    }
    // Fallback: uncompressed JSON
    serde_json::from_slice(data).ok()
}

