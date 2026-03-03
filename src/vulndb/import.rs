//! Data import functions for populating the vulndb from bulk data sources.

use super::compress::{compress_json, strip_osv_unused_fields};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::io::Read;

/// Import a single OSV ecosystem zip (one vuln per JSON file inside the zip).
/// Returns the number of vulnerabilities imported.
pub fn import_osv_ecosystem(
    conn: &Connection,
    ecosystem: &str,
    zip_bytes: &[u8],
) -> anyhow::Result<usize> {
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
        // Store payload ONCE per vuln ID (not per package -- saves 50-100x space)
        // Strip unused fields to reduce payload size by ~50-70%
        let stripped = strip_osv_unused_fields(&val);
        let stripped_bytes = serde_json::to_vec(&stripped).unwrap_or_else(|_| buf.clone());
        let compressed = compress_json(&stripped_bytes);
        tx.execute(
            "INSERT OR IGNORE INTO osv_payloads (id, payload) VALUES (?1, ?2)",
            params![vuln_id, compressed],
        )?;
        // Extract affected packages -- lightweight mapping rows only
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
        let cve_id = cve.get("id").and_then(|v| v.as_str()).unwrap_or_default();
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
        let pkg_name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or_default();
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
                if cve_id.is_empty() || (!cve_id.starts_with("CVE-") && !cve_id.starts_with("XSA-"))
                {
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
