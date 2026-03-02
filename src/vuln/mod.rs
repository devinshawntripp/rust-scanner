use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::redhat::{compare_evr, is_rpm_ecosystem};
use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};
use crate::utils::{progress, progress_timing};
use rayon::prelude::*;
use reqwest::blocking::Client;
use serde_json::Value;
use std::path::PathBuf;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;

// --- Submodules ---
mod cvss;
mod debian_legacy;
mod epss;
mod http;
mod kev;
pub mod pg;
mod osv;
mod version;

pub use pg::{pg_connect, pg_init_schema, resolve_enrich_cache_dir};
pub use debian_legacy::{debian_tracker_enrich, debian_tracker_enrich_seed};
pub use epss::epss_enrich_findings;
pub use kev::kev_enrich_findings;
pub use osv::{map_osv_results_to_findings, osv_batch_query, osv_enrich_findings};
use osv::drop_fixed_findings;

use cvss::{normalize_redhat_severity, parse_cvss_score};
use http::{build_http_client, cached_http_json, enrich_http_client, nvd_get_json};
use pg::{
    compute_dynamic_ttl_days, parse_nvd_last_modified, parse_osv_last_modified,
    parse_redhat_cve_last_modified, parse_redhat_last_modified, pg_get_cve, pg_get_osv,
    pg_get_redhat, pg_get_redhat_cve, pg_get_rhel_cves, pg_put_cve, pg_put_osv, pg_put_redhat,
    pg_put_redhat_cve, pg_put_rhel_cve,
};
use version::{cmp_versions, cpe_parts, is_version_in_range};

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

/// Returns true when the scanner is running in cluster mode (SCANROOK_CLUSTER_MODE=1).
/// In cluster mode the local file cache is skipped and PostgreSQL is used as the
/// primary enrichment cache so that all workers in the cluster share results.
pub fn cluster_mode() -> bool {
    std::env::var("SCANROOK_CLUSTER_MODE")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}



/// Queries the NVD API for a given component + version
pub fn match_vuln(component: &str, version: &str) {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=10",
        urlencoding::encode(&keyword)
    );

    println!("Querying NVD: {}", url);

    let client = build_http_client(10);

    let resp = match client.get(&url).send() {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to reach NVD API: {}", e);
            return;
        }
    };

    if !resp.status().is_success() {
        eprintln!("NVD API returned error: {}", resp.status());
        return;
    }

    let json: Value = match resp.json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to parse NVD response: {}", e);
            return;
        }
    };

    let mut found = false;
    let mut seen = HashSet::new();

    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let id = item["cve"]["id"].as_str().unwrap_or("unknown");
            let descs = match item["cve"]["descriptions"].as_array() {
                Some(array) => array,
                None => {
                    println!("⚠️ No descriptions found for CVE");
                    continue;
                }
            };

            let description = descs
                .iter()
                .find(|d| d["lang"] == "en")
                .and_then(|d| d["value"].as_str())
                .unwrap_or("No English description found");

            if seen.insert(id.to_string()) {
                println!("🔹 {}: {}", id, description);
                found = true;
            }
        }
    }

    if !found {
        println!("✅ No CVEs found for: {} {}", component, version);
    }
}


fn map_debian_advisory_to_cves(advisory_id: &str, pg: &mut Option<PgClient>) -> Option<Vec<String>> {
    // 1. Check PG osv_vuln_cache for aliases (populated by bulk import)
    if let Some(client_pg) = pg.as_mut() {
        if let Some((payload, _last_checked, _last_mod)) = pg_get_osv(client_pg, advisory_id) {
            let mut cves: std::collections::HashSet<String> = std::collections::HashSet::new();
            if let Some(arr) = payload["aliases"].as_array() {
                for a in arr.iter().filter_map(|x| x.as_str()) {
                    if a.starts_with("CVE-") {
                        cves.insert(a.to_string());
                    }
                }
            }
            // Also check references and text for CVE IDs
            if let Ok(re) = regex::Regex::new(r"CVE-\d{4}-\d+") {
                if let Some(arr) = payload["references"].as_array() {
                    for r in arr {
                        if let Some(u) = r["url"].as_str() {
                            for m in re.find_iter(u) {
                                cves.insert(m.as_str().to_string());
                            }
                        }
                    }
                }
                for field in ["summary", "details"] {
                    if let Some(text) = payload[field].as_str() {
                        for m in re.find_iter(text) {
                            cves.insert(m.as_str().to_string());
                        }
                    }
                }
            }
            if !cves.is_empty() {
                progress("osv.debian.map.pg_hit", &format!("{} -> {} CVEs", advisory_id, cves.len()));
                return Some(cves.into_iter().collect());
            }
        }
    }

    // 2. Check file cache
    let cache_dir = resolve_enrich_cache_dir();
    let cache_key_str = cache_key(&["debian_advisory_map", advisory_id]);
    if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_key_str) {
        if let Ok(arr) = serde_json::from_slice::<Vec<String>>(&bytes) {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
    }

    // 3. Fallback: fetch Debian tracker HTML page
    let url = format!(
        "https://security-tracker.debian.org/tracker/{}",
        advisory_id
    );
    let client = build_http_client(10);
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().ok()?;
    let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok()?;
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in re.find_iter(&body) {
        set.insert(m.as_str().to_string());
    }
    let result: Vec<String> = set.into_iter().collect();

    // Store in file cache for future runs
    if !result.is_empty() {
        if let Ok(json_bytes) = serde_json::to_vec(&result) {
            cache_put(cache_dir.as_deref(), &cache_key_str, &json_bytes);
        }
    }

    Some(result)
}

#[derive(Debug, Clone)]
struct DistroFixCandidate {
    fixed_version: String,
    source_id: String,
    reference_url: String,
    note: String,
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default)
}


fn is_cve_id(id: &str) -> bool {
    id.starts_with("CVE-")
}

fn pkg_cve_key(pkg: &str, cve: &str) -> String {
    format!("{}|{}", pkg.to_ascii_lowercase(), cve.to_ascii_uppercase())
}

fn select_best_candidate(
    installed_version: &str,
    candidates: &[DistroFixCandidate],
) -> Option<DistroFixCandidate> {
    if candidates.is_empty() {
        return None;
    }
    let mut greater: Vec<DistroFixCandidate> = Vec::new();
    let mut less_or_equal: Vec<DistroFixCandidate> = Vec::new();

    for c in candidates {
        if cmp_versions(installed_version, &c.fixed_version) == std::cmp::Ordering::Less {
            greater.push(c.clone());
        } else {
            less_or_equal.push(c.clone());
        }
    }

    if !greater.is_empty() {
        greater.sort_by(|a, b| cmp_versions(&a.fixed_version, &b.fixed_version));
        return greater.into_iter().next();
    }
    less_or_equal.sort_by(|a, b| cmp_versions(&b.fixed_version, &a.fixed_version));
    less_or_equal.into_iter().next()
}

fn apply_distro_candidate_to_finding(f: &mut Finding, candidate: &DistroFixCandidate) {
    let Some(pkg) = f.package.as_ref() else {
        return;
    };
    let is_fixed = cmp_versions(&pkg.version, &candidate.fixed_version) != std::cmp::Ordering::Less;

    if is_fixed {
        f.fixed = Some(true);
        if f.recommendation.is_none() {
            f.recommendation = Some(format!(
                "Installed {} {} is at or above fixed version {} ({}).",
                pkg.name, pkg.version, candidate.fixed_version, candidate.source_id
            ));
        }
    } else {
        if f.fixed.is_none() {
            f.fixed = Some(false);
        }
        f.fixed_in = Some(candidate.fixed_version.clone());
        if f.recommendation.is_none() {
            f.recommendation = Some(format!(
                "Upgrade {} to {} or later ({}).",
                pkg.name, candidate.fixed_version, candidate.source_id
            ));
        }
    }

    if !f.source_ids.iter().any(|sid| sid == &candidate.source_id) {
        f.source_ids.push(candidate.source_id.clone());
    }
    if !candidate.reference_url.is_empty()
        && !f
            .references
            .iter()
            .any(|r| r.url.eq_ignore_ascii_case(&candidate.reference_url))
    {
        f.references.push(ReferenceInfo {
            reference_type: "advisory".into(),
            url: candidate.reference_url.clone(),
        });
    }
    if f.accuracy_note.is_none() {
        f.accuracy_note = Some(candidate.note.clone());
    }
}

fn debian_source_name_candidates(name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let base = name
        .split(':')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase();
    if base.is_empty() {
        return out;
    }
    out.push(base.clone());

    // Common binary-package suffixes where source package often maps to the prefix.
    let suffixes = [
        "-dev", "-dbg", "-doc", "-data", "-bin", "-common", "-utils", "-tools", "-libs",
    ];
    for suffix in suffixes {
        if let Some(prefix) = base.strip_suffix(suffix) {
            if !prefix.is_empty() {
                out.push(prefix.to_string());
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

fn load_debian_tracker_data() -> Option<Value> {
    let ttl = env_i64("SCANNER_DEBIAN_TRACKER_TTL_SECS", 6 * 60 * 60);
    let timeout = env_u64("SCANNER_DISTRO_FEED_TIMEOUT_SECS", 45);
    cached_http_json(
        "https://security-tracker.debian.org/tracker/data/json",
        "debian_tracker",
        ttl,
        timeout,
    )
}

fn build_debian_candidate_index(
    debian_data: &Value,
    needed: &HashMap<String, HashSet<String>>,
) -> HashMap<String, Vec<DistroFixCandidate>> {
    let mut out: HashMap<String, Vec<DistroFixCandidate>> = HashMap::new();
    let Some(root) = debian_data.as_object() else {
        return out;
    };

    for (pkg, cves) in needed {
        let source_names = debian_source_name_candidates(pkg);
        for source in source_names {
            let Some(pkg_obj) = root.get(&source).and_then(|v| v.as_object()) else {
                continue;
            };
            for cve in cves {
                let Some(cve_obj) = pkg_obj.get(cve).and_then(|v| v.as_object()) else {
                    continue;
                };
                let Some(releases) = cve_obj.get("releases").and_then(|v| v.as_object()) else {
                    continue;
                };
                for (_release, rel_obj) in releases {
                    let Some(rel) = rel_obj.as_object() else {
                        continue;
                    };
                    let fixed_version = rel
                        .get("fixed_version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if fixed_version.is_empty() || fixed_version == "0" {
                        continue;
                    }
                    let status = rel
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let key = pkg_cve_key(pkg, cve);
                    out.entry(key).or_default().push(DistroFixCandidate {
                        fixed_version: fixed_version.to_string(),
                        source_id: "debian:security-tracker".into(),
                        reference_url: format!(
                            "https://security-tracker.debian.org/tracker/{}",
                            cve
                        ),
                        note: format!(
                            "Debian tracker source={} status={} fixed_version={}",
                            source, status, fixed_version
                        ),
                    });
                }
            }
        }
    }
    out
}

fn load_ubuntu_notices_data() -> Option<Value> {
    let ttl = env_i64("SCANNER_UBUNTU_NOTICES_TTL_SECS", 60 * 60);
    let timeout = env_u64("SCANNER_DISTRO_FEED_TIMEOUT_SECS", 45);
    cached_http_json(
        "https://ubuntu.com/security/notices.json",
        "ubuntu_notices",
        ttl,
        timeout,
    )
}

fn build_ubuntu_candidate_index(
    ubuntu_data: &Value,
    needed_keys: &HashSet<String>,
) -> HashMap<String, Vec<DistroFixCandidate>> {
    let mut out: HashMap<String, Vec<DistroFixCandidate>> = HashMap::new();
    let notices = ubuntu_data
        .get("notices")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for notice in notices {
        let Some(cves) = notice.get("cves_ids").and_then(|v| v.as_array()) else {
            continue;
        };
        let usn_id = notice
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("USN")
            .to_string();
        let matched_cves: Vec<String> = cves
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|id| is_cve_id(id))
            .map(|s| s.to_ascii_uppercase())
            .collect();
        if matched_cves.is_empty() {
            continue;
        }
        let Some(release_pkgs) = notice.get("release_packages").and_then(|v| v.as_object()) else {
            continue;
        };
        for entries in release_pkgs.values() {
            let Some(arr) = entries.as_array() else {
                continue;
            };
            for pkg_entry in arr {
                let name = pkg_entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                let fixed_version = pkg_entry
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if name.is_empty() || fixed_version.is_empty() {
                    continue;
                }
                for cve in &matched_cves {
                    let key = pkg_cve_key(&name, cve);
                    if !needed_keys.contains(&key) {
                        continue;
                    }
                    out.entry(key).or_default().push(DistroFixCandidate {
                        fixed_version: fixed_version.to_string(),
                        source_id: usn_id.clone(),
                        reference_url: format!("https://ubuntu.com/security/{}", usn_id),
                        note: format!("Ubuntu notice {} fixed package {}", usn_id, name),
                    });
                }
            }
        }
    }

    out
}

/// Query debian_tracker_cache in PG for needed packages/CVEs instead of downloading bulk JSON.
fn build_debian_candidate_index_pg(
    pg: &mut Option<PgClient>,
    needed: &HashMap<String, HashSet<String>>,
) -> Option<HashMap<String, Vec<DistroFixCandidate>>> {
    let client_pg = pg.as_mut()?;
    let mut out: HashMap<String, Vec<DistroFixCandidate>> = HashMap::new();
    for (pkg, cves) in needed {
        let source_names = debian_source_name_candidates(pkg);
        for source in &source_names {
            let rows = client_pg
                .query(
                    "SELECT cve_id, release, status, fixed_version FROM debian_tracker_cache WHERE package = $1",
                    &[&source],
                )
                .ok()?;
            for row in &rows {
                let cve_id: String = row.get(0);
                let _release: String = row.get(1);
                let status: Option<String> = row.get(2);
                let fixed_version: Option<String> = row.get(3);
                if !cves.contains(&cve_id) {
                    continue;
                }
                let fv = fixed_version.unwrap_or_default();
                if fv.is_empty() || fv == "0" {
                    continue;
                }
                let key = pkg_cve_key(pkg, &cve_id);
                out.entry(key).or_default().push(DistroFixCandidate {
                    fixed_version: fv.clone(),
                    source_id: "debian:security-tracker".into(),
                    reference_url: format!("https://security-tracker.debian.org/tracker/{}", cve_id),
                    note: format!(
                        "Debian tracker (PG cache) source={} status={} fixed_version={}",
                        source, status.as_deref().unwrap_or("unknown"), fv
                    ),
                });
            }
        }
    }
    progress("distro.debian.pg_hit", &format!("{} candidates", out.len()));
    Some(out)
}

/// Query ubuntu_usn_cache in PG for needed package/CVE pairs instead of downloading bulk JSON.
fn build_ubuntu_candidate_index_pg(
    pg: &mut Option<PgClient>,
    needed_keys: &HashSet<String>,
) -> Option<HashMap<String, Vec<DistroFixCandidate>>> {
    let client_pg = pg.as_mut()?;
    // Extract unique package names from needed keys (format: "pkg|CVE-...")
    let mut pkgs: HashSet<String> = HashSet::new();
    for key in needed_keys {
        if let Some(pkg) = key.split('|').next() {
            pkgs.insert(pkg.to_string());
        }
    }
    let mut out: HashMap<String, Vec<DistroFixCandidate>> = HashMap::new();
    for pkg in &pkgs {
        let rows = client_pg
            .query(
                "SELECT cve_id, release, status FROM ubuntu_usn_cache WHERE package = $1",
                &[&pkg],
            )
            .ok()?;
        for row in &rows {
            let cve_id: String = row.get(0);
            let _release: String = row.get(1);
            let status: Option<String> = row.get(2);
            let key = pkg_cve_key(pkg, &cve_id);
            if !needed_keys.contains(&key) {
                continue;
            }
            let fv = status.unwrap_or_default();
            if fv.is_empty() {
                continue;
            }
            out.entry(key).or_default().push(DistroFixCandidate {
                fixed_version: fv.clone(),
                source_id: "ubuntu:usn-cache".into(),
                reference_url: format!("https://ubuntu.com/security/cves/{}", cve_id),
                note: format!("Ubuntu USN (PG cache) package={}", pkg),
            });
        }
    }
    progress("distro.ubuntu.pg_hit", &format!("{} candidates", out.len()));
    Some(out)
}

fn alpine_secdb_branches() -> Vec<String> {
    if let Ok(raw) = std::env::var("SCANNER_ALPINE_SECDB_BRANCHES") {
        let mut out: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        out.sort();
        out.dedup();
        if !out.is_empty() {
            return out;
        }
    }
    vec![
        "v3.23".to_string(),
        "v3.22".to_string(),
        "v3.21".to_string(),
        "v3.20".to_string(),
        "edge".to_string(),
    ]
}

fn load_alpine_secdb(branch: &str, repo: &str) -> Option<Value> {
    let ttl = env_i64("SCANNER_ALPINE_SECDB_TTL_SECS", 6 * 60 * 60);
    let timeout = env_u64("SCANNER_DISTRO_FEED_TIMEOUT_SECS", 45);
    let url = format!("https://secdb.alpinelinux.org/{}/{}.json", branch, repo);
    cached_http_json(
        &url,
        &format!("alpine_secdb_{}_{}", branch, repo),
        ttl,
        timeout,
    )
}

fn build_alpine_candidate_index(
    needed_keys: &HashSet<String>,
    needed_pkgs: &HashSet<String>,
    needed_cves: &HashSet<String>,
) -> HashMap<String, Vec<DistroFixCandidate>> {
    let mut out: HashMap<String, Vec<DistroFixCandidate>> = HashMap::new();
    for branch in alpine_secdb_branches() {
        for repo in ["main", "community"] {
            let Some(doc) = load_alpine_secdb(&branch, repo) else {
                continue;
            };
            let Some(packages) = doc.get("packages").and_then(|v| v.as_array()) else {
                continue;
            };
            for item in packages {
                let Some(pkg_obj) = item.get("pkg").and_then(|v| v.as_object()) else {
                    continue;
                };
                let pkg_name = pkg_obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if pkg_name.is_empty() || !needed_pkgs.contains(&pkg_name) {
                    continue;
                }
                let Some(secfixes) = pkg_obj.get("secfixes").and_then(|v| v.as_object()) else {
                    continue;
                };
                for (fixed_version, cve_list) in secfixes {
                    let Some(arr) = cve_list.as_array() else {
                        continue;
                    };
                    for cve in arr.iter().filter_map(|v| v.as_str()) {
                        let cve_up = cve.to_ascii_uppercase();
                        if !needed_cves.contains(&cve_up) {
                            continue;
                        }
                        let key = pkg_cve_key(&pkg_name, &cve_up);
                        if !needed_keys.contains(&key) {
                            continue;
                        }
                        out.entry(key).or_default().push(DistroFixCandidate {
                            fixed_version: fixed_version.clone(),
                            source_id: format!("alpine-secdb:{}:{}", branch, repo),
                            reference_url: format!(
                                "https://secdb.alpinelinux.org/{}/{}.json",
                                branch, repo
                            ),
                            note: format!(
                                "Alpine SecDB branch={} repo={} package={}",
                                branch, repo, pkg_name
                            ),
                        });
                    }
                }
            }
        }
    }
    out
}

fn distro_feed_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
    if findings.is_empty() {
        return;
    }
    if !env_bool("SCANNER_DISTRO_FEED_ENRICH", true) {
        progress("distro.feed.skip", "disabled by SCANNER_DISTRO_FEED_ENRICH");
        return;
    }

    let mut needed_deb: HashMap<String, HashSet<String>> = HashMap::new();
    let mut needed_apk_pkgs: HashSet<String> = HashSet::new();
    let mut needed_apk_cves: HashSet<String> = HashSet::new();
    let mut needed_ubuntu_keys: HashSet<String> = HashSet::new();
    let mut needed_alpine_keys: HashSet<String> = HashSet::new();

    for f in findings.iter() {
        if !is_cve_id(&f.id) {
            continue;
        }
        let Some(pkg) = f.package.as_ref() else {
            continue;
        };
        let pkg_name = pkg.name.to_ascii_lowercase();
        if (pkg.ecosystem == "deb" || pkg.ecosystem == "ubuntu-deb") {
            needed_deb
                .entry(pkg_name.clone())
                .or_default()
                .insert(f.id.to_ascii_uppercase());
            needed_ubuntu_keys.insert(pkg_cve_key(&pkg_name, &f.id));
        } else if pkg.ecosystem == "apk" {
            needed_apk_pkgs.insert(pkg_name.clone());
            needed_apk_cves.insert(f.id.to_ascii_uppercase());
            needed_alpine_keys.insert(pkg_cve_key(&pkg_name, &f.id));
        }
    }

    let ubuntu_enabled = env_bool("SCANNER_UBUNTU_TRACKER_ENRICH", true);
    let debian_enabled = env_bool("SCANNER_DEBIAN_TRACKER_ENRICH", true);
    let alpine_enabled = env_bool("SCANNER_ALPINE_SECDB_ENRICH", true);

    let ubuntu_index = if ubuntu_enabled && !needed_ubuntu_keys.is_empty() {
        let started = std::time::Instant::now();
        let idx = build_ubuntu_candidate_index_pg(pg, &needed_ubuntu_keys)
            .unwrap_or_else(|| {
                load_ubuntu_notices_data()
                    .map(|v| build_ubuntu_candidate_index(&v, &needed_ubuntu_keys))
                    .unwrap_or_default()
            });
        progress_timing("distro.ubuntu.enrich", started);
        idx
    } else {
        HashMap::new()
    };

    let debian_index = if debian_enabled && !needed_deb.is_empty() {
        let started = std::time::Instant::now();
        let idx = build_debian_candidate_index_pg(pg, &needed_deb)
            .unwrap_or_else(|| {
                load_debian_tracker_data()
                    .map(|v| build_debian_candidate_index(&v, &needed_deb))
                    .unwrap_or_default()
            });
        progress_timing("distro.debian.enrich", started);
        idx
    } else {
        HashMap::new()
    };

    let alpine_index = if alpine_enabled && !needed_alpine_keys.is_empty() {
        let started = std::time::Instant::now();
        let idx =
            build_alpine_candidate_index(&needed_alpine_keys, &needed_apk_pkgs, &needed_apk_cves);
        progress_timing("distro.alpine.enrich", started);
        idx
    } else {
        HashMap::new()
    };

    let mut applied = 0usize;
    for f in findings.iter_mut() {
        if !is_cve_id(&f.id) {
            continue;
        }
        let Some((ecosystem, pkg_name, pkg_version)) = f
            .package
            .as_ref()
            .map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone()))
        else {
            continue;
        };
        let key = pkg_cve_key(&pkg_name, &f.id);

        if ecosystem == "apk" {
            if let Some(cands) = alpine_index.get(&key) {
                if let Some(best) = select_best_candidate(&pkg_version, cands) {
                    apply_distro_candidate_to_finding(f, &best);
                    applied += 1;
                }
            }
            continue;
        }

        if (ecosystem != "deb" && ecosystem != "ubuntu-deb") {
            continue;
        }

        let looks_ubuntu = pkg_version.to_ascii_lowercase().contains("ubuntu")
            || f.source_ids
                .iter()
                .any(|sid| sid.to_ascii_uppercase().starts_with("USN-"));

        let mut applied_one = false;
        if looks_ubuntu {
            if let Some(cands) = ubuntu_index.get(&key) {
                if let Some(best) = select_best_candidate(&pkg_version, cands) {
                    apply_distro_candidate_to_finding(f, &best);
                    applied += 1;
                    applied_one = true;
                }
            }
            if !applied_one {
                if let Some(cands) = debian_index.get(&key) {
                    if let Some(best) = select_best_candidate(&pkg_version, cands) {
                        apply_distro_candidate_to_finding(f, &best);
                        applied += 1;
                    }
                }
            }
        } else {
            if let Some(cands) = debian_index.get(&key) {
                if let Some(best) = select_best_candidate(&pkg_version, cands) {
                    apply_distro_candidate_to_finding(f, &best);
                    applied += 1;
                    applied_one = true;
                }
            }
            if !applied_one {
                if let Some(cands) = ubuntu_index.get(&key) {
                    if let Some(best) = select_best_candidate(&pkg_version, cands) {
                        apply_distro_candidate_to_finding(f, &best);
                        applied += 1;
                    }
                }
            }
        }
    }

    if applied > 0 {
        progress("distro.feed.enrich.ok", &format!("applied={}", applied));
    } else {
        progress("distro.feed.enrich.skip", "no matching distro candidates");
    }
}

fn normalize_redhat_errata_id(id: &str) -> String {
    id.trim()
        .to_ascii_uppercase()
        .replace("%3A", ":")
        .replace("%3a", ":")
}

fn retain_relevant_redhat_source_ids(source_ids: &mut Vec<String>, keep: Option<&str>) {
    source_ids.retain(|sid| {
        let norm = normalize_redhat_errata_id(sid);
        if is_redhat_errata_id(&norm) {
            return keep.map(|k| norm.eq_ignore_ascii_case(k)).unwrap_or(false);
        }
        true
    });
}

fn extract_redhat_errata_from_url(url: &str) -> Option<String> {
    let normalized = normalize_reference_url(url);
    let lower = normalized.to_ascii_lowercase();
    let marker = "/errata/";
    let idx = lower.find(marker)?;
    let tail = &normalized[idx + marker.len()..];
    let raw = tail
        .split(|c| matches!(c, '/' | '?' | '#'))
        .next()
        .unwrap_or("")
        .trim();
    if raw.is_empty() {
        return None;
    }
    let norm = normalize_redhat_errata_id(raw);
    if is_redhat_errata_id(&norm) {
        Some(norm)
    } else {
        None
    }
}

fn retain_relevant_redhat_references(refs: &mut Vec<ReferenceInfo>, keep: Option<&str>) {
    refs.retain(|r| {
        if !r.reference_type.eq_ignore_ascii_case("redhat") {
            return true;
        }
        let Some(errata) = extract_redhat_errata_from_url(&r.url) else {
            return true;
        };
        keep.map(|k| errata.eq_ignore_ascii_case(k))
            .unwrap_or(false)
    });
}

fn is_redhat_family_ecosystem(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "redhat" | "rpm" | "centos" | "rocky" | "almalinux"
    )
}

fn normalize_reference_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    urlencoding::decode(trimmed)
        .map(|v| v.into_owned())
        .unwrap_or_else(|_| trimmed.to_string())
}

fn append_unique_references(dest: &mut Vec<ReferenceInfo>, refs: Vec<ReferenceInfo>) {
    for r in refs {
        let exists = dest.iter().any(|cur| {
            cur.reference_type.eq_ignore_ascii_case(&r.reference_type)
                && cur.url.eq_ignore_ascii_case(&r.url)
        });
        if !exists {
            dest.push(r);
        }
    }
}

fn is_redhat_errata_id(id: &str) -> bool {
    let up = normalize_redhat_errata_id(id);
    let mut parts = up.splitn(2, '-');
    let kind = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    if kind != "RHSA" && kind != "RHBA" && kind != "RHEA" {
        return false;
    }
    let mut rhs = rest.splitn(2, ':');
    let year = rhs.next().unwrap_or("");
    let seq = rhs.next().unwrap_or("");
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && !seq.is_empty()
        && seq.chars().all(|c| c.is_ascii_digit())
}


fn redhat_cvss_from_vuln(vuln: &Value) -> Option<CvssInfo> {
    let scores = vuln.get("scores").and_then(|s| s.as_array())?;
    for score in scores {
        if let Some(cvss3) = score.get("cvss_v3") {
            if let Some(base) = cvss3.get("baseScore").and_then(|b| b.as_f64()) {
                let vector = cvss3
                    .get("vectorString")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Some(CvssInfo {
                    base: base as f32,
                    vector,
                });
            }
        }
        if let Some(cvss2) = score.get("cvss_v2") {
            if let Some(base) = cvss2.get("baseScore").and_then(|b| b.as_f64()) {
                let vector = cvss2
                    .get("vectorString")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Some(CvssInfo {
                    base: base as f32,
                    vector,
                });
            }
        }
    }
    None
}

fn redhat_note_text(document: &Value) -> Option<String> {
    let notes = document.get("notes").and_then(|n| n.as_array())?;

    // Prefer summary/topic style notes first.
    let preferred = notes
        .iter()
        .find(|n| {
            n.get("category")
                .and_then(|c| c.as_str())
                .map(|c| c.eq_ignore_ascii_case("summary"))
                .unwrap_or(false)
                || n.get("title")
                    .and_then(|t| t.as_str())
                    .map(|t| t.eq_ignore_ascii_case("topic"))
                    .unwrap_or(false)
        })
        .and_then(|n| n.get("text").and_then(|t| t.as_str()))
        .map(|s| s.to_string());
    if preferred.is_some() {
        return preferred;
    }

    // Fallback to any first note text.
    notes.iter().find_map(|n| {
        n.get("text")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
    })
}

#[derive(Debug, Clone)]
struct RedHatFixedRelease {
    advisory: Option<String>,
    package_name: String,
    fixed_evr: String,
}

#[derive(Debug, Clone)]
struct RedHatPackageState {
    package_name: String,
    fix_state: String,
    cpe: Option<String>,
}

fn parse_redhat_release_package(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Red Hat uses "name-epoch:version-release" in affected_release.package.
    let mut parts = trimmed.rsplitn(3, '-');
    let release = parts.next()?;
    let version = parts.next()?;
    let name = parts.next()?;
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    let has_digit = version.chars().any(|c| c.is_ascii_digit());
    if !has_digit {
        return None;
    }
    Some((name.to_string(), format!("{}-{}", version, release)))
}

fn parse_redhat_package_states(json: &Value) -> Vec<RedHatPackageState> {
    let mut states = Vec::new();
    if let Some(arr) = json.get("package_state").and_then(|v| v.as_array()) {
        for item in arr {
            let package_name = item
                .get("package_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let fix_state = item
                .get("fix_state")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if package_name.is_empty() || fix_state.is_empty() {
                continue;
            }
            let cpe = item
                .get("cpe")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            states.push(RedHatPackageState {
                package_name: package_name.to_string(),
                fix_state: fix_state.to_string(),
                cpe,
            });
        }
    }
    states
}

fn parse_redhat_cve_cvss(json: &Value) -> Option<CvssInfo> {
    let cvss3 = json.get("cvss3")?;
    let base = cvss3
        .get("cvss3_base_score")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f32>().ok())?;
    let vector = cvss3
        .get("cvss3_scoring_vector")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some(CvssInfo { base, vector })
}

fn redhat_cve_references(json: &Value) -> Vec<ReferenceInfo> {
    let mut refs: Vec<ReferenceInfo> = Vec::new();
    if let Some(arr) = json.get("references").and_then(|r| r.as_array()) {
        for raw in arr.iter().filter_map(|v| v.as_str()) {
            for line in raw.lines() {
                let url = normalize_reference_url(line);
                if !url.is_empty() {
                    refs.push(ReferenceInfo {
                        reference_type: "redhat".into(),
                        url,
                    });
                }
            }
        }
    }
    refs
}

fn rpm_epoch(evr: &str) -> i64 {
    evr.split_once(':')
        .and_then(|(lhs, _)| lhs.parse::<i64>().ok())
        .unwrap_or(0)
}

fn extract_el_tag(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == b'e' && bytes[i + 1] == b'l' && bytes[i + 2].is_ascii_digit() {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            return Some(lower[i..j].to_string());
        }
    }
    None
}

fn extract_rhel_major_from_cpe(cpe: &str) -> Option<String> {
    let lower = cpe.to_ascii_lowercase();
    if let Some(idx) = lower.find("enterprise_linux:") {
        let rest = &lower[idx + "enterprise_linux:".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return Some(digits);
        }
    }
    if let Some(idx) = lower.find("rhel_eus:") {
        let rest = &lower[idx + "rhel_eus:".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return Some(digits);
        }
    }
    None
}

fn extract_rhel_major_from_version(version: &str) -> Option<String> {
    let tag = extract_el_tag(version)?;
    let digits: String = tag
        .trim_start_matches("el")
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn strip_rpm_arch_suffix(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let suffixes = [
        ".x86_64", ".aarch64", ".ppc64le", ".s390x", ".i686", ".i386", ".armv7hl", ".noarch",
        ".src",
    ];
    for suffix in suffixes {
        if lower.ends_with(suffix) {
            return lower[..lower.len() - suffix.len()].to_string();
        }
    }
    lower
}

fn package_name_matches(installed: &str, candidate: &str) -> bool {
    let installed_norm = strip_rpm_arch_suffix(installed);
    let candidate_norm = strip_rpm_arch_suffix(candidate);
    if installed_norm == candidate_norm {
        return true;
    }

    // Red Hat affected_release.package usually carries the base SRPM-ish name
    // (e.g. "bind"), while installed RPMs are often subpackages
    // (e.g. "bind-license", "bind-libs", "bind-utils").
    // Treat that as a match when the installed package is a strict subpackage.
    if installed_norm
        .strip_prefix(&candidate_norm)
        .is_some_and(|rest| rest.starts_with('-'))
    {
        return true;
    }

    false
}

fn parse_redhat_fixed_releases(json: &Value) -> Vec<RedHatFixedRelease> {
    let mut releases = Vec::new();
    if let Some(arr) = json.get("affected_release").and_then(|v| v.as_array()) {
        for item in arr {
            let package_raw = item.get("package").and_then(|v| v.as_str()).unwrap_or("");
            let Some((package_name, fixed_evr)) = parse_redhat_release_package(package_raw) else {
                continue;
            };
            let advisory = item
                .get("advisory")
                .and_then(|v| v.as_str())
                .map(normalize_redhat_errata_id)
                .filter(|id| is_redhat_errata_id(id));
            releases.push(RedHatFixedRelease {
                advisory,
                package_name,
                fixed_evr,
            });
        }
    }
    releases
}

fn best_redhat_fixed_release(
    pkg: &PackageInfo,
    all: &[RedHatFixedRelease],
) -> Option<RedHatFixedRelease> {
    let mut candidates: Vec<RedHatFixedRelease> = all
        .iter()
        .filter(|r| package_name_matches(&pkg.name, &r.package_name))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return None;
    }

    if let Some(installed_tag) = extract_el_tag(&pkg.version) {
        let tagged: Vec<RedHatFixedRelease> = candidates
            .iter()
            .filter(|r| extract_el_tag(&r.fixed_evr).as_deref() == Some(installed_tag.as_str()))
            .cloned()
            .collect();
        if tagged.is_empty() {
            // Prevent cross-stream matches (e.g. el7 package matched to el8 advisory).
            return None;
        }
        candidates = tagged;
    }

    let installed_epoch = rpm_epoch(&pkg.version);
    let epoch_match: Vec<RedHatFixedRelease> = candidates
        .iter()
        .filter(|r| rpm_epoch(&r.fixed_evr) == installed_epoch)
        .cloned()
        .collect();
    if !epoch_match.is_empty() {
        candidates = epoch_match;
    }

    candidates.sort_by(|a, b| compare_evr(&a.fixed_evr, &b.fixed_evr));
    candidates.into_iter().next()
}

fn best_redhat_package_state(
    pkg: &PackageInfo,
    all: &[RedHatPackageState],
) -> Option<RedHatPackageState> {
    let mut candidates: Vec<RedHatPackageState> = all
        .iter()
        .filter(|s| package_name_matches(&pkg.name, &s.package_name))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return None;
    }

    if let Some(installed_major) = extract_rhel_major_from_version(&pkg.version) {
        let stream_matches: Vec<RedHatPackageState> = candidates
            .iter()
            .filter(|s| {
                s.cpe
                    .as_deref()
                    .and_then(extract_rhel_major_from_cpe)
                    .as_deref()
                    == Some(installed_major.as_str())
            })
            .cloned()
            .collect();
        if !stream_matches.is_empty() {
            candidates = stream_matches;
        }
    }

    // Prefer "Not affected" if present for this package/stream.
    if let Some(not_affected) = candidates
        .iter()
        .find(|s| s.fix_state.eq_ignore_ascii_case("Not affected"))
        .cloned()
    {
        return Some(not_affected);
    }
    candidates.into_iter().next()
}

fn redhat_enrich_cve_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
    if !env_bool("SCANNER_REDHAT_ENRICH", true) {
        progress("redhat.cve.fetch.skip", "disabled by SCANNER_REDHAT_ENRICH");
        return;
    }
    if findings.is_empty() {
        return;
    }

    let mut ids: Vec<String> = findings
        .iter()
        .filter_map(|f| {
            if !f.id.starts_with("CVE-") {
                return None;
            }
            let pkg = f.package.as_ref()?;
            if !is_rpm_ecosystem(&pkg.ecosystem) {
                return None;
            }
            Some(f.id.to_ascii_uppercase())
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    if ids.is_empty() {
        progress(
            "redhat.cve.fetch.skip",
            "no rpm-ecosystem CVE findings to enrich",
        );
        return;
    }
    ids.sort();
    progress("redhat.cve.fetch.start", &format!("cves={}", ids.len()));

    let timeout_secs: u64 = std::env::var("SCANNER_REDHAT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let ttl_days: i64 = std::env::var("SCANNER_REDHAT_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let sleep_ms: u64 = std::env::var("SCANNER_REDHAT_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let max_concurrent: usize = std::env::var("SCANNER_REDHAT_CVE_CONC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4)
        .max(1);
    let skip_cache = env_bool("SCANNER_SKIP_CACHE", false);
    let require_redhat_applicability = env_bool("SCANNER_REDHAT_REQUIRE_APPLICABILITY", true);

    let client = build_http_client(timeout_secs);
    let total = ids.len();
    if let Some(c) = pg.as_mut() {
        pg_init_schema(c);
    }

    let mut enriched_count = 0usize;
    let mut fixed_count = 0usize;
    let mut vulnerable_count = 0usize;
    let mut not_applicable_count = 0usize;
    let mut no_data_count = 0usize;
    let mut drop_not_applicable: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    let mut id_to_json: HashMap<String, Value> = HashMap::new();
    let mut to_fetch: Vec<String> = Vec::new();

    let redhat_cve_started = std::time::Instant::now();
    for (idx, cve_id) in ids.iter().enumerate() {
        progress(
            "redhat.cve.lookup",
            &format!("{}/{} {}", idx + 1, total, cve_id),
        );

        let cache_tag = cache_key(&["redhat_cve", cve_id]);
        let mut json: Option<Value> = None;

        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_redhat_cve(client_pg, cve_id) {
                let ttl_dyn_days = compute_dynamic_ttl_days(last_mod, ttl_days);
                if Utc::now() - last_checked < ChronoDuration::days(ttl_dyn_days) {
                    json = Some(payload);
                    progress("redhat.cve.cache.pg.hit", cve_id);
                }
            }
        }

        if json.is_none() && !skip_cache {
            if let Some(bytes) = cache_get(
                std::env::var_os("SCANNER_CACHE")
                    .as_deref()
                    .map(PathBuf::from)
                    .as_deref(),
                &cache_tag,
            ) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    json = Some(v);
                    progress("redhat.cve.cache.hit", cve_id);
                }
            }
        }

        if let Some(v) = json {
            id_to_json.insert(cve_id.clone(), v);
        } else {
            to_fetch.push(cve_id.clone());
        }
    }

    if !to_fetch.is_empty() {
        let fetch_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_concurrent)
            .build()
            .ok();
        let fetched: Vec<(String, Value, Option<DateTime<Utc>>)> = if let Some(pool) = fetch_pool {
            pool.install(|| {
                to_fetch
                    .par_iter()
                    .filter_map(|cve_id| {
                        if sleep_ms > 0 {
                            sleep(Duration::from_millis(sleep_ms));
                        }
                        let cache_tag = cache_key(&["redhat_cve", cve_id]);
                        let url = format!(
                            "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json",
                            cve_id
                        );
                        match client.get(&url).send() {
                            Ok(r) if r.status().is_success() => match r.json::<Value>() {
                                Ok(v) => {
                                    if !skip_cache {
                                        cache_put(
                                            std::env::var_os("SCANNER_CACHE")
                                                .as_deref()
                                                .map(PathBuf::from)
                                                .as_deref(),
                                            &cache_tag,
                                            v.to_string().as_bytes(),
                                        );
                                    }
                                    let lm = parse_redhat_cve_last_modified(&v);
                                    Some((cve_id.clone(), v, lm))
                                }
                                Err(e) => {
                                    progress(
                                        "redhat.cve.fetch.err",
                                        &format!("{} json {}", cve_id, e),
                                    );
                                    None
                                }
                            },
                            Ok(r) => {
                                progress(
                                    "redhat.cve.fetch.err",
                                    &format!("{} status={}", cve_id, r.status()),
                                );
                                None
                            }
                            Err(e) => {
                                progress("redhat.cve.fetch.err", &format!("{} {}", cve_id, e));
                                None
                            }
                        }
                    })
                    .collect()
            })
        } else {
            to_fetch
                .into_iter()
                .filter_map(|cve_id| {
                    if sleep_ms > 0 {
                        sleep(Duration::from_millis(sleep_ms));
                    }
                    let cache_tag = cache_key(&["redhat_cve", &cve_id]);
                    let url = format!(
                        "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json",
                        cve_id
                    );
                    match client.get(&url).send() {
                        Ok(r) if r.status().is_success() => match r.json::<Value>() {
                            Ok(v) => {
                                if !skip_cache {
                                    cache_put(
                                        std::env::var_os("SCANNER_CACHE")
                                            .as_deref()
                                            .map(PathBuf::from)
                                            .as_deref(),
                                        &cache_tag,
                                        v.to_string().as_bytes(),
                                    );
                                }
                                let lm = parse_redhat_cve_last_modified(&v);
                                Some((cve_id, v, lm))
                            }
                            Err(e) => {
                                progress("redhat.cve.fetch.err", &format!("{} json {}", cve_id, e));
                                None
                            }
                        },
                        Ok(r) => {
                            progress(
                                "redhat.cve.fetch.err",
                                &format!("{} status={}", cve_id, r.status()),
                            );
                            None
                        }
                        Err(e) => {
                            progress("redhat.cve.fetch.err", &format!("{} {}", cve_id, e));
                            None
                        }
                    }
                })
                .collect()
        };

        for (cve_id, cve_json, lm) in fetched {
            if let Some(client_pg) = pg.as_mut() {
                pg_put_redhat_cve(client_pg, &cve_id, &cve_json, lm);
            }
            progress("redhat.cve.fetch.ok", &cve_id);
            id_to_json.insert(cve_id, cve_json);
        }
    }

    for cve_id in ids {
        let Some(cve_json) = id_to_json.get(&cve_id) else {
            for idx in 0..findings.len() {
                if !findings[idx].id.eq_ignore_ascii_case(&cve_id) {
                    continue;
                }
                let f = &mut findings[idx];
                let pkg = match f.package.clone() {
                    Some(p) if is_rpm_ecosystem(&p.ecosystem) => p,
                    _ => continue,
                };
                if !is_redhat_family_ecosystem(&pkg.ecosystem) {
                    continue;
                }
                no_data_count += 1;
                retain_relevant_redhat_source_ids(&mut f.source_ids, None);
                retain_relevant_redhat_references(&mut f.references, None);
                if require_redhat_applicability {
                    drop_not_applicable.insert(idx);
                    progress(
                        "redhat.cve.no_data.drop",
                        &format!(
                            "{} pkg={} installed={} ecosystem={}",
                            cve_id, pkg.name, pkg.version, pkg.ecosystem
                        ),
                    );
                } else {
                    if f.accuracy_note.is_none() {
                        f.accuracy_note = Some(
                            "Red Hat applicability metadata unavailable for this CVE; finding may be over-inclusive."
                                .into(),
                        );
                    }
                    progress(
                        "redhat.cve.no_data",
                        &format!(
                            "{} pkg={} installed={} ecosystem={}",
                            cve_id, pkg.name, pkg.version, pkg.ecosystem
                        ),
                    );
                }
            }
            continue;
        };

        let severity = cve_json
            .get("threat_severity")
            .and_then(|s| s.as_str())
            .and_then(normalize_redhat_severity);
        let description = cve_json
            .get("details")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.iter().find_map(|v| v.as_str()))
            .map(|s| s.to_string());
        let cvss = parse_redhat_cve_cvss(&cve_json);
        let refs = redhat_cve_references(&cve_json);
        let fixed_releases = parse_redhat_fixed_releases(&cve_json);
        let package_states = parse_redhat_package_states(&cve_json);

        let mut applied = false;
        for idx in 0..findings.len() {
            if !findings[idx].id.eq_ignore_ascii_case(&cve_id) {
                continue;
            }
            let f = &mut findings[idx];
            let pkg = match f.package.clone() {
                Some(p) if is_rpm_ecosystem(&p.ecosystem) => p,
                _ => continue,
            };

            let redhat_family = is_redhat_family_ecosystem(&pkg.ecosystem);
            if redhat_family {
                // Drop stale/advisory aliases until we can prove applicability for this package.
                retain_relevant_redhat_source_ids(&mut f.source_ids, None);
                retain_relevant_redhat_references(&mut f.references, None);
                if severity.is_some() {
                    f.severity = severity.clone();
                }
                if cvss.is_some() {
                    f.cvss = cvss.clone();
                }
                if description.is_some() {
                    f.description = description.clone();
                }
            } else {
                if f.severity.is_none() {
                    f.severity = severity.clone();
                }
                if f.cvss.is_none() {
                    f.cvss = cvss.clone();
                }
                if f.description.is_none() {
                    f.description = description.clone();
                }
            }
            append_unique_references(&mut f.references, refs.clone());
            applied = true;

            if let Some(best) = best_redhat_fixed_release(&pkg, &fixed_releases) {
                retain_relevant_redhat_source_ids(&mut f.source_ids, best.advisory.as_deref());
                retain_relevant_redhat_references(&mut f.references, best.advisory.as_deref());
                if f.fixed_in.is_none() {
                    f.fixed_in = Some(best.fixed_evr.clone());
                }
                if let Some(advisory) = best.advisory.as_ref() {
                    if !f
                        .source_ids
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(advisory))
                    {
                        f.source_ids.push(advisory.clone());
                    }
                    append_unique_references(
                        &mut f.references,
                        vec![ReferenceInfo {
                            reference_type: "redhat".into(),
                            url: format!("https://access.redhat.com/errata/{}", advisory),
                        }],
                    );
                }
                let ord = compare_evr(&pkg.version, &best.fixed_evr);
                if ord == std::cmp::Ordering::Less {
                    f.fixed = Some(false);
                    vulnerable_count += 1;
                    progress(
                        "redhat.cve.vulnerable",
                        &format!(
                            "{} pkg={} installed={} fixed_in={}",
                            cve_id, pkg.name, pkg.version, best.fixed_evr
                        ),
                    );
                    f.recommendation = Some(format!(
                        "Upgrade {} to {} or later{}.",
                        pkg.name,
                        best.fixed_evr,
                        best.advisory
                            .as_ref()
                            .map(|a| format!(" ({})", a))
                            .unwrap_or_default()
                    ));
                } else {
                    f.fixed = Some(true);
                    fixed_count += 1;
                    progress(
                        "redhat.cve.fixed",
                        &format!(
                            "{} pkg={} installed={} fixed_in={}",
                            cve_id, pkg.name, pkg.version, best.fixed_evr
                        ),
                    );
                    if f.recommendation.is_none() {
                        f.recommendation = Some(format!(
                            "Installed {} {} is at or above Red Hat fixed build {}.",
                            pkg.name, pkg.version, best.fixed_evr
                        ));
                    }
                }
            } else if let Some(state) = best_redhat_package_state(&pkg, &package_states) {
                retain_relevant_redhat_source_ids(&mut f.source_ids, None);
                retain_relevant_redhat_references(&mut f.references, None);
                let state_lc = state.fix_state.to_ascii_lowercase();
                if state_lc == "not affected" {
                    f.fixed = Some(true);
                    fixed_count += 1;
                    progress(
                        "redhat.cve.not_affected",
                        &format!("{} pkg={} state={}", cve_id, pkg.name, state.fix_state),
                    );
                    if f.recommendation.is_none() {
                        f.recommendation = Some(format!(
                            "Red Hat marks {} as '{}' for this stream.",
                            pkg.name, state.fix_state
                        ));
                    }
                } else if state_lc.contains("will not fix") || state_lc.contains("out of support") {
                    f.fixed = Some(false);
                    vulnerable_count += 1;
                    progress(
                        "redhat.cve.unfixed",
                        &format!("{} pkg={} state={}", cve_id, pkg.name, state.fix_state),
                    );
                    if f.recommendation.is_none() {
                        f.recommendation = Some(format!(
                            "No Red Hat fixed build is available for {} on this stream (state: {}).",
                            pkg.name, state.fix_state
                        ));
                    }
                } else {
                    // Treat any other explicit Red Hat package state as unresolved/unfixed
                    // for this stream unless we already matched a fixed release above.
                    f.fixed = Some(false);
                    vulnerable_count += 1;
                    progress(
                        "redhat.cve.state",
                        &format!("{} pkg={} state={}", cve_id, pkg.name, state.fix_state),
                    );
                    if f.recommendation.is_none() {
                        f.recommendation = Some(format!(
                            "Red Hat marks {} as '{}' for this stream; no fixed build is currently published.",
                            pkg.name, state.fix_state
                        ));
                    }
                }
            } else if redhat_family {
                not_applicable_count += 1;
                retain_relevant_redhat_source_ids(&mut f.source_ids, None);
                retain_relevant_redhat_references(&mut f.references, None);
                if require_redhat_applicability {
                    drop_not_applicable.insert(idx);
                    progress(
                        "redhat.cve.not_applicable",
                        &format!(
                            "{} pkg={} installed={} ecosystem={}",
                            cve_id, pkg.name, pkg.version, pkg.ecosystem
                        ),
                    );
                } else {
                    if f.accuracy_note.is_none() {
                        f.accuracy_note = Some(
                            "Red Hat did not mark this package/stream as applicable for the CVE."
                                .into(),
                        );
                    }
                    progress(
                        "redhat.cve.not_applicable.keep",
                        &format!(
                            "{} pkg={} installed={} ecosystem={}",
                            cve_id, pkg.name, pkg.version, pkg.ecosystem
                        ),
                    );
                }
            }
        }
        if applied {
            enriched_count += 1;
        }
    }
    if !drop_not_applicable.is_empty() {
        let mut idx = 0usize;
        findings.retain(|_| {
            let keep = !drop_not_applicable.contains(&idx);
            idx += 1;
            keep
        });
        progress(
            "redhat.cve.not_applicable.drop",
            &format!("count={}", drop_not_applicable.len()),
        );
    }
    progress_timing("redhat.cve.fetch", redhat_cve_started);
    progress(
        "redhat.cve.enrich.done",
        &format!(
            "cves_enriched={} vulnerable={} fixed={} not_applicable={} no_data={} require_applicability={}",
            enriched_count,
            vulnerable_count,
            fixed_count,
            not_applicable_count,
            no_data_count,
            require_redhat_applicability
        ),
    );
}

fn redhat_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
    if !env_bool("SCANNER_REDHAT_ENRICH", true) {
        progress("redhat.fetch.skip", "disabled by SCANNER_REDHAT_ENRICH");
        return;
    }
    if findings.is_empty() {
        return;
    }

    for f in findings.iter_mut() {
        let norm = normalize_redhat_errata_id(&f.id);
        if norm != f.id && is_redhat_errata_id(&norm) {
            f.id = norm;
        }
    }

    let mut ids: Vec<String> = findings
        .iter()
        .map(|f| normalize_redhat_errata_id(&f.id))
        .filter(|id| is_redhat_errata_id(id))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    if ids.is_empty() {
        return;
    }
    ids.sort();

    let max_ids = std::env::var("SCANNER_REDHAT_ENRICH_MAX_IDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0);
    if let Some(max_ids) = max_ids {
        if ids.len() > max_ids {
            progress(
                "redhat.fetch.limit",
                &format!("processing {} of {} errata", max_ids, ids.len()),
            );
            ids.truncate(max_ids);
        }
    }

    let timeout_secs: u64 = std::env::var("SCANNER_REDHAT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let ttl_days: i64 = std::env::var("SCANNER_REDHAT_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let sleep_ms: u64 = std::env::var("SCANNER_REDHAT_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let client = build_http_client(timeout_secs);
    let total = ids.len();
    if let Some(c) = pg.as_mut() {
        pg_init_schema(c);
    }

    let redhat_started = std::time::Instant::now();
    for (idx, id) in ids.into_iter().enumerate() {
        progress(
            "redhat.fetch.start",
            &format!("{}/{} {}", idx + 1, total, id),
        );

        let cache_tag = cache_key(&["redhat_csaf", &id]);
        let mut json: Option<Value> = None;

        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_redhat(client_pg, &id) {
                let ttl_dyn_days = compute_dynamic_ttl_days(last_mod, ttl_days);
                if Utc::now() - last_checked < ChronoDuration::days(ttl_dyn_days) {
                    json = Some(payload);
                    progress("redhat.cache.pg.hit", &id);
                }
            }
        }

        if json.is_none() {
            if let Some(bytes) = cache_get(
                std::env::var_os("SCANNER_CACHE")
                    .as_deref()
                    .map(PathBuf::from)
                    .as_deref(),
                &cache_tag,
            ) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    json = Some(v);
                    progress("redhat.cache.hit", &id);
                }
            }
        }

        if json.is_none() {
            if sleep_ms > 0 {
                sleep(Duration::from_millis(sleep_ms));
            }
            let url = format!(
                "https://access.redhat.com/hydra/rest/securitydata/csaf/{}.json?isCompressed=false",
                id
            );
            match client.get(&url).send() {
                Ok(r) if r.status().is_success() => match r.json::<Value>() {
                    Ok(v) => {
                        cache_put(
                            std::env::var_os("SCANNER_CACHE")
                                .as_deref()
                                .map(PathBuf::from)
                                .as_deref(),
                            &cache_tag,
                            v.to_string().as_bytes(),
                        );
                        json = Some(v);
                    }
                    Err(e) => {
                        progress("redhat.fetch.err", &format!("{} json {}", id, e));
                    }
                },
                Ok(r) => {
                    progress("redhat.fetch.err", &format!("{} status={}", id, r.status()));
                }
                Err(e) => {
                    progress("redhat.fetch.err", &format!("{} {}", id, e));
                }
            }
        }

        let Some(doc_json) = json else {
            continue;
        };
        if let Some(client_pg) = pg.as_mut() {
            let last_mod = parse_redhat_last_modified(&doc_json);
            pg_put_redhat(client_pg, &id, &doc_json, last_mod);
        }
        progress("redhat.fetch.ok", &id);

        let document = &doc_json["document"];
        let description = redhat_note_text(document).or_else(|| {
            document
                .get("title")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        });
        let severity = document
            .get("aggregate_severity")
            .and_then(|s| s.get("text"))
            .and_then(|s| s.as_str())
            .and_then(normalize_redhat_severity);

        let mut references: Vec<ReferenceInfo> = Vec::new();
        if let Some(refs) = document.get("references").and_then(|r| r.as_array()) {
            for r in refs {
                if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                    let normalized = normalize_reference_url(url);
                    if normalized.is_empty() {
                        continue;
                    }
                    references.push(ReferenceInfo {
                        reference_type: "redhat".into(),
                        url: normalized,
                    });
                }
            }
        }
        if references.is_empty() {
            references.push(ReferenceInfo {
                reference_type: "redhat".into(),
                url: format!("https://access.redhat.com/errata/{}", id),
            });
        }

        let mut best_cvss: Option<CvssInfo> = None;
        if let Some(vulns) = doc_json.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulns {
                if let Some(cvss) = redhat_cvss_from_vuln(v) {
                    let replace = best_cvss
                        .as_ref()
                        .map(|existing| cvss.base > existing.base)
                        .unwrap_or(true);
                    if replace {
                        best_cvss = Some(cvss);
                    }
                }
            }
        }

        for f in findings
            .iter_mut()
            .filter(|f| f.id.eq_ignore_ascii_case(&id))
        {
            if f.description.is_none() {
                f.description = description.clone();
            }
            if f.severity.is_none() {
                f.severity = severity.clone();
            }
            if f.cvss.is_none() {
                f.cvss = best_cvss.clone();
            }
            if f.references.is_empty() && !references.is_empty() {
                f.references = references.clone();
            }
            if f.confidence.is_none() {
                f.confidence = Some("MEDIUM".into());
            }
        }
    }
    progress_timing("redhat.fetch", redhat_started);
}

/// Discover unfixed CVEs from the Red Hat per-package CVE list API and inject fully-enriched
/// findings for CVEs that are not yet in the findings list (i.e. CVEs tracked as "Affected",
/// "Fix deferred", or "Will not fix" by Red Hat but missing from OSV/OVAL because OVAL only
/// contains patch-class definitions).
///
/// Unlike `redhat_enrich_cve_findings` (which enriches existing findings), this function
/// discovers NEW CVEs. For each candidate, it fetches the per-CVE JSON and checks
/// `package_state` for the installed RHEL version before creating a finding — so only
/// genuinely applicable unfixed CVEs are injected, keeping the finding count accurate.
///
/// Uses the same cache format as `redhat_enrich_cve_findings` (`["redhat_cve", id]`)
/// to avoid redundant fetches between the two steps.
///
/// Controlled by `SCANNER_REDHAT_ENRICH` (default: true).
/// Set `SCANNER_REDHAT_UNFIXED_SKIP=1` to disable just this step.
pub fn redhat_inject_unfixed_cves(
    findings: &mut Vec<Finding>,
    packages: &[PackageCoordinate],
    pg: &mut Option<PgClient>,
) {
    if !env_bool("SCANNER_REDHAT_ENRICH", true) {
        return;
    }
    if env_bool("SCANNER_REDHAT_UNFIXED_SKIP", false) {
        progress("redhat.pkg.cve.skip", "disabled by SCANNER_REDHAT_UNFIXED_SKIP");
        return;
    }

    let rpm_packages: Vec<&PackageCoordinate> = packages
        .iter()
        .filter(|p| is_rpm_ecosystem(&p.ecosystem))
        .collect();
    if rpm_packages.is_empty() {
        return;
    }

    // Detect RHEL major version to filter package_state entries appropriately.
    let rhel_version = crate::redhat::detect_rhel_major_version(packages);
    let rhel_major_str = rhel_version.map(|v| v.to_string());

    // Build a set of CVE IDs already in findings (any package) to skip known CVEs.
    let existing_cve_ids: HashSet<String> = findings
        .iter()
        .filter(|f| f.id.starts_with("CVE-"))
        .map(|f| f.id.to_ascii_uppercase())
        .collect();

    // Build a set of (cve_id, package_name) keys already in findings to avoid exact duplicates.
    let existing_keys: HashSet<String> = findings
        .iter()
        .flat_map(|f| {
            let cve = f.id.to_ascii_uppercase();
            f.package
                .as_ref()
                .map(|p| format!("{}|{}", cve, p.name))
                .into_iter()
        })
        .collect();

    let timeout_secs: u64 = std::env::var("SCANNER_REDHAT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let skip_cache = env_bool("SCANNER_SKIP_CACHE", false);
    let cache_dir = resolve_enrich_cache_dir();
    let max_concurrent: usize = std::env::var("SCANNER_REDHAT_CVE_CONC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4)
        .max(1);

    let client = build_http_client(timeout_secs);
    let ttl_days: i64 = std::env::var("SCANNER_REDHAT_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    if let Some(c) = pg.as_mut() {
        pg_init_schema(c);
    }

    // In cluster mode, check the rhel_cves PG table for previously cached structured
    // findings. Any (cve_id, package) pairs found with valid TTL are injected directly
    // and excluded from later API fetching.
    let mut pg_preloaded_keys: HashSet<String> = HashSet::new();
    if cluster_mode() {
        if let Some(c) = pg.as_mut() {
            let rhel_ver = rhel_major_str.as_deref().unwrap_or("0");
            let unfixed_states_set: HashSet<&str> =
                ["affected", "fix deferred", "will not fix"].iter().copied().collect();
            for pkg in &rpm_packages {
                let rows = pg_get_rhel_cves(c, &pkg.name, rhel_ver, ttl_days);
                for (cve_id, _state, fix_state, _advisory) in &rows {
                    let key = format!("{}|{}", cve_id, pkg.name);
                    let state_lc = fix_state.to_ascii_lowercase();
                    if !unfixed_states_set.contains(state_lc.as_str()) {
                        // Cached as non-unfixed -- record key so we skip it downstream
                        pg_preloaded_keys.insert(key);
                        continue;
                    }
                    if existing_keys.contains(&key) || !pg_preloaded_keys.insert(key.clone()) {
                        continue;
                    }
                    // Build a finding from the cached structured data
                    let recommendation = Some(format!(
                        "No fix is currently available for {} on this platform (Red Hat state: {}).",
                        pkg.name, fix_state
                    ));
                    findings.push(Finding {
                        id: cve_id.clone(),
                        source_ids: vec!["redhat-security-data".to_string()],
                        package: Some(PackageInfo {
                            name: pkg.name.clone(),
                            ecosystem: pkg.ecosystem.clone(),
                            version: pkg.version.clone(),
                        }),
                        confidence_tier: ConfidenceTier::ConfirmedInstalled,
                        evidence_source: EvidenceSource::InstalledDb,
                        accuracy_note: Some(format!("redhat-state:{}", fix_state)),
                        fixed: Some(false),
                        fixed_in: None,
                        recommendation,
                        severity: None,
                        cvss: None,
                        description: None,
                        evidence: vec![],
                        references: vec![ReferenceInfo {
                            reference_type: "WEB".to_string(),
                            url: format!("https://access.redhat.com/security/cve/{}", cve_id),
                        }],
                        confidence: None,
                        epss_score: None,
                        epss_percentile: None,
                        in_kev: None,
                    });
                }
            }
            if !pg_preloaded_keys.is_empty() {
                progress(
                    "rhel_cves.pg.preload",
                    &format!("preloaded={}", pg_preloaded_keys.len()),
                );
            }
        }
    }

    // Collect unique candidate query names: exact installed name + derived base names.
    // Map query_name → list of installed PackageCoordinate-like tuples.
    let mut query_names: Vec<String> = Vec::new();
    let mut seen_query: HashSet<String> = HashSet::new();
    let mut query_to_packages: HashMap<String, Vec<(String, String, String)>> = HashMap::new();

    for pkg in &rpm_packages {
        let candidates = redhat_base_package_candidates(&pkg.name);
        for qname in candidates {
            if seen_query.insert(qname.clone()) {
                query_names.push(qname.clone());
            }
            query_to_packages
                .entry(qname)
                .or_default()
                .push((pkg.name.clone(), pkg.version.clone(), pkg.ecosystem.clone()));
        }
    }

    let total_queries = query_names.len();
    progress(
        "redhat.pkg.cve.start",
        &format!("packages={} queries={}", rpm_packages.len(), total_queries),
    );
    let started = std::time::Instant::now();

    // Step 1: Collect new candidate CVE IDs from per-package list (cached).
    // Each CVE ID is mapped to the set of installed package names it may affect.
    // Load all per-package CVE lists in parallel (cache reads + any network fetches).
    let pkg_list_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(max_concurrent)
        .build()
        .ok();

    let loaded_lists: Vec<(String, Vec<String>)> = if let Some(pool) = pkg_list_pool {
        pool.install(|| {
            query_names
                .par_iter()
                .filter_map(|qname| {
                    let cache_tag = cache_key(&["redhat_pkg_cves", qname]);
                    let mut cve_list: Option<Vec<String>> = None;

                    if !skip_cache {
                        if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_tag) {
                            if let Ok(v) = serde_json::from_slice::<Vec<String>>(&bytes) {
                                cve_list = Some(v);
                            }
                        }
                    }

                    if cve_list.is_none() {
                        let url = format!(
                            "https://access.redhat.com/hydra/rest/securitydata/cve.json?package={}&per_page=10000",
                            qname
                        );
                        let local_client = build_http_client(timeout_secs);
                        match local_client.get(&url).send() {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.json::<Value>() {
                                    Ok(json) => {
                                        let ids: Vec<String> = json
                                            .as_array()
                                            .map(|arr| {
                                                arr.iter()
                                                    .filter_map(|item| {
                                                        item.get("CVE")
                                                            .and_then(|v| v.as_str())
                                                            .map(|s| s.to_ascii_uppercase())
                                                    })
                                                    .collect()
                                            })
                                            .unwrap_or_default();
                                        if let Ok(bytes) = serde_json::to_vec(&ids) {
                                            let cd = resolve_enrich_cache_dir();
                                            cache_put(cd.as_deref(), &cache_tag, &bytes);
                                        }
                                        cve_list = Some(ids);
                                    }
                                    Err(_) => {}
                                }
                            }
                            _ => {}
                        }
                    }

                    cve_list.map(|ids| (qname.clone(), ids))
                })
                .collect()
        })
    } else {
        Vec::new()
    };

    progress(
        "redhat.pkg.cve.lists",
        &format!("loaded={}/{}", loaded_lists.len(), total_queries),
    );

    let mut cve_to_packages: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
    for (qname, cve_ids) in loaded_lists {
        let Some(pkg_attribs) = query_to_packages.get(&qname) else { continue };
        for cve_id in cve_ids {
            if !cve_id.starts_with("CVE-") {
                continue;
            }
            // Only process CVEs not already known to us — known CVEs are already handled
            // by redhat_enrich_cve_findings in the osv_enrich_findings pipeline.
            if existing_cve_ids.contains(&cve_id) {
                continue;
            }
            for attrib in pkg_attribs {
                let key = format!("{}|{}", cve_id, attrib.0);
                if !existing_keys.contains(&key) && !pg_preloaded_keys.contains(&key) {
                    cve_to_packages
                        .entry(cve_id.clone())
                        .or_default()
                        .push(attrib.clone());
                }
            }
        }
    }

    if cve_to_packages.is_empty() {
        progress_timing("redhat.pkg.cve", started);
        progress("redhat.pkg.cve.done", "injected=0 (no new CVEs from pkg list)");
        return;
    }

    progress(
        "redhat.pkg.cve.new",
        &format!("unique_cves={}", cve_to_packages.len()),
    );

    // Step 2: For each new CVE ID, fetch per-CVE JSON (using the SAME cache as
    // redhat_enrich_cve_findings to avoid redundant fetches).
    let new_cve_ids: Vec<String> = cve_to_packages.keys().cloned().collect();
    let total_new = new_cve_ids.len();

    // Check PG cache first (sequential since PgClient is !Send).
    let mut id_to_json: HashMap<String, Value> = HashMap::new();
    let mut pg_misses: Vec<String> = Vec::new();

    for cve_id in &new_cve_ids {
        let mut pg_hit = false;
        if let Some(c) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_redhat_cve(c, cve_id) {
                let ttl = compute_dynamic_ttl_days(last_mod, ttl_days);
                if Utc::now() - last_checked < ChronoDuration::days(ttl) {
                    id_to_json.insert(cve_id.clone(), payload);
                    pg_hit = true;
                }
            }
        }
        if !pg_hit {
            pg_misses.push(cve_id.clone());
        }
    }

    // Check file cache in parallel for PG misses — per-CVE JSONs can be large,
    // so parallel deserialization meaningfully reduces wall-clock time.
    let file_cache_results: Vec<(String, Value)> = if !skip_cache && !pg_misses.is_empty() {
        let file_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_concurrent)
            .build()
            .ok();
        if let Some(pool) = file_pool {
            pool.install(|| {
                pg_misses
                    .par_iter()
                    .filter_map(|cve_id| {
                        let cache_tag = cache_key(&["redhat_cve", cve_id]);
                        if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_tag) {
                            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                                return Some((cve_id.clone(), v));
                            }
                        }
                        None
                    })
                    .collect()
            })
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let mut to_fetch: Vec<String> = Vec::new();
    let file_hit_ids: HashSet<String> = file_cache_results.iter().map(|(k, _)| k.clone()).collect();
    for (id, v) in file_cache_results {
        id_to_json.insert(id, v);
    }
    for cve_id in &pg_misses {
        if !file_hit_ids.contains(cve_id) {
            to_fetch.push(cve_id.clone());
        }
    }

    // Parallel fetch for cache misses.
    if !to_fetch.is_empty() {
        progress(
            "redhat.pkg.cve.fetch",
            &format!("fetching={}/{}", to_fetch.len(), total_new),
        );
        let fetch_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_concurrent)
            .build()
            .ok();

        let fetched: Vec<(String, Value, Option<DateTime<Utc>>)> = if let Some(pool) = fetch_pool {
            pool.install(|| {
                to_fetch
                    .par_iter()
                    .filter_map(|cve_id| {
                        let cache_tag = cache_key(&["redhat_cve", cve_id]);
                        let url = format!(
                            "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json",
                            cve_id
                        );
                        let local_client = build_http_client(timeout_secs);
                        match local_client.get(&url).send() {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.json::<Value>() {
                                    Ok(v) => {
                                        let lm = parse_redhat_cve_last_modified(&v);
                                        let bytes = serde_json::to_vec(&v).unwrap_or_default();
                                        if !bytes.is_empty() {
                                            let cd = resolve_enrich_cache_dir();
                                            cache_put(cd.as_deref(), &cache_tag, &bytes);
                                        }
                                        Some((cve_id.clone(), v, lm))
                                    }
                                    Err(_) => None,
                                }
                            }
                            _ => None,
                        }
                    })
                    .collect()
            })
        } else {
            Vec::new()
        };

        // Store to PG and merge results (sequential).
        for (id, json, lm) in fetched {
            if let Some(c) = pg.as_mut() {
                pg_put_redhat_cve(c, &id, &json, lm);
            }
            id_to_json.insert(id, json);
        }
    }

    // Step 3: For each new CVE, check package_state for the installed RHEL version.
    // Only create findings for CVEs with unfixed fix_state for our packages.
    let mut new_findings: Vec<Finding> = Vec::new();
    let mut seen_injected: HashSet<String> = HashSet::new();
    let mut injected_count = 0usize;

    // Fix states that represent "unfixed but known" — we want to show these.
    // "Out of support scope" is intentionally excluded: it applies to packages in
    // unsupported lifecycles on older RHEL streams and generates many false positives
    // when matched without a strict RHEL-version-specific CPE filter.
    let unfixed_states: &[&str] = &["affected", "fix deferred", "will not fix"];

    for (cve_id, attributed_packages) in &cve_to_packages {
        let Some(cve_json) = id_to_json.get(cve_id) else {
            continue; // No data available — skip rather than emit unsupported finding.
        };

        let severity = cve_json
            .get("threat_severity")
            .and_then(|s| s.as_str())
            .and_then(normalize_redhat_severity);
        let description = cve_json
            .get("details")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.iter().find_map(|v| v.as_str()))
            .map(|s| s.to_string());
        let cvss = parse_redhat_cve_cvss(cve_json);
        let refs = redhat_cve_references(cve_json);
        let package_states = parse_redhat_package_states(cve_json);

        if package_states.is_empty() {
            continue; // No package_state data → can't confirm applicability.
        }

        for (installed_name, installed_version, installed_ecosystem) in attributed_packages {
            let key = format!("{}|{}", cve_id, installed_name);
            if existing_keys.contains(&key) || !seen_injected.insert(key) {
                continue;
            }

            let pkg_info = PackageInfo {
                name: installed_name.clone(),
                ecosystem: installed_ecosystem.clone(),
                version: installed_version.clone(),
            };

            // Find the best matching package_state for this package and RHEL version.
            // We ONLY accept an entry that matches the detected RHEL major version via CPE.
            // Without this strict filter we incorrectly pick up "Will not fix" / "Out of
            // support scope" states from RHEL 4/5/6/7/8 entries that do not apply to the
            // currently installed distribution.
            let best_state: Option<&RedHatPackageState> = if let Some(ref rhel_str) = rhel_major_str {
                // Only accept an entry matching both package name AND this RHEL version via CPE.
                package_states
                    .iter()
                    .find(|s| {
                        package_name_matches(installed_name, &s.package_name)
                            && s.cpe
                                .as_deref()
                                .and_then(extract_rhel_major_from_cpe)
                                .as_deref()
                                == Some(rhel_str.as_str())
                    })
            } else {
                // No RHEL version detected — match on package name only as last resort.
                package_states
                    .iter()
                    .find(|s| package_name_matches(installed_name, &s.package_name))
            };

            let Some(state) = best_state else {
                continue; // No applicable package_state for this package.
            };

            let state_lc = state.fix_state.to_ascii_lowercase();
            // Use exact match, NOT substring match — "not affected".contains("affected") is true
            // and would incorrectly include "Not affected" packages.
            if !unfixed_states.iter().any(|u| state_lc == *u) {
                continue; // "Not affected" or other non-unfixed state — skip.
            }

            let recommendation = Some(format!(
                "No fix is currently available for {} on this platform (Red Hat state: {}).",
                installed_name, state.fix_state
            ));

            let mut all_refs = vec![ReferenceInfo {
                reference_type: "WEB".to_string(),
                url: format!("https://access.redhat.com/security/cve/{}", cve_id),
            }];
            all_refs.extend(refs.clone());

            new_findings.push(Finding {
                id: cve_id.clone(),
                source_ids: vec!["redhat-security-data".to_string()],
                package: Some(pkg_info),
                confidence_tier: ConfidenceTier::ConfirmedInstalled,
                evidence_source: EvidenceSource::InstalledDb,
                accuracy_note: Some(format!("redhat-state:{}", state.fix_state)),
                fixed: Some(false),
                fixed_in: None,
                recommendation,
                severity: severity.clone(),
                cvss: cvss.clone(),
                description: description.clone(),
                evidence: vec![],
                references: all_refs,
                confidence: None,
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
            injected_count += 1;
        }
    }

    // In cluster mode, write back structured RHEL CVE data to PostgreSQL so that
    // other workers in the cluster can reuse the results without re-fetching.
    if cluster_mode() {
        if let Some(c) = pg.as_mut() {
            let rhel_ver = rhel_major_str.as_deref().unwrap_or("0");
            let mut wb_count = 0usize;
            for f in &new_findings {
                if let Some(ref pkg) = f.package {
                    let fix_state = f
                        .accuracy_note
                        .as_deref()
                        .and_then(|n| n.strip_prefix("redhat-state:"))
                        .unwrap_or("");
                    let advisory = f
                        .references
                        .iter()
                        .find(|r| r.url.contains("access.redhat.com"))
                        .map(|r| r.url.as_str());
                    pg_put_rhel_cve(c, &f.id, &pkg.name, rhel_ver, "unfixed", fix_state, advisory);
                    wb_count += 1;
                }
            }
            if wb_count > 0 {
                progress("rhel_cves.pg.writeback", &format!("rows={}", wb_count));
            }
        }
    }

    findings.extend(new_findings);
    progress_timing("redhat.pkg.cve", started);
    progress(
        "redhat.pkg.cve.done",
        &format!("injected={}", injected_count),
    );
}

/// Derive candidate query names for the Red Hat per-package CVE API from an installed RPM
/// subpackage name. The API accepts source/base package names (e.g. `curl`), not subpackage
/// names (e.g. `curl-minimal`). Returns both the exact name and derived base names.
fn redhat_base_package_candidates(installed: &str) -> Vec<String> {
    let mut candidates: Vec<String> = vec![installed.to_string()];

    // Strip common RPM subpackage suffixes to get the base source package name.
    const SUFFIXES: &[&str] = &[
        "-libs",
        "-minimal",
        "-devel",
        "-common",
        "-common-devel",
        "-core",
        "-utils",
        "-static",
        "-headers",
        "-tools",
        "-data",
        "-doc",
        "-docs",
        "-man",
        "-selinux",
        "-debuginfo",
        "-debugsource",
        "-build-libs",
        "-sign-libs",
        "-langpack",
        "-langpack-en",
        "-gold",
        "-setuptools-wheel",
        "-pip-wheel",
        "-wheel",
        "-test",
        "-tests",
    ];

    for suffix in SUFFIXES {
        if let Some(base) = installed.strip_suffix(suffix) {
            if !base.is_empty() {
                candidates.push(base.to_string());
            }
        }
    }

    // For lib-prefixed packages, also try the name without the lib prefix.
    if let Some(without_lib) = installed.strip_prefix("lib") {
        if !without_lib.is_empty() {
            candidates.push(without_lib.to_string());
            for suffix in SUFFIXES {
                if let Some(base) = without_lib.strip_suffix(suffix) {
                    if !base.is_empty() {
                        candidates.push(base.to_string());
                    }
                }
            }
        }
    }

    // Deduplicate while preserving order (exact name first).
    let mut seen = HashSet::new();
    candidates.retain(|c| seen.insert(c.clone()));
    candidates
}

pub fn enrich_findings_with_nvd(
    findings: &mut Vec<Finding>,
    api_key: Option<&str>,
    pg: &mut Option<PgClient>,
) {
    if !env_bool("SCANNER_NVD_ENRICH", true) {
        progress("nvd.fetch.skip", "disabled by SCANNER_NVD_ENRICH");
        return;
    }
    if findings.is_empty() {
        return;
    }
    // Only fetch CVEs that still need enrichment, unless explicitly disabled.
    let skip_fully_enriched = env_bool("SCANNER_NVD_SKIP_FULLY_ENRICHED", true);
    let mut cve_needs_nvd: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    for f in findings.iter().filter(|f| f.id.starts_with("CVE-")) {
        let needs_nvd = !skip_fully_enriched
            || f.cvss.is_none()
            || f.severity.is_none()
            || f.description.is_none()
            || f.references.is_empty();
        cve_needs_nvd
            .entry(f.id.clone())
            .and_modify(|v| *v = *v || needs_nvd)
            .or_insert(needs_nvd);
    }
    let total_cves = cve_needs_nvd.len();
    let mut unique_ids: Vec<String> = cve_needs_nvd
        .into_iter()
        .filter_map(|(id, needs_nvd)| if needs_nvd { Some(id) } else { None })
        .collect();
    unique_ids.sort();
    let skipped = total_cves.saturating_sub(unique_ids.len());
    if skipped > 0 {
        progress(
            "nvd.fetch.skip.enriched",
            &format!("{} already enriched", skipped),
        );
    }
    if unique_ids.is_empty() {
        return;
    }

    // Determine polite sleep between requests
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let ttl_days: i64 = std::env::var("SCANNER_NVD_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);

    // Fetch details per unique CVE with caching and rate limiting
    let mut id_to_json: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let total = unique_ids.len();

    // Optional Postgres cache
    if let Some(client) = pg.as_mut() {
        pg_init_schema(client);
    }

    // Determine which IDs to fetch from network after consulting PG cache
    let cache_lookup_started = std::time::Instant::now();
    let mut to_fetch: Vec<(usize, String)> = Vec::new();
    for (idx, id) in unique_ids.into_iter().enumerate() {
        let mut served_from_cache = false;
        if let Some(client) = pg.as_mut() {
            if let Some((payload, last_checked_at, nvd_last_modified)) = pg_get_cve(client, &id) {
                let ttl_dyn_days =
                    compute_dynamic_ttl_days(nvd_last_modified, ttl_days as i64) as i64;
                if Utc::now() - last_checked_at < ChronoDuration::days(ttl_dyn_days) {
                    id_to_json.insert(id.clone(), payload);
                    progress("nvd.cache.pg.hit", &id);
                    served_from_cache = true;
                }
            }
        }
        if !served_from_cache {
            to_fetch.push((idx, id));
        }
    }
    progress_timing("nvd.enrich.cache_lookup", cache_lookup_started);

    // Concurrency with politeness via a small threadpool
    let fetch_started = std::time::Instant::now();
    let max_concurrent: usize = std::env::var("SCANNER_NVD_CONC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if api_key.is_some() { 8 } else { 2 });
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(max_concurrent)
        .build()
        .ok();
    if let Some(pool) = pool {
        let fetched: Vec<(String, Value, Option<DateTime<Utc>>)> = pool.install(|| {
            to_fetch
                .par_iter()
                .filter_map(|(idx, id)| {
                    progress("nvd.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
                    let url = format!(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
                        id
                    );
                    match nvd_get_json(&url, api_key, &format!("cveId:{}", id), sleep_ms) {
                        Some(json) => {
                            let lm = parse_nvd_last_modified(&json);
                            Some((id.clone(), json, lm))
                        }
                        None => {
                            progress("nvd.fetch.err", id);
                            None
                        }
                    }
                })
                .collect()
        });
        // Merge results, update PG and memory map sequentially
        if let Some(client) = pg.as_mut() {
            for (id, json, lm) in &fetched {
                pg_put_cve(client, id, json, *lm);
            }
        }
        for (id, json, _lm) in fetched.into_iter() {
            id_to_json.insert(id.clone(), json);
            progress("nvd.fetch.ok", &id);
        }
    } else {
        // Fallback sequential loop
        for (idx, id) in to_fetch.into_iter() {
            progress("nvd.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
            let url = format!(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
                id
            );
            match nvd_get_json(&url, api_key, &format!("cveId:{}", id), sleep_ms) {
                Some(json) => {
                    let lm = parse_nvd_last_modified(&json);
                    if let Some(client) = pg.as_mut() {
                        pg_put_cve(client, &id, &json, lm);
                    }
                    id_to_json.insert(id.clone(), json);
                    progress("nvd.fetch.ok", &id);
                }
                None => {
                    progress("nvd.fetch.err", &id);
                }
            }
        }
    }
    progress_timing("nvd.enrich.fetch", fetch_started);

    // Apply enrichment
    let apply_started = std::time::Instant::now();
    for f in findings.iter_mut() {
        // If not in memory map and PG is configured, try PG (from parallel fetch path)
        if !id_to_json.contains_key(&f.id) {
            if let Some(client) = pg.as_mut() {
                if let Some((payload, _lc, _lm)) = pg_get_cve(client, &f.id) {
                    id_to_json.insert(f.id.clone(), payload);
                }
            }
        }
        if let Some(wrapper) = id_to_json.get(&f.id) {
            // Support both full NVD API format ({"vulnerabilities":[{"cve":{...}}]})
            // and inner CVE object format ({"id":"CVE-...", "metrics":{...}}) from bulk import
            let cve_ref = if let Some(items) = wrapper["vulnerabilities"].as_array() {
                items.first().map(|item| &item["cve"])
            } else if wrapper.get("id").and_then(|v| v.as_str()).is_some() {
                Some(wrapper)
            } else {
                None
            };
            if let Some(cve) = cve_ref {
                    if let Some(cvss3) = cve["metrics"]["cvssMetricV31"]
                        .as_array()
                        .and_then(|a| a.first())
                        .or_else(|| {
                            cve["metrics"]["cvssMetricV30"]
                                .as_array()
                                .and_then(|a| a.first())
                        })
                    {
                        // vector/score
                        if f.cvss.is_none() {
                            if let (Some(base), Some(vector)) = (
                                cvss3["cvssData"]["baseScore"].as_f64(),
                                cvss3["cvssData"]["vectorString"].as_str(),
                            ) {
                                let base_f = base as f32;
                                f.cvss = Some(CvssInfo {
                                    base: base_f,
                                    vector: vector.to_string(),
                                });
                                if f.severity.is_none() {
                                    f.severity = Some(severity_from_score(base_f).to_string());
                                }
                            }
                        }
                        // explicit severity if provided
                        if f.severity.is_none() {
                            if let Some(sev) = cvss3["cvssData"]["baseSeverity"]
                                .as_str()
                                .or_else(|| cvss3["baseSeverity"].as_str())
                            {
                                f.severity = Some(sev.to_uppercase());
                            }
                        }
                    } else if let Some(cvss2) = cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                    {
                        if f.cvss.is_none() {
                            if let Some(base) = cvss2["cvssData"]["baseScore"].as_f64() {
                                let base_f = base as f32;
                                let vector = cvss2["cvssData"]["vectorString"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string();
                                f.cvss = Some(CvssInfo {
                                    base: base_f,
                                    vector,
                                });
                                if f.severity.is_none() {
                                    f.severity = Some(severity_from_score(base_f).to_string());
                                }
                            }
                        }
                        if f.severity.is_none() {
                            if let Some(sev) = cvss2["baseSeverity"].as_str() {
                                f.severity = Some(sev.to_uppercase());
                            }
                        }
                    }
                    if f.description.is_none() {
                        let desc = cve["descriptions"]
                            .as_array()
                            .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                            .and_then(|d| d["value"].as_str())
                            .map(|s| s.to_string());
                        f.description = desc;
                    }
                    if let Some(refs) = cve["references"]["referenceData"].as_array() {
                        for r in refs {
                            if let Some(url) = r["url"].as_str() {
                                f.references.push(ReferenceInfo {
                                    reference_type: "nvd".into(),
                                    url: url.into(),
                                });
                            }
                        }
                    }
            }
        }
    }
    progress_timing("nvd.enrich.apply", apply_started);
}

/// Query NVD by keyword (component + version) and map to findings. Useful fallback when OSV has no package context.
pub fn nvd_keyword_findings(
    component: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(&keyword)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("kw:{}", keyword), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .map(|s| s.to_string());

            // Prefer CVSS v3.1, then v3.0, then v2
            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|a| a.first())
                .or_else(|| {
                    cve["metrics"]["cvssMetricV30"]
                        .as_array()
                        .and_then(|a| a.first())
                })
                .or_else(|| {
                    cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                })
            {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                cvss = Some(CvssInfo {
                    base,
                    vector: vector.clone(),
                });
                severity = Some(severity_from_score(base).to_string());
            }

            let evidence = vec![EvidenceItem {
                evidence_type: "hint".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(format!("keyword match: {} {}", component, version)),
            }];

            let mut references: Vec<ReferenceInfo> = Vec::new();
            if let Some(refs) = cve["references"]["referenceData"].as_array() {
                for r in refs {
                    if let Some(url) = r["url"].as_str() {
                        references.push(ReferenceInfo {
                            reference_type: "nvd".into(),
                            url: url.to_string(),
                        });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:keyword:{} {}", component, version)],
                package: Some(PackageInfo {
                    name: component.to_string(),
                    ecosystem: "nvd".into(),
                    version: version.to_string(),
                }),
                confidence_tier: ConfidenceTier::HeuristicUnverified,
                evidence_source: EvidenceSource::BinaryHeuristic,
                accuracy_note: Some(
                    "Derived via keyword heuristic; installed package inventory was not proven."
                        .into(),
                ),
                fixed: None,
                fixed_in: None,
                recommendation: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("MEDIUM".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
        }
    }
    out
}

/// Query NVD by CPE name constructed from component/version (best-effort)
pub fn nvd_cpe_findings(
    component: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let vendor = component.to_lowercase();
    let product = component.to_lowercase();
    let cpe = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}",
        urlencoding::encode(&cpe)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("cpe:{}", cpe), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .map(|s| s.to_string());

            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|a| a.first())
                .or_else(|| {
                    cve["metrics"]["cvssMetricV30"]
                        .as_array()
                        .and_then(|a| a.first())
                })
                .or_else(|| {
                    cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                })
            {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                cvss = Some(CvssInfo {
                    base,
                    vector: vector.clone(),
                });
                severity = Some(severity_from_score(base).to_string());
            }

            let evidence = vec![EvidenceItem {
                evidence_type: "cpe".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(cpe.clone()),
            }];

            let mut references: Vec<ReferenceInfo> = Vec::new();
            if let Some(refs) = cve["references"]["referenceData"].as_array() {
                for r in refs {
                    if let Some(url) = r["url"].as_str() {
                        references.push(ReferenceInfo {
                            reference_type: "nvd".into(),
                            url: url.to_string(),
                        });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:cpe:{} {}", component, version)],
                package: Some(PackageInfo {
                    name: component.to_string(),
                    ecosystem: "nvd".into(),
                    version: version.to_string(),
                }),
                confidence_tier: ConfidenceTier::HeuristicUnverified,
                evidence_source: EvidenceSource::BinaryHeuristic,
                accuracy_note: Some(
                    "Derived via CPE heuristic; installed package inventory was not proven.".into(),
                ),
                fixed: None,
                fixed_in: None,
                recommendation: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("MEDIUM".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
        }
    }
    out
}

/// NVD keyword search by name only (low confidence). Useful when version unknown or not indexed.
pub fn nvd_keyword_findings_name(
    component: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(component)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("kw_only:{}", component), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .map(|s| s.to_string());

            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|a| a.first())
                .or_else(|| {
                    cve["metrics"]["cvssMetricV30"]
                        .as_array()
                        .and_then(|a| a.first())
                })
                .or_else(|| {
                    cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                })
            {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                cvss = Some(CvssInfo {
                    base,
                    vector: vector.clone(),
                });
                severity = Some(severity_from_score(base).to_string());
            }

            let evidence = vec![EvidenceItem {
                evidence_type: "hint".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(format!("keyword match: {}", component)),
            }];

            let mut references: Vec<ReferenceInfo> = Vec::new();
            if let Some(refs) = cve["references"]["referenceData"].as_array() {
                for r in refs {
                    if let Some(url) = r["url"].as_str() {
                        references.push(ReferenceInfo {
                            reference_type: "nvd".into(),
                            url: url.to_string(),
                        });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:keyword:{}", component)],
                package: Some(PackageInfo {
                    name: component.to_string(),
                    ecosystem: "nvd".into(),
                    version: "unknown".into(),
                }),
                confidence_tier: ConfidenceTier::HeuristicUnverified,
                evidence_source: EvidenceSource::BinaryHeuristic,
                accuracy_note: Some(
                    "Derived via keyword heuristic; installed package inventory was not proven."
                        .into(),
                ),
                fixed: None,
                fixed_in: None,
                recommendation: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("LOW".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
        }
    }
    out
}


/// Broader NVD search for vendor/product and filter by version ranges in CPEs
pub fn nvd_findings_by_product_version(
    vendor: &str,
    product: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=2000",
        urlencoding::encode(product)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("prod:{}", product), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        'outer: for item in items {
            let cve = &item["cve"];
            let mut matches_product = false;
            if let Some(nodes) = cve["configurations"]
                .get("nodes")
                .and_then(|n| n.as_array())
            {
                for node in nodes {
                    if let Some(cpes) = node.get("cpeMatch").and_then(|m| m.as_array()) {
                        for c in cpes {
                            let criteria = c.get("criteria").and_then(|s| s.as_str()).unwrap_or("");
                            if let Some((ven, prod, ver_opt)) = cpe_parts(criteria) {
                                if ven.eq_ignore_ascii_case(vendor)
                                    && prod.eq_ignore_ascii_case(product)
                                {
                                    matches_product = true;
                                    let vulnerable = c
                                        .get("vulnerable")
                                        .and_then(|b| b.as_bool())
                                        .unwrap_or(false);
                                    if !vulnerable {
                                        continue;
                                    }
                                    let start_inc =
                                        c.get("versionStartIncluding").and_then(|s| s.as_str());
                                    let start_exc =
                                        c.get("versionStartExcluding").and_then(|s| s.as_str());
                                    let end_inc =
                                        c.get("versionEndIncluding").and_then(|s| s.as_str());
                                    let end_exc =
                                        c.get("versionEndExcluding").and_then(|s| s.as_str());
                                    // If criteria has exact version and no ranges, compare directly
                                    if start_inc.is_none()
                                        && start_exc.is_none()
                                        && end_inc.is_none()
                                        && end_exc.is_none()
                                    {
                                        if let Some(ver) = ver_opt.as_deref() {
                                            if ver != "*"
                                                && cmp_versions(version, ver)
                                                    != std::cmp::Ordering::Equal
                                            {
                                                continue;
                                            }
                                        }
                                    } else {
                                        if !is_version_in_range(
                                            version, start_inc, start_exc, end_inc, end_exc,
                                        ) {
                                            continue;
                                        }
                                    }

                                    // Build finding
                                    let id = cve["id"].as_str().unwrap_or("unknown").to_string();
                                    let description = cve["descriptions"]
                                        .as_array()
                                        .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                                        .and_then(|d| d["value"].as_str())
                                        .map(|s| s.to_string());
                                    let mut cvss: Option<CvssInfo> = None;
                                    let mut severity: Option<String> = None;
                                    if let Some(m) = cve["metrics"]["cvssMetricV31"]
                                        .as_array()
                                        .and_then(|a| a.first())
                                        .or_else(|| {
                                            cve["metrics"]["cvssMetricV30"]
                                                .as_array()
                                                .and_then(|a| a.first())
                                        })
                                        .or_else(|| {
                                            cve["metrics"]["cvssMetricV2"]
                                                .as_array()
                                                .and_then(|a| a.first())
                                        })
                                    {
                                        let base =
                                            m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0)
                                                as f32;
                                        let vector = m["cvssData"]["vectorString"]
                                            .as_str()
                                            .unwrap_or("")
                                            .to_string();
                                        cvss = Some(CvssInfo {
                                            base,
                                            vector: vector.clone(),
                                        });
                                        severity = Some(severity_from_score(base).to_string());
                                    }
                                    let evidence = vec![EvidenceItem {
                                        evidence_type: "cpe".into(),
                                        path: evidence_path.map(|s| s.to_string()),
                                        detail: Some(criteria.to_string()),
                                    }];
                                    let mut references: Vec<ReferenceInfo> = Vec::new();
                                    if let Some(refs) =
                                        cve["references"]["referenceData"].as_array()
                                    {
                                        for r in refs {
                                            if let Some(url) = r["url"].as_str() {
                                                references.push(ReferenceInfo {
                                                    reference_type: "nvd".into(),
                                                    url: url.to_string(),
                                                });
                                            }
                                        }
                                    }
                                    out.push(Finding {
                                        id,
                                        source_ids: vec![format!(
                                            "heuristic:product:{} {} {}",
                                            vendor, product, version
                                        )],
                                        package: Some(PackageInfo {
                                            name: product.to_string(),
                                            ecosystem: "nvd".into(),
                                            version: version.to_string(),
                                        }),
                                        confidence_tier: ConfidenceTier::HeuristicUnverified,
                                        evidence_source: EvidenceSource::BinaryHeuristic,
                                        accuracy_note: Some(
                                            "Derived via product/version heuristic; installed package inventory was not proven."
                                                .into(),
                                        ),
                                        fixed: None,
                                        fixed_in: None,
                                        recommendation: None,
                                        severity,
                                        cvss,
                                        description,
                                        evidence,
                                        references,
                                        confidence: Some("MEDIUM".into()),
                                        epss_score: None,
                                        epss_percentile: None,
                                        in_kev: None,
                                    });
                                    continue 'outer;
                                }
                            }
                        }
                    }
                }
            }
            let _ = matches_product; // silence warning if unused
        }
    }
    out
}




/// Pre-warm all distro advisory feeds (Ubuntu USN, Alpine SecDB) into the local cache.
pub fn seed_distro_feeds() {
    progress("seed.distro.ubuntu.start", "");
    let _ubuntu = load_ubuntu_notices_data();
    progress("seed.distro.ubuntu.done", "ok");
    progress("seed.distro.alpine.start", "");
    for branch in alpine_secdb_branches() {
        for repo in &["main", "community"] {
            let _alpine = load_alpine_secdb(&branch, repo);
        }
    }
    progress("seed.distro.alpine.done", "ok");
}

#[cfg(test)]
mod tests;
