use std::collections::{HashMap, HashSet};

use postgres::Client as PgClient;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::report::{Finding, ReferenceInfo};
use crate::utils::{progress, progress_timing};

use super::env_bool;
use super::http::{build_http_client, cached_http_json};
use super::pg::{pg_get_osv, resolve_enrich_cache_dir};
use super::version::cmp_versions;

pub(super) fn map_debian_advisory_to_cves(
    advisory_id: &str,
    pg: &mut Option<PgClient>,
) -> Option<Vec<String>> {
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
                progress(
                    "osv.debian.map.pg_hit",
                    &format!("{} -> {} CVEs", advisory_id, cves.len()),
                );
                return Some(cves.into_iter().collect());
            }
        }
    }

    // 2. Cross-reference: extract package name from OSV payload, look up CVEs
    //    in debian_tracker_cache (bulk-imported from Debian tracker JSON).
    //    This avoids expensive HTTP scraping of security-tracker.debian.org.
    if let Some(client_pg) = pg.as_mut() {
        // Get the package name(s) from the advisory's OSV affected[] field
        let mut pkg_names: Vec<String> = Vec::new();
        if let Some((payload, _, _)) = pg_get_osv(client_pg, advisory_id) {
            if let Some(affected) = payload["affected"].as_array() {
                for aff in affected {
                    if let Some(name) = aff["package"]["name"].as_str() {
                        if !name.is_empty() && !pkg_names.contains(&name.to_string()) {
                            pkg_names.push(name.to_string());
                        }
                    }
                }
            }
        }
        if !pkg_names.is_empty() {
            let mut cves: HashSet<String> = HashSet::new();
            for pkg in &pkg_names {
                if let Ok(rows) = client_pg.query(
                    "SELECT DISTINCT cve_id FROM debian_tracker_cache WHERE package = $1",
                    &[pkg],
                ) {
                    for row in &rows {
                        let cve_id: String = row.get(0);
                        cves.insert(cve_id);
                    }
                }
            }
            if !cves.is_empty() {
                let result: Vec<String> = cves.into_iter().collect();
                progress(
                    "osv.debian.map.tracker_cache",
                    &format!("{} ({}) -> {} CVEs", advisory_id, pkg_names.join(","), result.len()),
                );
                // Update osv_vuln_cache aliases so step 1 hits next time
                if let Some((mut payload, _, _)) = pg_get_osv(client_pg, advisory_id) {
                    let aliases_arr: Vec<serde_json::Value> = result
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect();
                    payload["aliases"] = serde_json::Value::Array(aliases_arr);
                    let _ = client_pg.execute(
                        "UPDATE osv_vuln_cache SET payload = $1::jsonb WHERE vuln_id = $2",
                        &[&payload.to_string(), &advisory_id],
                    );
                }
                return Some(result);
            }
        }
    }

    // 3. Check file cache
    let cache_dir = resolve_enrich_cache_dir();
    let cache_key_str = cache_key(&["debian_advisory_map", advisory_id]);
    if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_key_str) {
        if let Ok(arr) = serde_json::from_slice::<Vec<String>>(&bytes) {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
    }

    // 4. Last resort: fetch Debian tracker HTML page
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
    let mut set: HashSet<String> = HashSet::new();
    for m in re.find_iter(&body) {
        set.insert(m.as_str().to_string());
    }
    let result: Vec<String> = set.into_iter().collect();

    if !result.is_empty() {
        if let Ok(json_bytes) = serde_json::to_vec(&result) {
            cache_put(cache_dir.as_deref(), &cache_key_str, &json_bytes);
        }
    }

    Some(result)
}

#[derive(Debug, Clone)]
pub(super) struct DistroFixCandidate {
    pub(super) fixed_version: String,
    pub(super) source_id: String,
    pub(super) reference_url: String,
    pub(super) note: String,
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

pub(super) fn is_cve_id(id: &str) -> bool {
    id.starts_with("CVE-")
}

pub(super) fn pkg_cve_key(pkg: &str, cve: &str) -> String {
    format!("{}|{}", pkg.to_ascii_lowercase(), cve.to_ascii_uppercase())
}

pub(super) fn select_best_candidate(
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

pub(super) fn build_ubuntu_candidate_index(
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
                    reference_url: format!(
                        "https://security-tracker.debian.org/tracker/{}",
                        cve_id
                    ),
                    note: format!(
                        "Debian tracker (PG cache) source={} status={} fixed_version={}",
                        source,
                        status.as_deref().unwrap_or("unknown"),
                        fv
                    ),
                });
            }
        }
    }
    progress("distro.debian.pg_hit", &format!("{} candidates", out.len()));
    Some(out)
}

/// Query ubuntu_usn_cache in PG for needed package/CVE pairs instead of downloading bulk JSON.
pub(super) fn build_ubuntu_candidate_index_pg(
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
                "SELECT cve_id, release, status, fixed_version FROM ubuntu_usn_cache WHERE package = $1 AND status = 'released'",
                &[&pkg],
            )
            .ok()?;
        for row in &rows {
            let cve_id: String = row.get(0);
            let _release: String = row.get(1);
            let _status: Option<String> = row.get(2);
            let fixed_version: Option<String> = row.get(3);
            let key = pkg_cve_key(pkg, &cve_id);
            if !needed_keys.contains(&key) {
                continue;
            }
            // Use the fixed_version column (populated by bulk import). Skip if absent.
            let fv = fixed_version.unwrap_or_default();
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

/// Query alpine_secdb_cache in PG for needed package/CVE pairs instead of downloading bulk JSON.
fn build_alpine_candidate_index_pg(
    pg: &mut Option<PgClient>,
    needed_keys: &HashSet<String>,
    needed_pkgs: &HashSet<String>,
) -> Option<HashMap<String, Vec<DistroFixCandidate>>> {
    let client_pg = pg.as_mut()?;
    let mut out: HashMap<String, Vec<DistroFixCandidate>> = HashMap::new();
    for pkg in needed_pkgs {
        let rows = client_pg
            .query(
                "SELECT cve_id, branch, repo, fixed_version FROM alpine_secdb_cache WHERE package = $1",
                &[&pkg],
            )
            .ok()?;
        for row in &rows {
            let cve_id: String = row.get(0);
            let branch: String = row.get(1);
            let repo: String = row.get(2);
            let fixed_version: Option<String> = row.get(3);
            let key = pkg_cve_key(pkg, &cve_id);
            if !needed_keys.contains(&key) {
                continue;
            }
            let fv = fixed_version.unwrap_or_default();
            if fv.is_empty() {
                continue;
            }
            out.entry(key).or_default().push(DistroFixCandidate {
                fixed_version: fv.clone(),
                source_id: format!("alpine-secdb:{}:{}", branch, repo),
                reference_url: format!(
                    "https://secdb.alpinelinux.org/{}/{}.json",
                    branch, repo
                ),
                note: format!(
                    "Alpine SecDB (PG cache) branch={} repo={} package={}",
                    branch, repo, pkg
                ),
            });
        }
    }
    progress("distro.alpine.pg_hit", &format!("{} candidates", out.len()));
    Some(out)
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

pub(super) fn distro_feed_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
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
        if pkg.ecosystem == "deb" || pkg.ecosystem == "ubuntu-deb" {
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
        let idx = build_ubuntu_candidate_index_pg(pg, &needed_ubuntu_keys).unwrap_or_else(|| {
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
        let idx = build_debian_candidate_index_pg(pg, &needed_deb).unwrap_or_else(|| {
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
        let idx = build_alpine_candidate_index_pg(pg, &needed_alpine_keys, &needed_apk_pkgs)
            .unwrap_or_else(|| {
                build_alpine_candidate_index(&needed_alpine_keys, &needed_apk_pkgs, &needed_apk_cves)
            });
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

        if ecosystem != "deb" && ecosystem != "ubuntu-deb" {
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
