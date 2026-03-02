use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::redhat::{compare_evr, is_rpm_ecosystem};
use crate::report::{
    ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding, PackageInfo, ReferenceInfo,
};
use crate::utils::{progress, progress_timing};

use super::cluster_mode;
use super::cvss::normalize_redhat_severity;
use super::env_bool;
use super::http::build_http_client;
use super::pg::resolve_enrich_cache_dir;
use super::pg::{
    compute_dynamic_ttl_days, parse_redhat_cve_last_modified, parse_redhat_last_modified,
    pg_get_redhat, pg_get_redhat_cve, pg_get_rhel_cves, pg_init_schema, pg_put_redhat,
    pg_put_redhat_cve, pg_put_rhel_cve,
};

pub(super) fn normalize_redhat_errata_id(id: &str) -> String {
    id.trim()
        .to_ascii_uppercase()
        .replace("%3A", ":")
        .replace("%3a", ":")
}

pub(super) fn retain_relevant_redhat_source_ids(source_ids: &mut Vec<String>, keep: Option<&str>) {
    source_ids.retain(|sid| {
        let norm = normalize_redhat_errata_id(sid);
        if is_redhat_errata_id(&norm) {
            return keep.map(|k| norm.eq_ignore_ascii_case(k)).unwrap_or(false);
        }
        true
    });
}

pub(super) fn extract_redhat_errata_from_url(url: &str) -> Option<String> {
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

pub(super) fn retain_relevant_redhat_references(refs: &mut Vec<ReferenceInfo>, keep: Option<&str>) {
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

pub(super) fn is_redhat_family_ecosystem(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "redhat" | "rpm" | "centos" | "rocky" | "almalinux"
    )
}

pub(super) fn normalize_reference_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    urlencoding::decode(trimmed)
        .map(|v| v.into_owned())
        .unwrap_or_else(|_| trimmed.to_string())
}

pub(super) fn append_unique_references(dest: &mut Vec<ReferenceInfo>, refs: Vec<ReferenceInfo>) {
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

pub(super) fn is_redhat_errata_id(id: &str) -> bool {
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

pub(super) fn redhat_cvss_from_vuln(vuln: &Value) -> Option<CvssInfo> {
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

pub(super) fn redhat_note_text(document: &Value) -> Option<String> {
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
pub(super) struct RedHatFixedRelease {
    pub(super) advisory: Option<String>,
    pub(super) package_name: String,
    pub(super) fixed_evr: String,
}

#[derive(Debug, Clone)]
pub(super) struct RedHatPackageState {
    package_name: String,
    fix_state: String,
    cpe: Option<String>,
}

pub(super) fn parse_redhat_release_package(raw: &str) -> Option<(String, String)> {
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

pub(super) fn parse_redhat_package_states(json: &Value) -> Vec<RedHatPackageState> {
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

pub(super) fn parse_redhat_cve_cvss(json: &Value) -> Option<CvssInfo> {
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

pub(super) fn redhat_cve_references(json: &Value) -> Vec<ReferenceInfo> {
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

pub(super) fn rpm_epoch(evr: &str) -> i64 {
    evr.split_once(':')
        .and_then(|(lhs, _)| lhs.parse::<i64>().ok())
        .unwrap_or(0)
}

pub(super) fn extract_el_tag(text: &str) -> Option<String> {
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

pub(super) fn extract_rhel_major_from_cpe(cpe: &str) -> Option<String> {
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

pub(super) fn extract_rhel_major_from_version(version: &str) -> Option<String> {
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

pub(super) fn strip_rpm_arch_suffix(name: &str) -> String {
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

pub(super) fn package_name_matches(installed: &str, candidate: &str) -> bool {
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

pub(super) fn parse_redhat_fixed_releases(json: &Value) -> Vec<RedHatFixedRelease> {
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

pub(super) fn best_redhat_fixed_release(
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

pub(super) fn best_redhat_package_state(
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

pub(super) fn redhat_enrich_cve_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
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

pub(super) fn redhat_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
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
        progress(
            "redhat.pkg.cve.skip",
            "disabled by SCANNER_REDHAT_UNFIXED_SKIP",
        );
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
            let unfixed_states_set: HashSet<&str> = ["affected", "fix deferred", "will not fix"]
                .iter()
                .copied()
                .collect();
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
            query_to_packages.entry(qname).or_default().push((
                pkg.name.clone(),
                pkg.version.clone(),
                pkg.ecosystem.clone(),
            ));
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
        let Some(pkg_attribs) = query_to_packages.get(&qname) else {
            continue;
        };
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
        progress(
            "redhat.pkg.cve.done",
            "injected=0 (no new CVEs from pkg list)",
        );
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

    // Fetch cache misses in batches with rate-limit protection.
    if !to_fetch.is_empty() {
        let sleep_ms: u64 = std::env::var("SCANNER_REDHAT_SLEEP_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let max_fetch: usize = std::env::var("SCANNER_REDHAT_PKG_CVE_MAX_FETCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);

        if to_fetch.len() > max_fetch {
            progress(
                "redhat.pkg.cve.fetch.cap",
                &format!(
                    "capping fetch from {} to {} (set SCANNER_REDHAT_PKG_CVE_MAX_FETCH to adjust)",
                    to_fetch.len(),
                    max_fetch
                ),
            );
            to_fetch.truncate(max_fetch);
        }

        let total_to_fetch = to_fetch.len();
        progress(
            "redhat.pkg.cve.fetch",
            &format!("fetching={}/{}", total_to_fetch, total_new),
        );

        let fetched_count = std::sync::atomic::AtomicUsize::new(0);
        let batch_size = 200;

        for batch_start in (0..total_to_fetch).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(total_to_fetch);
            let batch = &to_fetch[batch_start..batch_end];

            let fetch_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(max_concurrent)
                .build()
                .ok();

            let batch_results: Vec<(String, Value, Option<DateTime<Utc>>)> =
                if let Some(pool) = fetch_pool {
                    pool.install(|| {
                        batch
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
                                let local_client = build_http_client(timeout_secs);
                                match local_client.get(&url).send() {
                                    Ok(resp) if resp.status().is_success() => {
                                        match resp.json::<Value>() {
                                            Ok(v) => {
                                                let lm = parse_redhat_cve_last_modified(&v);
                                                let bytes =
                                                    serde_json::to_vec(&v).unwrap_or_default();
                                                if !bytes.is_empty() {
                                                    let cd = resolve_enrich_cache_dir();
                                                    cache_put(cd.as_deref(), &cache_tag, &bytes);
                                                }
                                                fetched_count.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
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
            for (id, json, lm) in batch_results {
                if let Some(c) = pg.as_mut() {
                    pg_put_redhat_cve(c, &id, &json, lm);
                }
                id_to_json.insert(id, json);
            }

            let done = fetched_count.load(std::sync::atomic::Ordering::Relaxed);
            progress(
                "redhat.pkg.cve.fetch.progress",
                &format!("{}/{} fetched", done, total_to_fetch),
            );
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
            let best_state: Option<&RedHatPackageState> = if let Some(ref rhel_str) = rhel_major_str
            {
                // Only accept an entry matching both package name AND this RHEL version via CPE.
                package_states.iter().find(|s| {
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
                    pg_put_rhel_cve(
                        c, &f.id, &pkg.name, rhel_ver, "unfixed", fix_state, advisory,
                    );
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
