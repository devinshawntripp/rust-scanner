use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::redhat::is_rpm_ecosystem;
use crate::report::{ConfidenceTier, EvidenceSource, Finding, PackageInfo, ReferenceInfo};
use crate::utils::{progress, progress_timing};

use super::super::cluster_mode;
use super::super::cvss::normalize_redhat_severity;
use super::super::env_bool;
use super::super::http::build_http_client;
use super::super::pg::{
    compute_dynamic_ttl_days, parse_redhat_cve_last_modified, pg_get_redhat_cve, pg_get_rhel_cves,
    pg_init_schema, pg_put_redhat_cve, pg_put_rhel_cve, resolve_enrich_cache_dir,
};
use super::helpers::{
    extract_rhel_major_from_cpe, package_name_matches, parse_redhat_cve_cvss,
    parse_redhat_package_states, redhat_cve_references,
};

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
    // Map query_name -> list of installed PackageCoordinate-like tuples.
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
            // Only process CVEs not already known to us -- known CVEs are already handled
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

    // Check file cache in parallel for PG misses -- per-CVE JSONs can be large,
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

            let batch_results: Vec<(String, Value, Option<chrono::DateTime<Utc>>)> =
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

    // Fix states that represent "unfixed but known" -- we want to show these.
    // "Out of support scope" is intentionally excluded: it applies to packages in
    // unsupported lifecycles on older RHEL streams and generates many false positives
    // when matched without a strict RHEL-version-specific CPE filter.
    let unfixed_states: &[&str] = &["affected", "fix deferred", "will not fix"];

    for (cve_id, attributed_packages) in &cve_to_packages {
        let Some(cve_json) = id_to_json.get(cve_id) else {
            continue; // No data available -- skip rather than emit unsupported finding.
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
            continue; // No package_state data -> can't confirm applicability.
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
            let best_state: Option<&super::helpers::RedHatPackageState> = if let Some(ref rhel_str) = rhel_major_str
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
                // No RHEL version detected -- match on package name only as last resort.
                package_states
                    .iter()
                    .find(|s| package_name_matches(installed_name, &s.package_name))
            };

            let Some(state) = best_state else {
                continue; // No applicable package_state for this package.
            };

            let state_lc = state.fix_state.to_ascii_lowercase();
            // Use exact match, NOT substring match -- "not affected".contains("affected") is true
            // and would incorrectly include "Not affected" packages.
            if !unfixed_states.iter().any(|u| state_lc == *u) {
                continue; // "Not affected" or other non-unfixed state -- skip.
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
