use std::collections::HashMap;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::redhat::{compare_evr, is_rpm_ecosystem};
use crate::report::Finding;
use crate::utils::{progress, progress_timing};

use super::super::cvss::normalize_redhat_severity;
use super::super::env_bool;
use super::super::http::build_http_client;
use super::super::pg::{
    compute_dynamic_ttl_days, parse_redhat_cve_last_modified, pg_get_redhat_cve, pg_init_schema,
    pg_put_redhat_cve,
};
use super::helpers::{
    append_unique_references, best_redhat_fixed_release, best_redhat_package_state,
    is_redhat_family_ecosystem, parse_redhat_cve_cvss, parse_redhat_fixed_releases,
    parse_redhat_package_states, redhat_cve_references, retain_relevant_redhat_references,
    retain_relevant_redhat_source_ids,
};

pub(in crate::vuln) fn redhat_enrich_cve_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
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
    let mut cached_pg = 0usize;
    let mut cached_file = 0usize;

    let redhat_cve_started = std::time::Instant::now();
    for (idx, cve_id) in ids.iter().enumerate() {
        if (idx + 1) % 50 == 0 || idx + 1 == total {
            progress(
                "redhat.cve.lookup",
                &format!("{}/{}", idx + 1, total),
            );
        }

        let cache_tag = cache_key(&["redhat_cve", cve_id]);
        let mut json: Option<Value> = None;

        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_redhat_cve(client_pg, cve_id) {
                let ttl_dyn_days = compute_dynamic_ttl_days(last_mod, ttl_days);
                if Utc::now() - last_checked < ChronoDuration::days(ttl_dyn_days) {
                    json = Some(payload);
                    cached_pg += 1;
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
                    cached_file += 1;
                }
            }
        }

        if let Some(v) = json {
            id_to_json.insert(cve_id.clone(), v);
        } else {
            to_fetch.push(cve_id.clone());
        }
    }
    progress(
        "redhat.cve.cache_lookup.done",
        &format!("{} pg_cached, {} file_cached, {} to fetch", cached_pg, cached_file, to_fetch.len()),
    );

    if !to_fetch.is_empty() {
        let fetch_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_concurrent)
            .build()
            .ok();
        let fetched: Vec<(String, Value, Option<chrono::DateTime<Utc>>)> = if let Some(pool) = fetch_pool {
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

        let fetched_count = fetched.len();
        for (cve_id, cve_json, lm) in fetched {
            if let Some(client_pg) = pg.as_mut() {
                pg_put_redhat_cve(client_pg, &cve_id, &cve_json, lm);
            }
            id_to_json.insert(cve_id, cve_json);
        }
        progress("redhat.cve.fetch.done", &format!("fetched={}", fetched_count));
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
        let cvss = parse_redhat_cve_cvss(cve_json);
        let refs = redhat_cve_references(cve_json);
        let fixed_releases = parse_redhat_fixed_releases(cve_json);
        let package_states = parse_redhat_package_states(cve_json);

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
                        vec![crate::report::ReferenceInfo {
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
