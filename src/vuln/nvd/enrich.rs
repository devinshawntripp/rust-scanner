use chrono::{Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use serde_json::Value;

use crate::report::{severity_from_score, CvssInfo, Finding, ReferenceInfo};
use crate::utils::{progress, progress_timing};

use super::super::env_bool;
use super::super::http::nvd_get_json;
use super::super::pg::{
    compute_jittered_ttl_days, parse_nvd_last_modified, pg_get_cve, pg_init_schema, pg_put_cve,
};

pub fn enrich_findings_with_nvd(
    findings: &mut Vec<Finding>,
    api_key: Option<&str>,
    pg: &mut Option<PgClient>,
    breaker: &crate::vuln::CircuitBreaker,
) {
    if !env_bool("SCANNER_NVD_ENRICH", true) {
        progress("nvd.fetch.skip", "disabled by SCANNER_NVD_ENRICH");
        return;
    }
    if findings.is_empty() {
        return;
    }
    if breaker.is_open() {
        progress(
            "nvd.enrich.skip",
            &format!("circuit_open source={}", breaker.source_name()),
        );
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
    let base_ttl_days: i64 = std::env::var("SCANNER_NVD_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);

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
    progress(
        "nvd.enrich.cache_lookup.start",
        &format!("{} CVEs to check", total),
    );
    let mut cached_count: usize = 0;
    for (idx, id) in unique_ids.into_iter().enumerate() {
        let mut served_from_cache = false;
        if let Some(client) = pg.as_mut() {
            if let Some((payload, last_checked_at, nvd_last_modified)) = pg_get_cve(client, &id) {
                // In cluster mode, trust the PG cache unconditionally — the
                // vulndb-pg-import CronJob (every 6h) keeps it current via
                // incremental NVD API fetches. No per-CVE TTL needed.
                if crate::vuln::cluster_mode() {
                    id_to_json.insert(id.clone(), payload);
                    progress("nvd.cache.pg.hit", &id);
                    served_from_cache = true;
                    cached_count += 1;
                } else {
                    // Standalone mode: age-aware TTL for file-cache populated data.
                    let age_factor = if let Some(lm) = nvd_last_modified {
                        let age_days = (Utc::now() - lm).num_days();
                        if age_days > 730 { 3 } else if age_days > 365 { 2 } else { 1 }
                    } else {
                        1
                    };
                    let effective_ttl = base_ttl_days * age_factor;
                    let ttl_dyn_days = compute_jittered_ttl_days(effective_ttl, 7);
                    if Utc::now() - last_checked_at < ChronoDuration::days(ttl_dyn_days) {
                        id_to_json.insert(id.clone(), payload);
                        progress("nvd.cache.pg.hit", &id);
                        served_from_cache = true;
                        cached_count += 1;
                    }
                }
            }
        }
        if !served_from_cache {
            to_fetch.push((idx, id));
        }
        if (idx + 1) % 50 == 0 || idx + 1 == total {
            progress(
                "nvd.enrich.cache_lookup.progress",
                &format!("{}/{}", idx + 1, total),
            );
        }
    }
    let to_fetch_count = to_fetch.len();
    progress(
        "nvd.enrich.cache_lookup.done",
        &format!("{} cached, {} to fetch", cached_count, to_fetch_count),
    );
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
        let fetched: Vec<(String, Value, Option<chrono::DateTime<Utc>>)> = pool.install(|| {
            to_fetch
                .par_iter()
                .filter_map(|(idx, id)| {
                    // Skip if circuit is open (checked per-thread using atomics)
                    if breaker.is_open() {
                        return None;
                    }
                    progress("nvd.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
                    let url = format!(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
                        id
                    );
                    match nvd_get_json(&url, api_key, &format!("cveId:{}", id), sleep_ms) {
                        Some(json) => {
                            let lm = parse_nvd_last_modified(&json);
                            breaker.record_success();
                            Some((id.clone(), json, lm))
                        }
                        None => {
                            progress("nvd.fetch.err", id);
                            breaker.record_failure();
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
            // Check circuit before each attempt in sequential path
            if breaker.is_open() {
                progress(
                    "nvd.fetch.skip",
                    &format!("circuit_open source={} id={}", breaker.source_name(), id),
                );
                break;
            }
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
                    breaker.record_success();
                    progress("nvd.fetch.ok", &id);
                }
                None => {
                    progress("nvd.fetch.err", &id);
                    breaker.record_failure();
                }
            }
        }
    }
    progress_timing("nvd.enrich.fetch", fetch_started);

    // Apply enrichment
    let apply_started = std::time::Instant::now();
    for f in findings.iter_mut() {
        if !id_to_json.contains_key(&f.id) {
            if let Some(client) = pg.as_mut() {
                if let Some((payload, _lc, _lm)) = pg_get_cve(client, &f.id) {
                    id_to_json.insert(f.id.clone(), payload);
                }
            }
        }
        if let Some(wrapper) = id_to_json.get(&f.id) {
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
