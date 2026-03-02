use std::collections::{HashMap, HashSet};

use crate::cache::{cache_get, cache_key, cache_put};
use crate::report::Finding;
use crate::utils::{progress, progress_timing};
use serde_json::Value;

use super::pg::pg_connect;
use super::http::enrich_http_client;

fn epss_enrich_enabled() -> bool {
    std::env::var("SCANNER_EPSS_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Enrich findings with EPSS (Exploit Prediction Scoring System) scores.
/// Batch queries the FIRST.org EPSS API in groups of 100 CVE IDs.
pub fn epss_enrich_findings(findings: &mut [Finding], cache_dir: Option<&std::path::Path>) {
    if !epss_enrich_enabled() {
        progress("epss.enrich.skip", "disabled by SCANNER_EPSS_ENRICH");
        return;
    }
    let mut cve_ids: Vec<String> = findings
        .iter()
        .filter(|f| f.id.starts_with("CVE-"))
        .map(|f| f.id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    // Sort for stable chunking — without this the HashSet iteration order is random each run,
    // producing different chunk boundaries and non-matching cache keys on every scan.
    cve_ids.sort_unstable();
    if cve_ids.is_empty() {
        return;
    }
    progress("epss.enrich.start", &format!("cves={}", cve_ids.len()));
    let started = std::time::Instant::now();

    let mut scores: HashMap<String, (f32, f32)> = HashMap::new();

    // Try PostgreSQL cache first (bulk-populated by vulndb-pg-import CronJob)
    let mut pg_miss_ids: Vec<String> = Vec::new();
    if let Some(mut client) = pg_connect() {
        for chunk in cve_ids.chunks(500) {
            let params_str: String = chunk
                .iter()
                .enumerate()
                .map(|(i, _)| format!("${}", i + 1))
                .collect::<Vec<_>>()
                .join(",");
            let query = format!(
                "SELECT cve_id, score, percentile FROM epss_scores_cache WHERE cve_id IN ({})",
                params_str
            );
            let params: Vec<&(dyn postgres::types::ToSql + Sync)> =
                chunk.iter().map(|s| s as &(dyn postgres::types::ToSql + Sync)).collect();
            match client.query(&*query, &params) {
                Ok(rows) => {
                    let found: HashSet<String> = rows
                        .iter()
                        .filter_map(|row| {
                            let cve_id: String = row.get(0);
                            let score: f32 = row.get(1);
                            let percentile: f32 = row.get(2);
                            scores.insert(cve_id.clone(), (score, percentile));
                            Some(cve_id)
                        })
                        .collect();
                    for id in chunk {
                        if !found.contains(id) {
                            pg_miss_ids.push(id.clone());
                        }
                    }
                }
                Err(e) => {
                    progress("epss.enrich.pg_error", &format!("{}", e));
                    pg_miss_ids.extend(chunk.iter().cloned());
                }
            }
        }
        if !scores.is_empty() {
            progress(
                "epss.enrich.pg_hit",
                &format!("hit={} miss={}", scores.len(), pg_miss_ids.len()),
            );
        }
    } else {
        pg_miss_ids = cve_ids.clone();
    }

    // Fall back to FIRST.org API for misses
    for chunk in pg_miss_ids.chunks(100) {
        let cache_k = cache_key(
            &std::iter::once("epss_v1")
                .chain(chunk.iter().map(|s| s.as_str()))
                .collect::<Vec<_>>(),
        );
        if let Some(cached) = cache_get(cache_dir, &cache_k) {
            if let Ok(map) = serde_json::from_slice::<HashMap<String, (f32, f32)>>(&cached) {
                scores.extend(map);
                continue;
            }
        }

        let cve_param = chunk.join(",");
        let url = format!("https://api.first.org/data/v1/epss?cve={}", cve_param);
        match enrich_http_client().get(&url).send() {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<Value>() {
                    let mut chunk_scores: HashMap<String, (f32, f32)> = HashMap::new();
                    if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
                        for entry in data {
                            let cve = entry
                                .get("cve")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            let score = entry
                                .get("epss")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<f32>().ok())
                                .or_else(|| {
                                    entry.get("epss").and_then(|v| v.as_f64()).map(|f| f as f32)
                                });
                            let percentile = entry
                                .get("percentile")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<f32>().ok())
                                .or_else(|| {
                                    entry
                                        .get("percentile")
                                        .and_then(|v| v.as_f64())
                                        .map(|f| f as f32)
                                });
                            if let (Some(s), Some(p)) = (score, percentile) {
                                chunk_scores.insert(cve.to_string(), (s, p));
                            }
                        }
                    }
                    if let Ok(serialized) = serde_json::to_vec(&chunk_scores) {
                        cache_put(cache_dir, &cache_k, &serialized);
                    }
                    scores.extend(chunk_scores);
                }
            }
            Ok(resp) => {
                progress(
                    "epss.enrich.http_error",
                    &format!("status={}", resp.status()),
                );
            }
            Err(e) => {
                progress("epss.enrich.error", &format!("{}", e));
            }
        }
    }

    let mut enriched = 0usize;
    for finding in findings.iter_mut() {
        if let Some(&(score, percentile)) = scores.get(&finding.id) {
            finding.epss_score = Some(score);
            finding.epss_percentile = Some(percentile);
            enriched += 1;
        }
    }
    progress_timing("epss.enrich", started);
    progress(
        "epss.enrich.done",
        &format!("enriched={}/{}", enriched, findings.len()),
    );
}
