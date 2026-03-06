use std::collections::{HashMap, HashSet};

use crate::cache::{cache_get, cache_key, cache_put};
use crate::report::Finding;
use crate::utils::{progress, progress_timing};
use postgres::Client as PgClient;
use serde_json::Value;

use super::http::enrich_http_client;
use super::pg::{compute_jittered_ttl_days, pg_get_epss_scores, pg_put_epss_scores};

fn epss_enrich_enabled() -> bool {
    std::env::var("SCANNER_EPSS_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Fetch EPSS scores for a set of CVE IDs using the provided PG connection.
/// Returns a map of CVE ID -> (score, percentile).
fn fetch_epss_scores_with_pg(
    cve_ids: &[String],
    pg: &mut Option<PgClient>,
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) -> HashMap<String, (f32, f32)> {
    if !epss_enrich_enabled() {
        progress("epss.enrich.skip", "disabled by SCANNER_EPSS_ENRICH");
        return HashMap::new();
    }
    if breaker.is_open() {
        progress(
            "epss.enrich.skip",
            &format!("circuit_open source={}", breaker.source_name()),
        );
        return HashMap::new();
    }
    if cve_ids.is_empty() {
        return HashMap::new();
    }

    let mut sorted_ids: Vec<String> = cve_ids.iter().cloned().collect::<HashSet<_>>().into_iter().collect();
    sorted_ids.sort_unstable();

    progress("epss.enrich.start", &format!("cves={}", sorted_ids.len()));
    let started = std::time::Instant::now();

    let mut scores: HashMap<String, (f32, f32)> = HashMap::new();
    let mut api_ids: Vec<String> = sorted_ids.clone();

    // Cluster mode: check PG cache before calling live API
    if crate::vuln::cluster_mode() {
        if let Some(client) = pg.as_mut() {
            let ttl = compute_jittered_ttl_days(30, 7);
            let id_refs: Vec<&str> = sorted_ids.iter().map(|s| s.as_str()).collect();
            let pg_scores = pg_get_epss_scores(client, &id_refs, ttl);
            let hit_count = pg_scores.len();
            scores.extend(pg_scores);
            // Only request IDs that were not in PG
            api_ids = sorted_ids
                .iter()
                .filter(|id| !scores.contains_key(id.as_str()))
                .cloned()
                .collect();
            if hit_count > 0 {
                progress(
                    "epss.enrich.pg_hit",
                    &format!("hit={} miss={}", hit_count, api_ids.len()),
                );
            }
        }
    }

    // Standalone mode: check local vulndb for EPSS scores
    if !crate::vuln::cluster_mode() {
        if let Some(conn) = crate::vulndb::open_vulndb() {
            let mut db_hits = 0usize;
            let mut still_needed: Vec<String> = Vec::new();
            for id in &api_ids {
                if let Some((score, percentile)) = crate::vulndb::query_epss(&conn, id) {
                    scores.insert(id.clone(), (score, percentile));
                    db_hits += 1;
                } else {
                    still_needed.push(id.clone());
                }
            }
            if db_hits > 0 {
                progress(
                    "epss.enrich.vulndb_hit",
                    &format!("hit={} miss={}", db_hits, still_needed.len()),
                );
            }
            api_ids = still_needed;
        }
    }

    // Fetch remaining IDs from FIRST.org API (or all IDs in standalone mode)
    let mut api_fetched: Vec<(String, f32, f32)> = Vec::new();
    for chunk in api_ids.chunks(100) {
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
        // Check circuit breaker before each chunk HTTP request
        if breaker.is_open() {
            progress(
                "epss.enrich.chunk.skip",
                &format!("circuit_open source={}", breaker.source_name()),
            );
            break;
        }
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
                                api_fetched.push((cve.to_string(), s, p));
                            }
                        }
                    }
                    if !crate::vuln::cluster_mode() {
                        // Standalone mode: write to file cache
                        if let Ok(serialized) = serde_json::to_vec(&chunk_scores) {
                            cache_put(cache_dir, &cache_k, &serialized);
                        }
                    }
                    breaker.record_success();
                    scores.extend(chunk_scores);
                }
            }
            Ok(resp) => {
                progress(
                    "epss.enrich.http_error",
                    &format!("status={}", resp.status()),
                );
                breaker.record_failure();
                if breaker.is_open() {
                    break;
                }
            }
            Err(e) => {
                progress("epss.enrich.error", &format!("{}", e));
                breaker.record_failure();
                if breaker.is_open() {
                    break;
                }
            }
        }
    }

    // Cluster mode: write API-fetched scores back to PG
    if crate::vuln::cluster_mode() && !api_fetched.is_empty() {
        if let Some(client) = pg.as_mut() {
            pg_put_epss_scores(client, &api_fetched);
        }
    }

    progress_timing("epss.enrich.fetch", started);
    scores
}

/// Fetch EPSS scores for a set of CVE IDs, opening its own PG connection.
/// Intended for use in parallel enrichment where the caller's PG connection
/// cannot be shared across threads.
pub fn fetch_epss_scores(
    cve_ids: &[String],
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) -> HashMap<String, (f32, f32)> {
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    fetch_epss_scores_with_pg(cve_ids, &mut pg, cache_dir, breaker)
}

/// Apply pre-fetched EPSS scores to findings. Returns the number of findings enriched.
pub fn apply_epss_scores(findings: &mut [Finding], scores: &HashMap<String, (f32, f32)>) -> usize {
    let mut enriched = 0usize;
    for finding in findings.iter_mut() {
        if let Some(&(score, percentile)) = scores.get(&finding.id) {
            finding.epss_score = Some(score);
            finding.epss_percentile = Some(percentile);
            enriched += 1;
        }
    }
    enriched
}

/// Enrich findings with EPSS (Exploit Prediction Scoring System) scores.
/// Batch queries the FIRST.org EPSS API in groups of 100 CVE IDs.
///
/// In cluster mode (`SCANROOK_CLUSTER_MODE=1`), checks the PostgreSQL `epss_scores_cache`
/// table before calling the FIRST.org API. API responses are written back to PG.
/// In standalone mode, uses the file cache only — PG is never touched.
pub fn epss_enrich_findings(
    findings: &mut [Finding],
    pg: &mut Option<PgClient>,
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) {
    let cve_ids: Vec<String> = findings
        .iter()
        .filter(|f| f.id.starts_with("CVE-"))
        .map(|f| f.id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let scores = fetch_epss_scores_with_pg(&cve_ids, pg, cache_dir, breaker);
    let enriched = apply_epss_scores(findings, &scores);
    progress(
        "epss.enrich.done",
        &format!("enriched={}/{}", enriched, findings.len()),
    );
}
