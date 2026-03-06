use std::collections::HashSet;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::report::Finding;
use crate::utils::{progress, progress_timing};
use postgres::Client as PgClient;
use serde_json::Value;

use super::http::enrich_http_client;
use super::pg::{compute_jittered_ttl_days, pg_get_kev_entries, pg_put_kev_entries};

fn kev_enrich_enabled() -> bool {
    std::env::var("SCANNER_KEV_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Fetch KEV entries using the provided PG connection.
/// Returns a set of CVE IDs that are in the CISA KEV catalog.
fn fetch_kev_set_with_pg(
    pg: &mut Option<PgClient>,
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) -> Option<HashSet<String>> {
    if !kev_enrich_enabled() {
        progress("kev.enrich.skip", "disabled by SCANNER_KEV_ENRICH");
        return None;
    }
    if breaker.is_open() {
        progress(
            "kev.enrich.skip",
            &format!("circuit_open source={}", breaker.source_name()),
        );
        return None;
    }
    progress("kev.enrich.start", "checking KEV catalog");
    let started = std::time::Instant::now();

    // Cluster mode: check PG cache before calling live API
    if crate::vuln::cluster_mode() {
        if let Some(client) = pg.as_mut() {
            let ttl = compute_jittered_ttl_days(30, 7);
            let kev_set = pg_get_kev_entries(client, ttl);
            if !kev_set.is_empty() {
                progress("kev.enrich.pg_hit", &format!("entries={}", kev_set.len()));
                progress_timing("kev.enrich.fetch", started);
                return Some(kev_set);
            }
        }
    }

    // Standalone vulndb KEV check happens in apply_kev_set() since it
    // needs per-finding CVE IDs. Fall through to file cache / live API.

    // Standalone mode (or PG miss): use file cache / live API
    let kev_set = kev_from_cache_or_api(cache_dir, breaker);

    // Cluster mode: write API-fetched KEV entries back to PG
    if crate::vuln::cluster_mode() {
        if let Some(client) = pg.as_mut() {
            let ids: Vec<String> = kev_set.iter().cloned().collect();
            if !ids.is_empty() {
                pg_put_kev_entries(client, &ids);
            }
        }
    }

    progress_timing("kev.enrich.fetch", started);
    Some(kev_set)
}

/// Fetch KEV set, opening its own PG connection.
/// Intended for use in parallel enrichment.
pub fn fetch_kev_set(
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) -> HashSet<String> {
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    fetch_kev_set_with_pg(&mut pg, cache_dir, breaker).unwrap_or_default()
}

/// Apply pre-fetched KEV set to findings. Returns the number of findings enriched.
pub fn apply_kev_set(findings: &mut [Finding], kev_set: &HashSet<String>) -> usize {
    // Also check vulndb in standalone mode for any entries not in the API set
    let vulndb_conn = if !crate::vuln::cluster_mode() {
        crate::vulndb::open_vulndb()
    } else {
        None
    };

    let mut enriched = 0usize;
    for finding in findings.iter_mut() {
        if finding.id.starts_with("CVE-") {
            if kev_set.contains(&finding.id) {
                finding.in_kev = Some(true);
                enriched += 1;
            } else if let Some(ref conn) = vulndb_conn {
                if crate::vulndb::query_kev(conn, &finding.id) {
                    finding.in_kev = Some(true);
                    enriched += 1;
                }
            }
        }
    }
    enriched
}

/// Enrich findings with CISA KEV (Known Exploited Vulnerabilities) data.
/// Downloads the full KEV catalog JSON and marks matching findings.
///
/// In cluster mode (`SCANROOK_CLUSTER_MODE=1`), checks the PostgreSQL `kev_entries_cache`
/// table before calling the CISA API. API responses are written back to PG.
/// In standalone mode, uses the file cache only — PG is never touched.
pub fn kev_enrich_findings(
    findings: &mut [Finding],
    pg: &mut Option<PgClient>,
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) {
    let has_cves = findings.iter().any(|f| f.id.starts_with("CVE-"));
    if !has_cves {
        return;
    }
    let kev_set = match fetch_kev_set_with_pg(pg, cache_dir, breaker) {
        Some(set) => set,
        None => return,
    };
    let enriched = apply_kev_set(findings, &kev_set);
    progress(
        "kev.enrich.done",
        &format!(
            "kev_total={} matched={}/{}",
            kev_set.len(),
            enriched,
            findings.len()
        ),
    );
}

fn kev_from_cache_or_api(
    cache_dir: Option<&std::path::Path>,
    breaker: &crate::vuln::CircuitBreaker,
) -> HashSet<String> {
    let cache_k = cache_key(&["kev_catalog_v1"]);
    if let Some(cached) = cache_get(cache_dir, &cache_k) {
        if let Ok(set) = serde_json::from_slice::<HashSet<String>>(&cached) {
            progress("kev.enrich.cache_hit", &format!("cves={}", set.len()));
            return set;
        }
    }
    match fetch_kev_catalog(breaker) {
        Some(set) => {
            if let Ok(serialized) = serde_json::to_vec(&set) {
                cache_put(cache_dir, &cache_k, &serialized);
            }
            set
        }
        None => HashSet::new(),
    }
}

fn fetch_kev_catalog(breaker: &crate::vuln::CircuitBreaker) -> Option<HashSet<String>> {
    if breaker.is_open() {
        return None;
    }
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    match enrich_http_client().get(url).send() {
        Ok(resp) if resp.status().is_success() => {
            let body: Value = resp.json().ok()?;
            let vulns = body.get("vulnerabilities")?.as_array()?;
            let set: HashSet<String> = vulns
                .iter()
                .filter_map(|v| v.get("cveID").and_then(|c| c.as_str()).map(String::from))
                .collect();
            breaker.record_success();
            progress("kev.enrich.catalog_fetched", &format!("cves={}", set.len()));
            Some(set)
        }
        Ok(resp) => {
            progress(
                "kev.enrich.http_error",
                &format!("status={}", resp.status()),
            );
            breaker.record_failure();
            None
        }
        Err(e) => {
            progress("kev.enrich.error", &format!("{}", e));
            breaker.record_failure();
            None
        }
    }
}
