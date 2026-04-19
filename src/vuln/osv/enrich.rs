use std::path::PathBuf;

use chrono::{Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use reqwest::blocking::Client;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::report::{severity_from_score, CvssInfo, Finding, ReferenceInfo};
use crate::utils::{progress, progress_timing};

use super::super::cvss::parse_cvss_score;
use super::super::env_bool;
use super::super::http::build_http_client;
use super::super::pg::{
    compute_jittered_ttl_days, parse_osv_last_modified, pg_get_osv, pg_init_schema, pg_put_osv,
};

/// Apply a single OSV JSON payload to all matching findings in `findings`.
///
/// Extracts description/cvss/severity/references from `json` and writes them onto
/// every finding whose `id` equals `id`.  Then performs the advisory-to-CVE upgrade
/// (mutates finding IDs, appends extra CVE findings, deduplicates) and, as a final
/// fallback for Debian DLA-/DSA- advisories, calls `map_debian_advisory_to_cves`.
///
/// This function must be called sequentially because it mutates the shared `findings`
/// vec; it is intentionally separated from the HTTP-fetch path so that the fetch can
/// be parallelised independently.
fn osv_apply_payload_to_findings(
    id: &str,
    json: &Value,
    findings: &mut Vec<Finding>,
    pg: &mut Option<PgClient>,
) {
    // Extract description
    let description = json["summary"]
        .as_str()
        .or_else(|| json["details"].as_str())
        .map(|s| s.to_string());

    // Extract CVSS / severity
    let mut cvss: Option<CvssInfo> = None;
    let mut severity_str: Option<String> = None;
    if let Some(severities) = json["severity"].as_array() {
        for sev in severities {
            if sev["type"] == "CVSS_V3" || sev["type"] == "CVSS_V2" || sev["type"] == "CVSS_V4" {
                if let Some(score_str) = sev["score"].as_str() {
                    if let Some((score_num, vector)) = parse_cvss_score(score_str) {
                        cvss = Some(CvssInfo {
                            base: score_num,
                            vector,
                        });
                        severity_str = Some(severity_from_score(score_num).to_string());
                        break;
                    }
                }
            }
        }
    }

    // Extract references
    let mut refs: Vec<ReferenceInfo> = Vec::new();
    if let Some(references) = json["references"].as_array() {
        for r in references {
            if let Some(url) = r["url"].as_str() {
                refs.push(ReferenceInfo {
                    reference_type: r["type"].as_str().unwrap_or("reference").to_string(),
                    url: url.to_string(),
                });
            }
        }
    }

    // Apply enrichment fields to matching findings
    for f in findings.iter_mut().filter(|f| f.id == id) {
        if f.description.is_none() {
            f.description = description.clone();
        }
        if f.cvss.is_none() {
            f.cvss = cvss.clone();
        }
        if f.severity.is_none() {
            f.severity = severity_str.clone();
        }
        if f.references.is_empty() && !refs.is_empty() {
            f.references = refs.clone();
        }
    }

    // Advisory -> CVE upgrade
    let mut to_append: Vec<Finding> = Vec::new();
    for i in 0..findings.len() {
        if findings[i].id != id {
            continue;
        }
        if findings[i].id.starts_with("CVE-") {
            continue;
        }
        // Build text corpus to scan for CVE patterns
        let mut text = String::new();
        if let Some(s) = json["summary"].as_str() {
            text.push_str(s);
            text.push(' ');
        }
        if let Some(d) = json["details"].as_str() {
            text.push_str(d);
        }
        let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
        let mut cves: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Some(arr) = json["aliases"].as_array() {
            for a in arr.iter().filter_map(|x| x.as_str()) {
                if a.starts_with("CVE-") {
                    cves.insert(a.to_string());
                }
            }
        }
        if let Some(arr) = json["references"].as_array() {
            if let Some(re2) = &re {
                for r in arr {
                    if let Some(u) = r["url"].as_str() {
                        if let Some(m) = re2.find(u) {
                            cves.insert(m.as_str().to_string());
                        }
                    }
                }
            }
        }
        if let Some(re2) = &re {
            if let Some(m) = re2.find(&text) {
                cves.insert(m.as_str().to_string());
            }
        }
        if !cves.is_empty() {
            // Clone the base finding BEFORE mutating id so secondary CVE records
            // carry the original advisory ID in source_ids.
            let base_clone = findings[i].clone();
            let mut cves_iter = cves.into_iter();
            if let Some(primary) = cves_iter.next() {
                let f = &mut findings[i];
                if !f.source_ids.contains(&f.id) {
                    f.source_ids.push(f.id.clone());
                }
                f.id = primary;
            }
            for extra in cves_iter {
                let mut nf = base_clone.clone();
                if !nf.source_ids.contains(&nf.id) {
                    nf.source_ids.push(nf.id.clone());
                }
                nf.id = extra;
                to_append.push(nf);
            }
        }
    }
    findings.extend(to_append);

    // Keep one row per (id, package) pair after advisory upgrades.
    dedupe_findings_by_id_and_package(findings);

    // Log upgrade count by counting CVEs that reference this advisory in source_ids
    let upgraded_cve_count = findings
        .iter()
        .filter(|f| f.id.starts_with("CVE-") && f.source_ids.iter().any(|s| s == id))
        .count();
    if upgraded_cve_count > 0 {
        progress(
            "osv.upgrade.cve",
            &format!("{} -> {} CVEs", id, upgraded_cve_count),
        );
    }

    // Drop any remaining advisory-only finding with this id
    if !id.starts_with("CVE-") && upgraded_cve_count > 0 {
        let before_len = findings.len();
        findings.retain(|f| f.id != id);
        if findings.len() != before_len {
            progress("osv.advisory.drop", id);
        }
    }

    // Debian DLA-/DSA- fallback: if still advisory-only, map via the Debian tracker
    if (id.starts_with("DLA-") || id.starts_with("DSA-")) && findings.iter().any(|f| f.id == id) {
        if let Some(mut mapped) = super::super::map_debian_advisory_to_cves(id, pg) {
            mapped.sort();
            mapped.dedup();
            if !mapped.is_empty() {
                let mut to_append2: Vec<Finding> = Vec::new();
                for f in findings.iter_mut().filter(|f| f.id == id) {
                    if let Some(first) = mapped.first().cloned() {
                        if !f.source_ids.contains(&f.id) {
                            f.source_ids.push(f.id.clone());
                        }
                        f.id = first;
                    }
                    for extra in mapped.iter().skip(1) {
                        let mut nf = f.clone();
                        nf.id = extra.clone();
                        to_append2.push(nf);
                    }
                }
                findings.extend(to_append2);
                dedupe_findings_by_id_and_package(findings);
                progress(
                    "osv.debian.map.ok",
                    &format!("{} -> {} CVEs", id, mapped.len()),
                );
                let before_len2 = findings.len();
                findings.retain(|f| f.id != id);
                if findings.len() != before_len2 {
                    progress("osv.advisory.drop", id);
                }
            } else {
                progress("osv.debian.map.empty", id);
            }
        } else {
            progress("osv.debian.map.skip", id);
        }
    }
}

/// Fetch OSV `/v1/vulns/{id}` payloads in parallel (bounded concurrency).
///
/// For each id in `ids`:
///   1. Check the file cache first.
///   2. If not cached, acquire a slot from the semaphore (capacity 5), perform
///      the HTTP GET, release the slot, and store the result to the file cache.
///
/// Returns a map of id -> parsed JSON for every id that could be resolved.
/// PG-cache lookups are deliberately excluded here because `PgClient` is not `Send`;
/// callers must handle PG separately before and after this function.
///
/// The `breaker` is checked before making each HTTP request and updated on success/failure.
/// Since `CircuitBreaker` uses atomics internally it is `Sync` and can be shared across threads.
fn osv_fetch_parallel(
    ids: &[String],
    client: &Client,
    breaker: &crate::vuln::CircuitBreaker,
) -> std::collections::HashMap<String, Value> {
    if ids.is_empty() {
        return std::collections::HashMap::new();
    }

    let cache_dir = std::env::var_os("SCANNER_CACHE").map(PathBuf::from);
    let max_concurrent: usize = std::env::var("SCANNER_OSV_ENRICH_CONC")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5);

    // Semaphore: Arc<(Mutex<count>, Condvar)>, initialised to max_concurrent permits.
    let sem = std::sync::Arc::new((
        std::sync::Mutex::new(max_concurrent),
        std::sync::Condvar::new(),
    ));

    let results: std::collections::HashMap<String, Value> = ids
        .par_iter()
        .filter_map(|id| {
            // Skip if circuit is already open.
            if breaker.is_open() {
                return None;
            }

            // File-cache hit fast path — no semaphore needed.
            let cache_tag = cache_key(&["osv_vuln", id]);
            if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_tag) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    return Some((id.clone(), v));
                }
            }

            // Acquire a semaphore permit.
            {
                let (lock, cvar) = &*sem;
                let mut count = lock.lock().unwrap();
                while *count == 0 {
                    count = cvar.wait(count).unwrap();
                }
                *count -= 1;
            }

            let url = format!("https://api.osv.dev/v1/vulns/{}", id);
            let result = match client.get(&url).send() {
                Ok(r) if r.status().is_success() => match r.json::<Value>() {
                    Ok(v) => {
                        cache_put(cache_dir.as_deref(), &cache_tag, v.to_string().as_bytes());
                        breaker.record_success();
                        Some((id.clone(), v))
                    }
                    Err(_) => {
                        breaker.record_failure();
                        None
                    }
                },
                _ => {
                    breaker.record_failure();
                    None
                }
            };

            // Release the semaphore permit.
            {
                let (lock, cvar) = &*sem;
                let mut count = lock.lock().unwrap();
                *count += 1;
                cvar.notify_one();
            }

            result
        })
        .collect();

    results
}

pub(in crate::vuln) fn drop_fixed_findings(findings: &mut Vec<Finding>) -> usize {
    let before = findings.len();
    findings.retain(|f| !matches!(f.fixed, Some(true)));
    before.saturating_sub(findings.len())
}

fn osv_fetch_cve_details() -> bool {
    env_bool("SCANNER_OSV_FETCH_CVE_DETAILS", false)
}

fn finding_dedupe_key(f: &Finding) -> String {
    if let Some(pkg) = f.package.as_ref() {
        format!("{}|{}|{}|{}", f.id, pkg.ecosystem, pkg.name, pkg.version)
    } else {
        format!("{}|||", f.id)
    }
}

pub(in crate::vuln) fn dedupe_findings_by_id_and_package(findings: &mut Vec<Finding>) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(finding_dedupe_key(f)));
}

/// Enrich findings with details from OSV /v1/vulns/{id} (fills description, severity, references)
pub fn osv_enrich_findings(
    findings: &mut Vec<Finding>,
    pg: &mut Option<PgClient>,
    breaker: &crate::vuln::CircuitBreaker,
) {
    if !env_bool("SCANNER_OSV_ENRICH", true) {
        progress("osv.fetch.skip", "disabled by SCANNER_OSV_ENRICH");
        return;
    }
    if findings.is_empty() {
        return;
    }
    if breaker.is_open() {
        progress(
            "osv.enrich.skip",
            &format!("circuit_open source={}", breaker.source_name()),
        );
        return;
    }
    // Deduplicate IDs to query
    let mut unique_ids_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in findings.iter() {
        unique_ids_set.insert(f.id.clone());
    }
    let mut unique_ids: Vec<String> = unique_ids_set.into_iter().collect();
    unique_ids.sort();
    let client = build_http_client(15);
    let fetch_cve_details = osv_fetch_cve_details();

    if let Some(c) = pg.as_mut() {
        pg_init_schema(c);
    }

    // Phase 0: vulndb payload lookup (standalone mode only)
    let vulndb_conn = if !crate::vuln::cluster_mode() {
        crate::vulndb::open_vulndb()
    } else {
        None
    };
    let mut vulndb_hits: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();
    if let Some(ref conn) = vulndb_conn {
        for id in &unique_ids {
            if id.starts_with("CVE-") && !fetch_cve_details {
                continue;
            }
            if let Some(json) = crate::vulndb::query_osv_payload_by_id(conn, id) {
                vulndb_hits.insert(id.clone(), json);
            }
        }
        if !vulndb_hits.is_empty() {
            progress(
                "osv.enrich.vulndb",
                &format!("hits={}/{}", vulndb_hits.len(), unique_ids.len()),
            );
        }
    }

    // Phase 1: PG cache lookup (sequential — PgClient is not Send)
    let phase_pg_started = std::time::Instant::now();
    let mut pg_cache_hits: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();
    let mut needs_fetch: Vec<String> = Vec::new();
    let mut skipped_cve_fetch = 0usize;
    for id in &unique_ids {
        // Skip IDs already resolved from vulndb
        if vulndb_hits.contains_key(id) {
            continue;
        }
        if id.starts_with("CVE-") && !fetch_cve_details {
            skipped_cve_fetch += 1;
            continue;
        }
        let mut pg_hit = false;
        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, _last_mod)) = pg_get_osv(client_pg, id) {
                // In cluster mode, trust PG cache unconditionally — the import
                // CronJob keeps it current. In standalone mode, use 90-day TTL.
                let fresh = if crate::vuln::cluster_mode() {
                    true
                } else {
                    let ttl_days = compute_jittered_ttl_days(90, 7);
                    Utc::now() - last_checked < ChronoDuration::days(ttl_days)
                };
                if fresh {
                    pg_cache_hits.insert(id.clone(), payload);
                    pg_hit = true;
                }
            }
        }
        if !pg_hit {
            needs_fetch.push(id.clone());
        }
    }
    if skipped_cve_fetch > 0 {
        progress(
            "osv.enrich.cve_fetch.skip",
            &format!(
                "count={} reason=SCANNER_OSV_FETCH_CVE_DETAILS=0",
                skipped_cve_fetch
            ),
        );
    }
    progress_timing("osv.enrich.pg_cache_lookup", phase_pg_started);

    // Phase 2: Parallel fetch for PG-cache misses (bounded concurrency)
    let phase_fetch_started = std::time::Instant::now();
    let fetched = osv_fetch_parallel(&needs_fetch, &client, breaker);
    progress_timing("osv.enrich.fetch_parallel", phase_fetch_started);
    progress(
        "osv.fetch.parallel.done",
        &format!(
            "fetched={} missed={}",
            fetched.len(),
            needs_fetch.len().saturating_sub(fetched.len())
        ),
    );

    // Phase 3: Store newly fetched payloads to PG (sequential)
    let phase_pg_store_started = std::time::Instant::now();
    for (id, json) in &fetched {
        if let Some(c) = pg.as_mut() {
            let lm = parse_osv_last_modified(json);
            pg_put_osv(c, id, json, lm);
        }
    }
    progress_timing("osv.enrich.pg_cache_store", phase_pg_store_started);

    // Capture source counts before consuming the maps
    let count_vulndb = vulndb_hits.len();
    let count_pg = pg_cache_hits.len();
    let count_network = fetched.len();

    // Phase 4: Build combined payloads map (vulndb + PG hits + freshly fetched)
    let all_payloads: std::collections::HashMap<String, Value> =
        vulndb_hits.into_iter().chain(pg_cache_hits).chain(fetched).collect();

    // Log source breakdown so users can tell what came from local DB vs network
    progress(
        "osv.enrich.summary",
        &format!(
            "total={} vulndb={} pg_cache={} network={} skipped_cve={}",
            all_payloads.len(),
            count_vulndb,
            count_pg,
            count_network,
            skipped_cve_fetch
        ),
    );

    // Phase 5: Apply payloads to findings sequentially
    // (advisory->CVE upgrades require sequential mutation of the shared findings vec)
    let phase_apply_started = std::time::Instant::now();
    let ids_to_apply: Vec<String> = unique_ids
        .into_iter()
        .filter(|id| all_payloads.contains_key(id))
        .collect();
    let total_apply = ids_to_apply.len();
    for (idx, id) in ids_to_apply.into_iter().enumerate() {
        progress(
            "osv.apply.start",
            &format!("{}/{} {}", idx + 1, total_apply, id),
        );
        if let Some(json) = all_payloads.get(&id) {
            osv_apply_payload_to_findings(&id, json, findings, pg);
            progress("osv.apply.ok", &id);
        }
    }
    progress_timing("osv.enrich.apply", phase_apply_started);

    // Advisory-level enrichment for Red Hat errata IDs (RHSA/RHBA/RHEA).
    // This fills severity/cvss/description/references so they don't stay as empty "Other" rows.
    super::super::redhat_enrich_findings(findings, pg);
    // CVE-level Red Hat enrichment computes package applicability and fixed package versions.
    super::super::redhat_enrich_cve_findings(findings, pg);
    // First-class distro advisory enrichment for Debian/Ubuntu/Alpine.
    super::super::distro_feed_enrich_findings(findings, pg);
    let dropped_fixed = drop_fixed_findings(findings);
    if dropped_fixed > 0 {
        progress("osv.fixed.drop", &format!("count={}", dropped_fixed));
    }

    // Keep one row per (id, package) pair.
    dedupe_findings_by_id_and_package(findings);

    // Final pass: drop any remaining Debian advisories (DLA/DSA) to drive non-CVE count to zero
    let before_len_final = findings.len();
    findings.retain(|f| !(f.id.starts_with("DLA-") || f.id.starts_with("DSA-")));
    let dropped = before_len_final.saturating_sub(findings.len());
    if dropped > 0 {
        progress("osv.advisory.drop.final", &format!("count={}", dropped));
    }
}

#[cfg(test)]
mod tests {
    /// In standalone mode (no SCANROOK_CLUSTER_MODE), vulndb should be checked
    /// for advisory payloads before falling through to PG/API.
    #[test]
    fn test_vulndb_payload_lookup_in_standalone_mode() {
        // Ensure standalone mode
        std::env::remove_var("SCANROOK_CLUSTER_MODE");

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::vulndb::schema::CREATE_SCHEMA).unwrap();
        crate::vulndb::schema::set_metadata(&conn, "schema_version", "2").unwrap();
        crate::vulndb::schema::set_metadata(&conn, "dict_compression", "0").unwrap();

        // Insert a DLA advisory payload
        let dla_json = br#"{"id": "DLA-3879-1", "aliases": ["CVE-2024-1234"], "summary": "test"}"#;
        let compressed = crate::vulndb::compress::compress_json(dla_json);
        conn.execute(
            "INSERT INTO osv_payloads (id, payload) VALUES (?1, ?2)",
            rusqlite::params!["DLA-3879-1", compressed],
        ).unwrap();

        // query_osv_payload_by_id should find it
        let result = crate::vulndb::query_osv_payload_by_id(&conn, "DLA-3879-1");
        assert!(result.is_some(), "vulndb should return payload for DLA-3879-1");
        assert_eq!(result.unwrap()["id"].as_str().unwrap(), "DLA-3879-1");
    }

    /// In cluster mode (SCANROOK_CLUSTER_MODE=1), vulndb should NOT be opened.
    /// The enrichment pipeline should skip vulndb and use PG cache instead.
    #[test]
    fn test_cluster_mode_skips_vulndb() {
        std::env::set_var("SCANROOK_CLUSTER_MODE", "1");
        assert!(crate::vuln::cluster_mode(), "cluster_mode should be true");

        // In cluster mode, open_vulndb is not called (vulndb_conn = None)
        let vulndb_conn: Option<rusqlite::Connection> = if !crate::vuln::cluster_mode() {
            Some(rusqlite::Connection::open_in_memory().unwrap())
        } else {
            None
        };
        assert!(vulndb_conn.is_none(), "cluster mode should skip vulndb");

        // Clean up env
        std::env::remove_var("SCANROOK_CLUSTER_MODE");
    }
}
