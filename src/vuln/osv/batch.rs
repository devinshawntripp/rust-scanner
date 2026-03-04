use std::time::Duration;

use postgres::Client as PgClient;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::utils::progress;

use super::super::http::build_http_client;
use super::super::pg::resolve_enrich_cache_dir;

/// Batch query OSV with package coordinates. Returns a JSON value (array of results).
///
/// In cluster mode (`SCANROOK_CLUSTER_MODE=1`), checks the `osv_batch_chunk_cache` PostgreSQL
/// table before making any API calls. Successful API responses are written back to PG.
/// In standalone mode, the existing file-cache path is used unchanged.
///
/// The `breaker` is checked before each chunk HTTP request; on network failure
/// `record_failure()` is called and the loop breaks if the circuit opens.
pub fn osv_batch_query(
    packages: &Vec<PackageCoordinate>,
    pg: &mut Option<PgClient>,
    breaker: &crate::vuln::CircuitBreaker,
) -> serde_json::Value {
    if packages.is_empty() {
        return serde_json::json!([]);
    }
    if breaker.is_open() {
        progress(
            "osv.batch.skip",
            &format!("circuit_open source={}", breaker.source_name()),
        );
        return serde_json::json!([]);
    }

    let cache_dir = resolve_enrich_cache_dir();

    // Build per-package queries and remember original indices
    let mut ecosystem_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let indexed: Vec<(usize, Value)> = packages.iter().enumerate().filter_map(|(i, p)| {
        let (ecosystem, name, version) = map_ecosystem_name_version(p);
        if ecosystem.is_empty() {
            // Skip packages with no OSV ecosystem (e.g. mac-app, mac-pkg, mac-framework)
            return None;
        }
        *ecosystem_counts.entry(ecosystem.clone()).or_insert(0) += 1;
        let q = serde_json::json!({ "package": {"ecosystem": ecosystem, "name": name}, "version": version });
        Some((i, q))
    }).collect();
    let mut eco_summary: Vec<String> = ecosystem_counts
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    eco_summary.sort();
    progress("osv.query.ecosystems", &eco_summary.join(" "));

    // Output buffer aligned to packages (each entry: {"vulns": [...]})
    let mut results: Vec<Value> = vec![serde_json::json!({"vulns": []}); packages.len()];

    let chunk_size: usize = std::env::var("SCANNER_OSV_BATCH_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let retries: usize = std::env::var("SCANNER_OSV_RETRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let backoff_ms_base: u64 = std::env::var("SCANNER_OSV_BACKOFF_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);

    let osv_timeout_secs: u64 = std::env::var("SCANNER_OSV_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let client = build_http_client(osv_timeout_secs);

    // Standalone mode: open vulndb once for SQLite lookups across all chunks
    let vulndb_conn = if !crate::vuln::cluster_mode() {
        crate::vulndb::open_vulndb()
    } else {
        None
    };

    for chunk in indexed.chunks(chunk_size) {
        // Prepare body for this chunk
        let body =
            serde_json::json!({ "queries": chunk.iter().map(|(_, q)| q).collect::<Vec<&Value>>() });
        let body_bytes = body.to_string();
        let body_digest = {
            use sha2::{Digest as _, Sha256};
            let hash = Sha256::digest(body_bytes.as_bytes());
            format!("{:x}", hash)
        };
        let cache_tag = cache_key(&["osv_batch", &body_digest]);
        progress(
            "osv.query.chunk.start",
            &format!(
                "offset={} size={}",
                chunk.first().map(|(i, _)| i).unwrap_or(&0),
                chunk.len()
            ),
        );

        // Standalone mode: check SQLite vulndb before API
        if let Some(ref conn) = vulndb_conn {
            let mut all_found = true;
            for &(orig_idx, ref query) in chunk {
                let eco = query["package"]["ecosystem"].as_str().unwrap_or_default();
                let name = query["package"]["name"].as_str().unwrap_or_default();
                let vulns = crate::vulndb::query_osv_by_package(conn, eco, name);
                if vulns.is_empty() {
                    all_found = false;
                    break;
                }
                results[orig_idx] = serde_json::json!({"vulns": vulns});
            }
            if all_found {
                progress(
                    "osv.query.chunk.vulndb",
                    &format!(
                        "offset={} size={}",
                        chunk.first().map(|(i, _)| i).unwrap_or(&0),
                        chunk.len()
                    ),
                );
                continue; // skip API call for this chunk
            }
        }

        // Cluster mode: check PG chunk cache BEFORE the retry loop (outside attempt counting)
        if crate::vuln::cluster_mode() {
            if let Some(c) = pg.as_mut() {
                let ttl = crate::vuln::pg::compute_jittered_ttl_days(30, 7);
                if let Some(cached) = crate::vuln::pg::pg_get_osv_batch_chunk(c, &body_digest, ttl) {
                    if let Some(arr) = cached["results"].as_array() {
                        for (idx_in_chunk, item) in arr.iter().enumerate() {
                            if idx_in_chunk < chunk.len() {
                                results[chunk[idx_in_chunk].0] = item.clone();
                            }
                        }
                        progress(
                            "osv.query.chunk.pg_cache",
                            &format!("digest={}", &body_digest[..8.min(body_digest.len())]),
                        );
                        continue; // skip to next chunk
                    }
                }
            }
        }

        let mut attempt = 0;
        let mut done = false;
        while attempt < retries && !done {
            // Check circuit breaker before each attempt
            if breaker.is_open() {
                progress(
                    "osv.batch.chunk.skip",
                    &format!(
                        "circuit_open source={} offset={}",
                        breaker.source_name(),
                        chunk.first().map(|(i, _)| i).unwrap_or(&0)
                    ),
                );
                break;
            }
            attempt += 1;
            // In standalone mode: try file cache for this chunk first
            if !crate::vuln::cluster_mode() {
                if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_tag) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(arr) = v["results"].as_array() {
                            for (idx_in_chunk, item) in arr.iter().enumerate() {
                                let orig_idx = chunk[idx_in_chunk].0;
                                results[orig_idx] = item.clone();
                            }
                            progress(
                                "osv.query.chunk.cache",
                                &format!(
                                    "offset={} size={}",
                                    chunk.first().map(|(i, _)| i).unwrap_or(&0),
                                    chunk.len()
                                ),
                            );
                            done = true;
                            break;
                        }
                    }
                }
            }

            // Network request
            let resp = client
                .post("https://api.osv.dev/v1/querybatch")
                .json(&body)
                .send();
            match resp {
                Ok(r) => {
                    let status = r.status();
                    let offset = chunk.first().map(|(i, _)| i).unwrap_or(&0);
                    if !status.is_success() {
                        let body_preview = r.text().unwrap_or_default();
                        let preview = body_preview.chars().take(120).collect::<String>();
                        progress(
                            "osv.query.error",
                            &format!(
                                "chunk_http_err offset={} attempt={} status={} body={}",
                                offset, attempt, status, preview
                            ),
                        );
                        breaker.record_failure();
                        if breaker.is_open() {
                            break;
                        }
                    } else {
                        // Capture raw body first so we can log it on failure
                        match r.text() {
                            Ok(text) => match serde_json::from_str::<Value>(&text) {
                                Ok(v) => {
                                    if let Some(arr) = v["results"].as_array() {
                                        for (idx_in_chunk, item) in arr.iter().enumerate() {
                                            let orig_idx = chunk[idx_in_chunk].0;
                                            results[orig_idx] = item.clone();
                                        }
                                        // Write back to appropriate cache based on mode
                                        if crate::vuln::cluster_mode() {
                                            if let Some(c) = pg.as_mut() {
                                                crate::vuln::pg::pg_put_osv_batch_chunk(
                                                    c,
                                                    &body_digest,
                                                    &v,
                                                );
                                            }
                                        } else {
                                            cache_put(
                                                cache_dir.as_deref(),
                                                &cache_tag,
                                                v.to_string().as_bytes(),
                                            );
                                        }
                                        breaker.record_success();
                                        progress(
                                            "osv.query.chunk.done",
                                            &format!(
                                                "offset={} size={} attempts={}",
                                                offset,
                                                chunk.len(),
                                                attempt
                                            ),
                                        );
                                        done = true;
                                        break;
                                    } else {
                                        let keys = v
                                            .as_object()
                                            .map(|m| m.keys().cloned().collect::<Vec<_>>())
                                            .unwrap_or_default();
                                        let preview = text.chars().take(200).collect::<String>();
                                        progress(
                                                "osv.query.error",
                                                &format!(
                                                    "chunk_parse offset={} attempt={} keys={:?} body={}",
                                                    offset, attempt, keys, preview
                                                ),
                                            );
                                        breaker.record_failure();
                                        if breaker.is_open() {
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    let preview = text.chars().take(200).collect::<String>();
                                    progress(
                                        "osv.query.error",
                                        &format!(
                                            "chunk_json offset={} attempt={} err={} body={}",
                                            offset, attempt, e, preview
                                        ),
                                    );
                                    breaker.record_failure();
                                    if breaker.is_open() {
                                        break;
                                    }
                                }
                            },
                            Err(e) => {
                                progress(
                                    "osv.query.error",
                                    &format!(
                                        "chunk_text offset={} attempt={} err={}",
                                        offset, attempt, e
                                    ),
                                );
                                breaker.record_failure();
                                if breaker.is_open() {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    progress(
                        "osv.query.error",
                        &format!(
                            "chunk_http offset={} attempt={} err={}",
                            chunk.first().map(|(i, _)| i).unwrap_or(&0),
                            attempt,
                            e
                        ),
                    );
                    breaker.record_failure();
                    if breaker.is_open() {
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(backoff_ms_base * attempt as u64));
        }

        if !done {
            // Fallback: per-package (skip entirely if circuit is open)
            if breaker.is_open() {
                progress(
                    "osv.batch.fallback.skip",
                    &format!(
                        "circuit_open source={} offset={}",
                        breaker.source_name(),
                        chunk.first().map(|(i, _)| i).unwrap_or(&0)
                    ),
                );
            } else {
            for (orig_idx, q) in chunk {
                // Check circuit breaker before each per-package attempt
                if breaker.is_open() {
                    progress(
                        "osv.query.pkg.skip",
                        &format!("circuit_open source={} idx={}", breaker.source_name(), orig_idx),
                    );
                    break;
                }
                let mut attempt_p = 0;
                let single_cache = cache_key(&["osv_one", &q.to_string()]);
                loop {
                    attempt_p += 1;
                    if let Some(bytes) = cache_get(cache_dir.as_deref(), &single_cache) {
                        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                            results[*orig_idx] = v;
                            break;
                        }
                    }
                    progress(
                        "osv.query.pkg.start",
                        &format!("idx={} attempt={}", orig_idx, attempt_p),
                    );
                    let resp = client.post("https://api.osv.dev/v1/query").json(&q).send();
                    match resp {
                        Ok(r) => match r.json::<Value>() {
                            Ok(v) => {
                                cache_put(
                                    cache_dir.as_deref(),
                                    &single_cache,
                                    v.to_string().as_bytes(),
                                );
                                results[*orig_idx] = v;
                                breaker.record_success();
                                progress(
                                    "osv.query.pkg.ok",
                                    &format!("idx={} attempts={}", orig_idx, attempt_p),
                                );
                                break;
                            }
                            Err(e) => {
                                progress(
                                    "osv.query.pkg.error",
                                    &format!("idx={} json err={}", orig_idx, e),
                                );
                                breaker.record_failure();
                            }
                        },
                        Err(e) => {
                            progress(
                                "osv.query.pkg.error",
                                &format!("idx={} http err={}", orig_idx, e),
                            );
                            breaker.record_failure();
                        }
                    }
                    if attempt_p >= retries || breaker.is_open() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(backoff_ms_base * attempt_p as u64));
                }
            }
            }
            progress(
                "osv.query.chunk.fallback",
                &format!(
                    "offset={} size={}",
                    chunk.first().map(|(i, _)| i).unwrap_or(&0),
                    chunk.len()
                ),
            );
        }
    }

    serde_json::Value::Array(results)
}

fn map_ecosystem_name_version(p: &PackageCoordinate) -> (String, String, String) {
    // Map OS package ecosystems to OSV conventions
    match p.ecosystem.as_str() {
        // OSV's Debian ecosystem indexes by source package name, not binary name.
        // Use the source_name from dpkg's Source: field when available.
        // dpkg: OSV Debian ecosystem indexes by SOURCE package name.
        // Ubuntu has its own OSV ecosystem with separate advisory data.
        "deb" | "ubuntu-deb" => {
            let eco = if p.ecosystem == "ubuntu-deb" {
                "Ubuntu"
            } else {
                "Debian"
            };
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            (eco.into(), query_name, p.version.clone())
        }
        // APK: OSV Alpine ecosystem uses "Alpine" (NOT "Alpine Linux") and indexes
        // by origin package name (the `o:` field in /lib/apk/db/installed).
        "apk" => {
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            ("Alpine".into(), query_name, p.version.clone())
        }
        // RPM ecosystems: OSV indexes by source RPM name for Rocky/SUSE/openSUSE.
        // Red Hat and AlmaLinux list both source and binary names in advisories.
        "redhat" => {
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            ("Red Hat".into(), query_name, p.version.clone())
        }
        "rocky" => {
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            ("Rocky Linux".into(), query_name, p.version.clone())
        }
        "almalinux" => {
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            ("AlmaLinux".into(), query_name, p.version.clone())
        }
        "suse" => {
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            ("SUSE".into(), query_name, p.version.clone())
        }
        "opensuse" => {
            let query_name = p.source_name.as_deref().unwrap_or(&p.name).to_string();
            ("openSUSE".into(), query_name, p.version.clone())
        }
        "amazonlinux" => ("Amazon Linux".into(), p.name.clone(), p.version.clone()),
        "oraclelinux" => ("Oracle Linux".into(), p.name.clone(), p.version.clone()),
        "chainguard" => ("Chainguard".into(), p.name.clone(), p.version.clone()),
        "wolfi" => ("Wolfi".into(), p.name.clone(), p.version.clone()),
        "fedora" => ("Fedora".into(), p.name.clone(), p.version.clone()),
        "centos" => ("Red Hat".into(), p.name.clone(), p.version.clone()),
        "rpm" => ("Red Hat".into(), p.name.clone(), p.version.clone()),
        // macOS ecosystems have no OSV database — skip by returning empty ecosystem
        // so the filter below excludes them. They are enriched via NVD/CPE instead.
        "mac-app" | "mac-pkg" | "mac-framework" => {
            ("".into(), p.name.clone(), p.version.clone())
        }
        other => (other.to_string(), p.name.clone(), p.version.clone()),
    }
}
