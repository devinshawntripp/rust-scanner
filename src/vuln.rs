use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::Duration;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::redhat::{compare_evr, is_rpm_ecosystem};
use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};
use crate::utils::{progress, progress_timing};
use rand::Rng;
use rayon::prelude::*;
use reqwest::blocking::{Client, Response};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;

// --- Postgres cache ---
use chrono::{DateTime, Duration as ChronoDuration, NaiveDateTime, Utc};
use postgres::{Client as PgClient, NoTls};

fn scanner_force_ipv4() -> bool {
    std::env::var("SCANNER_FORCE_IPV4")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn parse_cvss_score(score_raw: &str) -> Option<(f32, String)> {
    let s = score_raw.trim();
    if s.is_empty() {
        return None;
    }

    // 1) Plain numeric score (e.g. "7.5")
    if let Ok(n) = s.parse::<f32>() {
        return Some((n, s.to_string()));
    }

    // 2) Legacy "X.Y/..." format
    let head = s.split('/').next().unwrap_or(s);
    if let Ok(n) = head.parse::<f32>() {
        return Some((n, s.to_string()));
    }

    // 3) CVSS vector format (e.g. "CVSS:3.1/AV:L/...")
    if s.starts_with("CVSS:") {
        if let Ok(v) = s.parse::<cvss::Cvss>() {
            return Some((v.score() as f32, s.to_string()));
        }
    }

    None
}

fn build_http_client(timeout_secs: u64) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(format!("scanrook/{}", env!("CARGO_PKG_VERSION")));
    if scanner_force_ipv4() {
        // Worker pods on many homelab clusters have no usable IPv6 egress.
        // Pin outbound sockets to IPv4 to avoid long OSV/NVD timeouts.
        builder = builder.local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    builder.build().unwrap()
}

static NVD_HTTP_CLIENT: OnceLock<Client> = OnceLock::new();
static ENRICH_HTTP_CLIENT: OnceLock<Client> = OnceLock::new();
static REDIS_CLIENT: OnceLock<Option<redis::Client>> = OnceLock::new();

fn nvd_timeout_secs() -> u64 {
    std::env::var("SCANNER_NVD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
}

fn nvd_retry_max() -> usize {
    std::env::var("SCANNER_NVD_RETRY_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

fn nvd_retry_base_ms() -> u64 {
    std::env::var("SCANNER_NVD_RETRY_BASE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
}

fn nvd_http_client() -> &'static Client {
    NVD_HTTP_CLIENT.get_or_init(|| build_http_client(nvd_timeout_secs()))
}

fn enrich_http_client() -> &'static Client {
    ENRICH_HTTP_CLIENT.get_or_init(|| build_http_client(30))
}

fn redis_client() -> Option<&'static redis::Client> {
    REDIS_CLIENT
        .get_or_init(|| {
            let url = std::env::var("SCANNER_REDIS_URL")
                .ok()
                .or_else(|| std::env::var("REDIS_URL").ok())
                .unwrap_or_default();
            if url.trim().is_empty() {
                return None;
            }
            redis::Client::open(url).ok()
        })
        .as_ref()
}

fn nvd_scope_key(api_key: Option<&str>) -> String {
    if let Some(key) = api_key {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        let full = format!("key:{:x}", digest);
        return full.chars().take(20).collect();
    }
    "anon".to_string()
}

fn wait_for_global_nvd_rate_slot(api_key: Option<&str>) {
    let per_minute: i64 = std::env::var("SCANNER_NVD_GLOBAL_RATE_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if per_minute <= 0 {
        return;
    }
    let Some(client) = redis_client() else {
        return;
    };

    loop {
        let now = Utc::now();
        let minute = now.timestamp() / 60;
        let scope = nvd_scope_key(api_key);
        let key = format!("scanner:nvd:rate:{}:{}", scope, minute);
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(e) => {
                progress("nvd.rate.redis.err", &format!("{}", e));
                return;
            }
        };

        let count: i64 = redis::cmd("INCR").arg(&key).query(&mut conn).unwrap_or(1);
        let _: redis::RedisResult<()> = redis::cmd("EXPIRE").arg(&key).arg(70).query(&mut conn);
        if count <= per_minute {
            return;
        }

        let sec = now.timestamp().rem_euclid(60);
        let wait_ms = ((60 - sec).max(1) as u64) * 1000;
        progress(
            "nvd.rate.wait",
            &format!(
                "scope={} count={} limit={} wait_ms={}",
                scope, count, per_minute, wait_ms
            ),
        );
        sleep(Duration::from_millis(wait_ms));
    }
}

fn parse_retry_after_ms(resp: &Response) -> Option<u64> {
    let value = resp.headers().get("Retry-After")?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1000));
    }
    None
}

fn retry_backoff_with_jitter_ms(attempt: usize) -> u64 {
    let capped_exp = (attempt.saturating_sub(1)).min(7);
    let exp = 1u64 << capped_exp;
    let max_backoff = nvd_retry_base_ms().saturating_mul(exp);
    if max_backoff == 0 {
        return 0;
    }
    rand::thread_rng().gen_range(0..=max_backoff)
}

/// Queries the NVD API for a given component + version
pub fn match_vuln(component: &str, version: &str) {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=10",
        urlencoding::encode(&keyword)
    );

    println!("Querying NVD: {}", url);

    let client = build_http_client(10);

    let resp = match client.get(&url).send() {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to reach NVD API: {}", e);
            return;
        }
    };

    if !resp.status().is_success() {
        eprintln!("NVD API returned error: {}", resp.status());
        return;
    }

    let json: Value = match resp.json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to parse NVD response: {}", e);
            return;
        }
    };

    let mut found = false;
    let mut seen = HashSet::new();

    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let id = item["cve"]["id"].as_str().unwrap_or("unknown");
            let descs = match item["cve"]["descriptions"].as_array() {
                Some(array) => array,
                None => {
                    println!("⚠️ No descriptions found for CVE");
                    continue;
                }
            };

            let description = descs
                .iter()
                .find(|d| d["lang"] == "en")
                .and_then(|d| d["value"].as_str())
                .unwrap_or("No English description found");

            if seen.insert(id.to_string()) {
                println!("🔹 {}: {}", id, description);
                found = true;
            }
        }
    }

    if !found {
        println!("✅ No CVEs found for: {} {}", component, version);
    }
}

/// Batch query OSV with package coordinates. Returns a JSON value (array of results)
pub fn osv_batch_query(packages: &Vec<PackageCoordinate>) -> serde_json::Value {
    if packages.is_empty() {
        return serde_json::json!([]);
    }

    // Build per-package queries and remember original indices
    let mut ecosystem_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let indexed: Vec<(usize, Value)> = packages.iter().enumerate().map(|(i, p)| {
        let (ecosystem, name, version) = map_ecosystem_name_version(p);
        *ecosystem_counts.entry(ecosystem.clone()).or_insert(0) += 1;
        let q = serde_json::json!({ "package": {"ecosystem": ecosystem, "name": name}, "version": version });
        (i, q)
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

        let mut attempt = 0;
        let mut done = false;
        while attempt < retries && !done {
            attempt += 1;
            // Try cache for this chunk first
            if let Some(bytes) = cache_get(
                std::env::var_os("SCANNER_CACHE")
                    .as_deref()
                    .map(PathBuf::from)
                    .as_deref(),
                &cache_tag,
            ) {
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
                                        cache_put(
                                            std::env::var_os("SCANNER_CACHE")
                                                .as_deref()
                                                .map(PathBuf::from)
                                                .as_deref(),
                                            &cache_tag,
                                            v.to_string().as_bytes(),
                                        );
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
                }
            }
            std::thread::sleep(Duration::from_millis(backoff_ms_base * attempt as u64));
        }

        if !done {
            // Fallback: per-package
            for (orig_idx, q) in chunk {
                let mut attempt_p = 0;
                let single_cache = cache_key(&["osv_one", &q.to_string()]);
                loop {
                    attempt_p += 1;
                    if let Some(bytes) = cache_get(
                        std::env::var_os("SCANNER_CACHE")
                            .as_deref()
                            .map(PathBuf::from)
                            .as_deref(),
                        &single_cache,
                    ) {
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
                                    std::env::var_os("SCANNER_CACHE")
                                        .as_deref()
                                        .map(PathBuf::from)
                                        .as_deref(),
                                    &single_cache,
                                    v.to_string().as_bytes(),
                                );
                                results[*orig_idx] = v;
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
                            }
                        },
                        Err(e) => {
                            progress(
                                "osv.query.pkg.error",
                                &format!("idx={} http err={}", orig_idx, e),
                            );
                        }
                    }
                    if attempt_p >= retries {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(backoff_ms_base * attempt_p as u64));
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
        "deb" => ("Debian".into(), p.name.clone(), p.version.clone()),
        "apk" => ("Alpine Linux".into(), p.name.clone(), p.version.clone()),
        "redhat" => ("Red Hat".into(), p.name.clone(), p.version.clone()),
        "rocky" => ("Rocky Linux".into(), p.name.clone(), p.version.clone()),
        "almalinux" => ("AlmaLinux".into(), p.name.clone(), p.version.clone()),
        "amazonlinux" => ("Amazon Linux".into(), p.name.clone(), p.version.clone()),
        "oraclelinux" => ("Oracle Linux".into(), p.name.clone(), p.version.clone()),
        "suse" => ("SUSE".into(), p.name.clone(), p.version.clone()),
        "opensuse" => ("openSUSE".into(), p.name.clone(), p.version.clone()),
        "chainguard" => ("Chainguard".into(), p.name.clone(), p.version.clone()),
        "wolfi" => ("Wolfi".into(), p.name.clone(), p.version.clone()),
        "fedora" => ("Fedora".into(), p.name.clone(), p.version.clone()),
        "centos" => ("Red Hat".into(), p.name.clone(), p.version.clone()),
        // Legacy fallback from older detector output.
        "rpm" => ("Red Hat".into(), p.name.clone(), p.version.clone()),
        // Fallback: pass through
        other => (other.to_string(), p.name.clone(), p.version.clone()),
    }
}

pub fn map_osv_results_to_findings(
    packages: &Vec<PackageCoordinate>,
    osv_results: &serde_json::Value,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for (idx, pkg) in packages.iter().enumerate() {
        let res = &osv_results[idx];
        if let Some(vulns) = res["vulns"].as_array() {
            for v in vulns {
                // Collect CVE ids from aliases, references, OSV id and text
                let aliases: Vec<String> = v["aliases"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let re_cve = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
                let mut cve_ids: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                if let Some(re) = &re_cve {
                    for a in &aliases {
                        if let Some(m) = re.find(a) {
                            cve_ids.insert(m.as_str().to_string());
                        }
                    }
                }
                if cve_ids.is_empty() {
                    if let Some(refs) = v["references"].as_array() {
                        if let Some(re) = &re_cve {
                            for u in refs.iter().filter_map(|r| r["url"].as_str()) {
                                if let Some(m) = re.find(u) {
                                    cve_ids.insert(m.as_str().to_string());
                                }
                            }
                        }
                    }
                }
                if cve_ids.is_empty() {
                    if let Some(osv_id_str) = v["id"].as_str() {
                        if let Some(re) = &re_cve {
                            if let Some(m) = re.find(osv_id_str) {
                                cve_ids.insert(m.as_str().to_string());
                            }
                        }
                    }
                }
                if cve_ids.is_empty() {
                    let mut text = String::new();
                    if let Some(s) = v["summary"].as_str() {
                        text.push_str(s);
                        text.push(' ');
                    }
                    if let Some(d) = v["details"].as_str() {
                        text.push_str(d);
                    }
                    if let Some(re) = &re_cve {
                        if let Some(m) = re.find(&text) {
                            cve_ids.insert(m.as_str().to_string());
                        }
                    }
                }
                let description = v["summary"]
                    .as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v["details"].as_str().map(|s| s.to_string()));
                let mut cvss: Option<CvssInfo> = None;
                let mut severity_str: Option<String> = None;
                if let Some(severities) = v["severity"].as_array() {
                    for sev in severities {
                        if sev["type"] == "CVSS_V3"
                            || sev["type"] == "CVSS_V2"
                            || sev["type"] == "CVSS_V4"
                        {
                            if let Some(score_str) = sev["score"].as_str() {
                                if let Some((score, vector)) = parse_cvss_score(score_str) {
                                    cvss = Some(CvssInfo {
                                        base: score,
                                        vector,
                                    });
                                    severity_str = Some(severity_from_score(score).to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
                // Fallback to database_specific severity if available (e.g., LOW/MEDIUM/HIGH)
                if severity_str.is_none() {
                    if let Some(sev) = v["database_specific"]["severity"].as_str() {
                        severity_str = Some(sev.to_uppercase());
                    }
                }

                let package = Some(PackageInfo {
                    name: pkg.name.clone(),
                    ecosystem: pkg.ecosystem.clone(),
                    version: pkg.version.clone(),
                });
                let evidence = vec![EvidenceItem {
                    evidence_type: "file".into(),
                    path: None,
                    detail: Some("package db record".into()),
                }];
                let mut references: Vec<ReferenceInfo> = Vec::new();
                if let Some(refs) = v["references"].as_array() {
                    for r in refs {
                        if let Some(url) = r["url"].as_str() {
                            references.push(ReferenceInfo {
                                reference_type: r["type"]
                                    .as_str()
                                    .unwrap_or("reference")
                                    .to_string(),
                                url: url.to_string(),
                            });
                        }
                    }
                }

                let mut source_ids = aliases;
                let osv_id = v["id"].as_str().unwrap_or("").to_string();
                if !osv_id.is_empty() {
                    source_ids.push(osv_id.clone());
                }
                // Determine fixed status using OSV affected ranges when possible
                let mut fixed: Option<bool> = None;
                if let Some(aff) = v["affected"].as_array() {
                    // OSV affected entries may include ranges with introduced/fixed
                    for a in aff {
                        if a["package"]
                            .get("ecosystem")
                            .and_then(|e| e.as_str())
                            .is_some()
                        {
                            let name_match = a["package"]
                                .get("name")
                                .and_then(|n| n.as_str())
                                .map(|s| s == pkg.name)
                                .unwrap_or(false);
                            if !name_match {
                                continue;
                            }
                            if let Some(ranges) = a["ranges"].as_array() {
                                for r in ranges {
                                    let range_type = r["type"].as_str().unwrap_or("");
                                    if range_type == "GIT" {
                                        // GIT ranges cannot be compared to installed versions
                                        // without git history; leave fixed as None
                                        continue;
                                    }
                                    if range_type == "ECOSYSTEM" || range_type == "SEMVER" {
                                        if let Some(events) = r["events"].as_array() {
                                            // Simplified: if a fixed version exists and pkg.version >= fixed, mark fixed=true
                                            if let Some(fixed_ver) = events.iter().find_map(|e| {
                                                e.get("fixed").and_then(|s| s.as_str())
                                            }) {
                                                // Use Debian-style compare for deb/apk when available
                                                // Fallback: naive numeric compare of dotted versions
                                                let is_fixed =
                                                    cmp_versions(&pkg.version, fixed_ver)
                                                        != std::cmp::Ordering::Less;
                                                fixed = Some(is_fixed);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !cve_ids.is_empty() {
                    for cid in cve_ids {
                        out.push(Finding {
                            id: cid.trim().to_string(),
                            source_ids: source_ids.clone(),
                            package: package.clone(),
                            confidence_tier: ConfidenceTier::ConfirmedInstalled,
                            evidence_source: EvidenceSource::InstalledDb,
                            accuracy_note: None,
                            fixed,
                            fixed_in: None,
                            recommendation: None,
                            severity: severity_str.clone(),
                            cvss: cvss.clone(),
                            description: description.clone(),
                            evidence: evidence.clone(),
                            references: references.clone(),
                            confidence: Some("HIGH".into()),
                            epss_score: None,
                            epss_percentile: None,
                            in_kev: None,
                        });
                    }
                } else {
                    // Advisory-only if no CVE mapping found yet
                    out.push(Finding {
                        id: osv_id,
                        source_ids,
                        package,
                        confidence_tier: ConfidenceTier::ConfirmedInstalled,
                        evidence_source: EvidenceSource::InstalledDb,
                        accuracy_note: None,
                        fixed,
                        fixed_in: None,
                        recommendation: None,
                        severity: severity_str,
                        cvss,
                        description,
                        evidence,
                        references,
                        confidence: Some("LOW".into()),
                        epss_score: None,
                        epss_percentile: None,
                        in_kev: None,
                    });
                }
            }
        }
    }
    out
}

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
fn osv_apply_payload_to_findings(id: &str, json: &Value, findings: &mut Vec<Finding>) {
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
        if let Some(mut mapped) = map_debian_advisory_to_cves(id) {
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
fn osv_fetch_parallel(ids: &[String], client: &Client) -> std::collections::HashMap<String, Value> {
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
                        Some((id.clone(), v))
                    }
                    Err(_) => None,
                },
                _ => None,
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

fn drop_fixed_findings(findings: &mut Vec<Finding>) -> usize {
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

fn dedupe_findings_by_id_and_package(findings: &mut Vec<Finding>) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(finding_dedupe_key(f)));
}

/// Enrich findings with details from OSV /v1/vulns/{id} (fills description, severity, references)
pub fn osv_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
    if !env_bool("SCANNER_OSV_ENRICH", true) {
        progress("osv.fetch.skip", "disabled by SCANNER_OSV_ENRICH");
        return;
    }
    if findings.is_empty() {
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

    // Phase 1: PG cache lookup (sequential — PgClient is not Send)
    let phase_pg_started = std::time::Instant::now();
    let mut pg_cache_hits: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();
    let mut needs_fetch: Vec<String> = Vec::new();
    let mut skipped_cve_fetch = 0usize;
    for id in &unique_ids {
        if id.starts_with("CVE-") && !fetch_cve_details {
            skipped_cve_fetch += 1;
            continue;
        }
        let mut pg_hit = false;
        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_osv(client_pg, id) {
                let ttl_days = compute_dynamic_ttl_days(last_mod, 14);
                if Utc::now() - last_checked < ChronoDuration::days(ttl_days) {
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
    let fetched = osv_fetch_parallel(&needs_fetch, &client);
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

    // Phase 4: Build combined payloads map (PG hits + freshly fetched)
    let all_payloads: std::collections::HashMap<String, Value> =
        pg_cache_hits.into_iter().chain(fetched).collect();

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
            "osv.fetch.start",
            &format!("{}/{} {}", idx + 1, total_apply, id),
        );
        if let Some(json) = all_payloads.get(&id) {
            osv_apply_payload_to_findings(&id, json, findings);
            progress("osv.fetch.ok", &id);
        }
    }
    progress_timing("osv.enrich.apply", phase_apply_started);

    // Advisory-level enrichment for Red Hat errata IDs (RHSA/RHBA/RHEA).
    // This fills severity/cvss/description/references so they don't stay as empty "Other" rows.
    redhat_enrich_findings(findings, pg);
    // CVE-level Red Hat enrichment computes package applicability and fixed package versions.
    redhat_enrich_cve_findings(findings, pg);
    // First-class distro advisory enrichment for Debian/Ubuntu/Alpine.
    distro_feed_enrich_findings(findings);
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

fn map_debian_advisory_to_cves(advisory_id: &str) -> Option<Vec<String>> {
    // Fetch Debian tracker page and extract CVE IDs
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
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in re.find_iter(&body) {
        set.insert(m.as_str().to_string());
    }
    Some(set.into_iter().collect())
}

#[derive(Debug, Clone)]
struct DistroFixCandidate {
    fixed_version: String,
    source_id: String,
    reference_url: String,
    note: String,
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

fn cached_http_json(url: &str, tag: &str, ttl_secs: i64, timeout_secs: u64) -> Option<Value> {
    let cache_dir = std::env::var_os("SCANNER_CACHE").map(PathBuf::from);
    let key = cache_key(&["distro_feed", tag, url]);
    if let Some(bytes) = cache_get(cache_dir.as_deref(), &key) {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            // New wrapper format: {"fetched_at": <unix>, "payload": {...}}
            if let (Some(fetched_at), Some(payload)) = (
                v.get("fetched_at").and_then(|x| x.as_i64()),
                v.get("payload"),
            ) {
                if Utc::now().timestamp().saturating_sub(fetched_at) <= ttl_secs {
                    return Some(payload.clone());
                }
            } else if v.is_object() || v.is_array() {
                // Backward compatibility if older cache writes raw JSON.
                return Some(v);
            }
        }
    }

    let client = build_http_client(timeout_secs);
    let resp = client.get(url).send().ok()?;
    if !resp.status().is_success() {
        progress(
            "distro.feed.http.err",
            &format!("tag={} status={} url={}", tag, resp.status(), url),
        );
        return None;
    }
    let payload: Value = resp.json().ok()?;
    let wrapped = serde_json::json!({
        "fetched_at": Utc::now().timestamp(),
        "payload": payload
    });
    cache_put(cache_dir.as_deref(), &key, wrapped.to_string().as_bytes());
    wrapped.get("payload").cloned()
}

fn is_cve_id(id: &str) -> bool {
    id.starts_with("CVE-")
}

fn pkg_cve_key(pkg: &str, cve: &str) -> String {
    format!("{}|{}", pkg.to_ascii_lowercase(), cve.to_ascii_uppercase())
}

fn select_best_candidate(
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

fn build_ubuntu_candidate_index(
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

fn distro_feed_enrich_findings(findings: &mut Vec<Finding>) {
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
        if pkg.ecosystem == "deb" {
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
        let idx = load_ubuntu_notices_data()
            .map(|v| build_ubuntu_candidate_index(&v, &needed_ubuntu_keys))
            .unwrap_or_default();
        progress_timing("distro.ubuntu.enrich", started);
        idx
    } else {
        HashMap::new()
    };

    let debian_index = if debian_enabled && !needed_deb.is_empty() {
        let started = std::time::Instant::now();
        let idx = load_debian_tracker_data()
            .map(|v| build_debian_candidate_index(&v, &needed_deb))
            .unwrap_or_default();
        progress_timing("distro.debian.enrich", started);
        idx
    } else {
        HashMap::new()
    };

    let alpine_index = if alpine_enabled && !needed_alpine_keys.is_empty() {
        let started = std::time::Instant::now();
        let idx =
            build_alpine_candidate_index(&needed_alpine_keys, &needed_apk_pkgs, &needed_apk_cves);
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

        if ecosystem != "deb" {
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

fn normalize_redhat_errata_id(id: &str) -> String {
    id.trim()
        .to_ascii_uppercase()
        .replace("%3A", ":")
        .replace("%3a", ":")
}

fn retain_relevant_redhat_source_ids(source_ids: &mut Vec<String>, keep: Option<&str>) {
    source_ids.retain(|sid| {
        let norm = normalize_redhat_errata_id(sid);
        if is_redhat_errata_id(&norm) {
            return keep.map(|k| norm.eq_ignore_ascii_case(k)).unwrap_or(false);
        }
        true
    });
}

fn extract_redhat_errata_from_url(url: &str) -> Option<String> {
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

fn retain_relevant_redhat_references(refs: &mut Vec<ReferenceInfo>, keep: Option<&str>) {
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

fn is_redhat_family_ecosystem(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "redhat" | "rpm" | "centos" | "rocky" | "almalinux"
    )
}

fn normalize_reference_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    urlencoding::decode(trimmed)
        .map(|v| v.into_owned())
        .unwrap_or_else(|_| trimmed.to_string())
}

fn append_unique_references(dest: &mut Vec<ReferenceInfo>, refs: Vec<ReferenceInfo>) {
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

fn is_redhat_errata_id(id: &str) -> bool {
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

fn normalize_redhat_severity(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    if up.is_empty() {
        return None;
    }
    let mapped = match up.as_str() {
        "IMPORTANT" => "HIGH",
        "MODERATE" => "MEDIUM",
        "LOW" => "LOW",
        "MEDIUM" => "MEDIUM",
        "HIGH" => "HIGH",
        "CRITICAL" => "CRITICAL",
        _ => up.as_str(),
    };
    Some(mapped.to_string())
}

fn redhat_cvss_from_vuln(vuln: &Value) -> Option<CvssInfo> {
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

fn redhat_note_text(document: &Value) -> Option<String> {
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
struct RedHatFixedRelease {
    advisory: Option<String>,
    package_name: String,
    fixed_evr: String,
}

#[derive(Debug, Clone)]
struct RedHatPackageState {
    package_name: String,
    fix_state: String,
    cpe: Option<String>,
}

fn parse_redhat_release_package(raw: &str) -> Option<(String, String)> {
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

fn parse_redhat_package_states(json: &Value) -> Vec<RedHatPackageState> {
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

fn parse_redhat_cve_cvss(json: &Value) -> Option<CvssInfo> {
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

fn redhat_cve_references(json: &Value) -> Vec<ReferenceInfo> {
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

fn rpm_epoch(evr: &str) -> i64 {
    evr.split_once(':')
        .and_then(|(lhs, _)| lhs.parse::<i64>().ok())
        .unwrap_or(0)
}

fn extract_el_tag(text: &str) -> Option<String> {
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

fn extract_rhel_major_from_cpe(cpe: &str) -> Option<String> {
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

fn extract_rhel_major_from_version(version: &str) -> Option<String> {
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

fn strip_rpm_arch_suffix(name: &str) -> String {
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

fn package_name_matches(installed: &str, candidate: &str) -> bool {
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

fn parse_redhat_fixed_releases(json: &Value) -> Vec<RedHatFixedRelease> {
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

fn best_redhat_fixed_release(
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

fn best_redhat_package_state(
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

fn redhat_enrich_cve_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
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

fn redhat_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
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
        progress("redhat.pkg.cve.skip", "disabled by SCANNER_REDHAT_UNFIXED_SKIP");
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

    if let Some(c) = pg.as_mut() {
        pg_init_schema(c);
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
            query_to_packages
                .entry(qname)
                .or_default()
                .push((pkg.name.clone(), pkg.version.clone(), pkg.ecosystem.clone()));
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
        let Some(pkg_attribs) = query_to_packages.get(&qname) else { continue };
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
                if !existing_keys.contains(&key) {
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
        progress("redhat.pkg.cve.done", "injected=0 (no new CVEs from pkg list)");
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
    let ttl_days: i64 = std::env::var("SCANNER_REDHAT_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

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

    // Parallel fetch for cache misses.
    if !to_fetch.is_empty() {
        progress(
            "redhat.pkg.cve.fetch",
            &format!("fetching={}/{}", to_fetch.len(), total_new),
        );
        let fetch_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_concurrent)
            .build()
            .ok();

        let fetched: Vec<(String, Value, Option<DateTime<Utc>>)> = if let Some(pool) = fetch_pool {
            pool.install(|| {
                to_fetch
                    .par_iter()
                    .filter_map(|cve_id| {
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
                                        let bytes = serde_json::to_vec(&v).unwrap_or_default();
                                        if !bytes.is_empty() {
                                            let cd = resolve_enrich_cache_dir();
                                            cache_put(cd.as_deref(), &cache_tag, &bytes);
                                        }
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
        for (id, json, lm) in fetched {
            if let Some(c) = pg.as_mut() {
                pg_put_redhat_cve(c, &id, &json, lm);
            }
            id_to_json.insert(id, json);
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
            let best_state: Option<&RedHatPackageState> = if let Some(ref rhel_str) = rhel_major_str {
                // Only accept an entry matching both package name AND this RHEL version via CPE.
                package_states
                    .iter()
                    .find(|s| {
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

pub fn enrich_findings_with_nvd(
    findings: &mut Vec<Finding>,
    api_key: Option<&str>,
    pg: &mut Option<PgClient>,
) {
    if !env_bool("SCANNER_NVD_ENRICH", true) {
        progress("nvd.fetch.skip", "disabled by SCANNER_NVD_ENRICH");
        return;
    }
    if findings.is_empty() {
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
    let ttl_days: i64 = std::env::var("SCANNER_NVD_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);

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
    for (idx, id) in unique_ids.into_iter().enumerate() {
        let mut served_from_cache = false;
        if let Some(client) = pg.as_mut() {
            if let Some((payload, last_checked_at, nvd_last_modified)) = pg_get_cve(client, &id) {
                let ttl_dyn_days =
                    compute_dynamic_ttl_days(nvd_last_modified, ttl_days as i64) as i64;
                if Utc::now() - last_checked_at < ChronoDuration::days(ttl_dyn_days) {
                    id_to_json.insert(id.clone(), payload);
                    progress("nvd.cache.pg.hit", &id);
                    served_from_cache = true;
                }
            }
        }
        if !served_from_cache {
            to_fetch.push((idx, id));
        }
    }
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
        let fetched: Vec<(String, Value, Option<DateTime<Utc>>)> = pool.install(|| {
            to_fetch
                .par_iter()
                .filter_map(|(idx, id)| {
                    progress("nvd.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
                    let url = format!(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
                        id
                    );
                    match nvd_get_json(&url, api_key, &format!("cveId:{}", id), sleep_ms) {
                        Some(json) => {
                            let lm = parse_nvd_last_modified(&json);
                            Some((id.clone(), json, lm))
                        }
                        None => {
                            progress("nvd.fetch.err", id);
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
                    progress("nvd.fetch.ok", &id);
                }
                None => {
                    progress("nvd.fetch.err", &id);
                }
            }
        }
    }
    progress_timing("nvd.enrich.fetch", fetch_started);

    // Apply enrichment
    let apply_started = std::time::Instant::now();
    for f in findings.iter_mut() {
        // If not in memory map and PG is configured, try PG (from parallel fetch path)
        if !id_to_json.contains_key(&f.id) {
            if let Some(client) = pg.as_mut() {
                if let Some((payload, _lc, _lm)) = pg_get_cve(client, &f.id) {
                    id_to_json.insert(f.id.clone(), payload);
                }
            }
        }
        if let Some(wrapper) = id_to_json.get(&f.id) {
            if let Some(items) = wrapper["vulnerabilities"].as_array() {
                if let Some(item) = items.first() {
                    let cve = &item["cve"];
                    if let Some(cvss3) = cve["metrics"]["cvssMetricV31"]
                        .as_array()
                        .and_then(|a| a.first())
                        .or_else(|| {
                            cve["metrics"]["cvssMetricV30"]
                                .as_array()
                                .and_then(|a| a.first())
                        })
                    {
                        // vector/score
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
                        // explicit severity if provided
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
    }
    progress_timing("nvd.enrich.apply", apply_started);
}

/// Query NVD by keyword (component + version) and map to findings. Useful fallback when OSV has no package context.
pub fn nvd_keyword_findings(
    component: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(&keyword)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("kw:{}", keyword), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .map(|s| s.to_string());

            // Prefer CVSS v3.1, then v3.0, then v2
            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|a| a.first())
                .or_else(|| {
                    cve["metrics"]["cvssMetricV30"]
                        .as_array()
                        .and_then(|a| a.first())
                })
                .or_else(|| {
                    cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                })
            {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                cvss = Some(CvssInfo {
                    base,
                    vector: vector.clone(),
                });
                severity = Some(severity_from_score(base).to_string());
            }

            let evidence = vec![EvidenceItem {
                evidence_type: "hint".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(format!("keyword match: {} {}", component, version)),
            }];

            let mut references: Vec<ReferenceInfo> = Vec::new();
            if let Some(refs) = cve["references"]["referenceData"].as_array() {
                for r in refs {
                    if let Some(url) = r["url"].as_str() {
                        references.push(ReferenceInfo {
                            reference_type: "nvd".into(),
                            url: url.to_string(),
                        });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:keyword:{} {}", component, version)],
                package: Some(PackageInfo {
                    name: component.to_string(),
                    ecosystem: "nvd".into(),
                    version: version.to_string(),
                }),
                confidence_tier: ConfidenceTier::HeuristicUnverified,
                evidence_source: EvidenceSource::BinaryHeuristic,
                accuracy_note: Some(
                    "Derived via keyword heuristic; installed package inventory was not proven."
                        .into(),
                ),
                fixed: None,
                fixed_in: None,
                recommendation: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("MEDIUM".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
        }
    }
    out
}

/// Query NVD by CPE name constructed from component/version (best-effort)
pub fn nvd_cpe_findings(
    component: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let vendor = component.to_lowercase();
    let product = component.to_lowercase();
    let cpe = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}",
        urlencoding::encode(&cpe)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("cpe:{}", cpe), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .map(|s| s.to_string());

            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|a| a.first())
                .or_else(|| {
                    cve["metrics"]["cvssMetricV30"]
                        .as_array()
                        .and_then(|a| a.first())
                })
                .or_else(|| {
                    cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                })
            {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                cvss = Some(CvssInfo {
                    base,
                    vector: vector.clone(),
                });
                severity = Some(severity_from_score(base).to_string());
            }

            let evidence = vec![EvidenceItem {
                evidence_type: "cpe".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(cpe.clone()),
            }];

            let mut references: Vec<ReferenceInfo> = Vec::new();
            if let Some(refs) = cve["references"]["referenceData"].as_array() {
                for r in refs {
                    if let Some(url) = r["url"].as_str() {
                        references.push(ReferenceInfo {
                            reference_type: "nvd".into(),
                            url: url.to_string(),
                        });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:cpe:{} {}", component, version)],
                package: Some(PackageInfo {
                    name: component.to_string(),
                    ecosystem: "nvd".into(),
                    version: version.to_string(),
                }),
                confidence_tier: ConfidenceTier::HeuristicUnverified,
                evidence_source: EvidenceSource::BinaryHeuristic,
                accuracy_note: Some(
                    "Derived via CPE heuristic; installed package inventory was not proven.".into(),
                ),
                fixed: None,
                fixed_in: None,
                recommendation: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("MEDIUM".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
        }
    }
    out
}

/// NVD keyword search by name only (low confidence). Useful when version unknown or not indexed.
pub fn nvd_keyword_findings_name(
    component: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(component)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("kw_only:{}", component), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"]
                .as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str())
                .map(|s| s.to_string());

            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|a| a.first())
                .or_else(|| {
                    cve["metrics"]["cvssMetricV30"]
                        .as_array()
                        .and_then(|a| a.first())
                })
                .or_else(|| {
                    cve["metrics"]["cvssMetricV2"]
                        .as_array()
                        .and_then(|a| a.first())
                })
            {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                cvss = Some(CvssInfo {
                    base,
                    vector: vector.clone(),
                });
                severity = Some(severity_from_score(base).to_string());
            }

            let evidence = vec![EvidenceItem {
                evidence_type: "hint".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(format!("keyword match: {}", component)),
            }];

            let mut references: Vec<ReferenceInfo> = Vec::new();
            if let Some(refs) = cve["references"]["referenceData"].as_array() {
                for r in refs {
                    if let Some(url) = r["url"].as_str() {
                        references.push(ReferenceInfo {
                            reference_type: "nvd".into(),
                            url: url.to_string(),
                        });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:keyword:{}", component)],
                package: Some(PackageInfo {
                    name: component.to_string(),
                    ecosystem: "nvd".into(),
                    version: "unknown".into(),
                }),
                confidence_tier: ConfidenceTier::HeuristicUnverified,
                evidence_source: EvidenceSource::BinaryHeuristic,
                accuracy_note: Some(
                    "Derived via keyword heuristic; installed package inventory was not proven."
                        .into(),
                ),
                fixed: None,
                fixed_in: None,
                recommendation: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("LOW".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
        }
    }
    out
}

fn tokenize_version(v: &str) -> Vec<i64> {
    v.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<i64>().unwrap_or(-1))
        .collect()
}

fn cmp_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let ta = tokenize_version(a);
    let tb = tokenize_version(b);
    let len = ta.len().max(tb.len());
    for i in 0..len {
        let va = *ta.get(i).unwrap_or(&0);
        let vb = *tb.get(i).unwrap_or(&0);
        if va < vb {
            return Ordering::Less;
        }
        if va > vb {
            return Ordering::Greater;
        }
    }
    Ordering::Equal
}

fn is_version_in_range(
    target: &str,
    start_inc: Option<&str>,
    start_exc: Option<&str>,
    end_inc: Option<&str>,
    end_exc: Option<&str>,
) -> bool {
    if let Some(s) = start_inc {
        if cmp_versions(target, s) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(s) = start_exc {
        if cmp_versions(target, s) != std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(e) = end_inc {
        if cmp_versions(target, e) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(e) = end_exc {
        if cmp_versions(target, e) != std::cmp::Ordering::Less {
            return false;
        }
    }
    true
}

fn cpe_parts(criteria: &str) -> Option<(String, String, Option<String>)> {
    // cpe:2.3:a:vendor:product:version:...
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() >= 5 {
        Some((
            parts[3].to_string(),
            parts[4].to_string(),
            Some(parts[5].to_string()),
        ))
    } else {
        None
    }
}

/// Broader NVD search for vendor/product and filter by version ranges in CPEs
pub fn nvd_findings_by_product_version(
    vendor: &str,
    product: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
) -> Vec<Finding> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=2000",
        urlencoding::encode(product)
    );
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("prod:{}", product), sleep_ms) {
        Some(j) => j,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        'outer: for item in items {
            let cve = &item["cve"];
            let mut matches_product = false;
            if let Some(nodes) = cve["configurations"]
                .get("nodes")
                .and_then(|n| n.as_array())
            {
                for node in nodes {
                    if let Some(cpes) = node.get("cpeMatch").and_then(|m| m.as_array()) {
                        for c in cpes {
                            let criteria = c.get("criteria").and_then(|s| s.as_str()).unwrap_or("");
                            if let Some((ven, prod, ver_opt)) = cpe_parts(criteria) {
                                if ven.eq_ignore_ascii_case(vendor)
                                    && prod.eq_ignore_ascii_case(product)
                                {
                                    matches_product = true;
                                    let vulnerable = c
                                        .get("vulnerable")
                                        .and_then(|b| b.as_bool())
                                        .unwrap_or(false);
                                    if !vulnerable {
                                        continue;
                                    }
                                    let start_inc =
                                        c.get("versionStartIncluding").and_then(|s| s.as_str());
                                    let start_exc =
                                        c.get("versionStartExcluding").and_then(|s| s.as_str());
                                    let end_inc =
                                        c.get("versionEndIncluding").and_then(|s| s.as_str());
                                    let end_exc =
                                        c.get("versionEndExcluding").and_then(|s| s.as_str());
                                    // If criteria has exact version and no ranges, compare directly
                                    if start_inc.is_none()
                                        && start_exc.is_none()
                                        && end_inc.is_none()
                                        && end_exc.is_none()
                                    {
                                        if let Some(ver) = ver_opt.as_deref() {
                                            if ver != "*"
                                                && cmp_versions(version, ver)
                                                    != std::cmp::Ordering::Equal
                                            {
                                                continue;
                                            }
                                        }
                                    } else {
                                        if !is_version_in_range(
                                            version, start_inc, start_exc, end_inc, end_exc,
                                        ) {
                                            continue;
                                        }
                                    }

                                    // Build finding
                                    let id = cve["id"].as_str().unwrap_or("unknown").to_string();
                                    let description = cve["descriptions"]
                                        .as_array()
                                        .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                                        .and_then(|d| d["value"].as_str())
                                        .map(|s| s.to_string());
                                    let mut cvss: Option<CvssInfo> = None;
                                    let mut severity: Option<String> = None;
                                    if let Some(m) = cve["metrics"]["cvssMetricV31"]
                                        .as_array()
                                        .and_then(|a| a.first())
                                        .or_else(|| {
                                            cve["metrics"]["cvssMetricV30"]
                                                .as_array()
                                                .and_then(|a| a.first())
                                        })
                                        .or_else(|| {
                                            cve["metrics"]["cvssMetricV2"]
                                                .as_array()
                                                .and_then(|a| a.first())
                                        })
                                    {
                                        let base =
                                            m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0)
                                                as f32;
                                        let vector = m["cvssData"]["vectorString"]
                                            .as_str()
                                            .unwrap_or("")
                                            .to_string();
                                        cvss = Some(CvssInfo {
                                            base,
                                            vector: vector.clone(),
                                        });
                                        severity = Some(severity_from_score(base).to_string());
                                    }
                                    let evidence = vec![EvidenceItem {
                                        evidence_type: "cpe".into(),
                                        path: evidence_path.map(|s| s.to_string()),
                                        detail: Some(criteria.to_string()),
                                    }];
                                    let mut references: Vec<ReferenceInfo> = Vec::new();
                                    if let Some(refs) =
                                        cve["references"]["referenceData"].as_array()
                                    {
                                        for r in refs {
                                            if let Some(url) = r["url"].as_str() {
                                                references.push(ReferenceInfo {
                                                    reference_type: "nvd".into(),
                                                    url: url.to_string(),
                                                });
                                            }
                                        }
                                    }
                                    out.push(Finding {
                                        id,
                                        source_ids: vec![format!(
                                            "heuristic:product:{} {} {}",
                                            vendor, product, version
                                        )],
                                        package: Some(PackageInfo {
                                            name: product.to_string(),
                                            ecosystem: "nvd".into(),
                                            version: version.to_string(),
                                        }),
                                        confidence_tier: ConfidenceTier::HeuristicUnverified,
                                        evidence_source: EvidenceSource::BinaryHeuristic,
                                        accuracy_note: Some(
                                            "Derived via product/version heuristic; installed package inventory was not proven."
                                                .into(),
                                        ),
                                        fixed: None,
                                        fixed_in: None,
                                        recommendation: None,
                                        severity,
                                        cvss,
                                        description,
                                        evidence,
                                        references,
                                        confidence: Some("MEDIUM".into()),
                                        epss_score: None,
                                        epss_percentile: None,
                                        in_kev: None,
                                    });
                                    continue 'outer;
                                }
                            }
                        }
                    }
                }
            }
            let _ = matches_product; // silence warning if unused
        }
    }
    out
}

fn nvd_get_json(url: &str, api_key: Option<&str>, cache_tag: &str, sleep_ms: u64) -> Option<Value> {
    let skip_cache = env_bool("SCANNER_SKIP_CACHE", false);
    let key = cache_key(&["nvd", cache_tag, url]);
    if !skip_cache {
        if let Some(bytes) = cache_get(
            std::env::var_os("SCANNER_CACHE")
                .as_deref()
                .map(PathBuf::from)
                .as_deref(),
            &key,
        ) {
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                return Some(v);
            }
        }
    }

    let client = nvd_http_client();
    let attempts = nvd_retry_max().max(1);
    for attempt in 1..=attempts {
        if sleep_ms > 0 {
            sleep(Duration::from_millis(sleep_ms));
        }
        wait_for_global_nvd_rate_slot(api_key);

        let mut req = client.get(url).header("Accept", "application/json");
        if let Some(k) = api_key {
            req = req.header("apiKey", k).header("X-Api-Key", k);
        }

        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                let retry_ms = retry_backoff_with_jitter_ms(attempt);
                progress(
                    "nvd.http.err",
                    &format!(
                        "attempt={} err={} retry_ms={} url={}",
                        attempt, e, retry_ms, url
                    ),
                );
                if attempt >= attempts {
                    return None;
                }
                if retry_ms > 0 {
                    sleep(Duration::from_millis(retry_ms));
                }
                continue;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let rem = resp
                .headers()
                .get("X-RateLimit-Remaining")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let lim = resp
                .headers()
                .get("X-RateLimit-Limit")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let retryable =
                status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            let retry_after_ms = parse_retry_after_ms(&resp).unwrap_or(0);
            let jitter_ms = retry_backoff_with_jitter_ms(attempt);
            let wait_ms = retry_after_ms.max(jitter_ms);
            progress(
                "nvd.http.err",
                &format!(
                    "attempt={} status={} remaining={} limit={} retryable={} wait_ms={} url={}",
                    attempt, status, rem, lim, retryable, wait_ms, url
                ),
            );

            if retryable && attempt < attempts {
                if wait_ms > 0 {
                    sleep(Duration::from_millis(wait_ms));
                }
                continue;
            }
            return None;
        }

        adjust_rate_limits(&resp);
        let v: Value = match resp.json() {
            Ok(j) => j,
            Err(e) => {
                let retry_ms = retry_backoff_with_jitter_ms(attempt);
                progress(
                    "nvd.json.err",
                    &format!(
                        "attempt={} err={} retry_ms={} url={}",
                        attempt, e, retry_ms, url
                    ),
                );
                if attempt >= attempts {
                    return None;
                }
                if retry_ms > 0 {
                    sleep(Duration::from_millis(retry_ms));
                }
                continue;
            }
        };

        if !skip_cache {
            cache_put(
                std::env::var_os("SCANNER_CACHE")
                    .as_deref()
                    .map(PathBuf::from)
                    .as_deref(),
                &key,
                v.to_string().as_bytes(),
            );
        }
        return Some(v);
    }

    None
}

fn adjust_rate_limits(resp: &Response) {
    if let Some(rem) = resp.headers().get("X-RateLimit-Remaining") {
        if let Ok(rem_str) = rem.to_str() {
            if let Ok(remaining) = rem_str.parse::<i64>() {
                if remaining <= 1 {
                    // back off hard if we are at the edge
                    std::env::set_var("SCANNER_NVD_SLEEP_MS", "7000");
                } else if remaining < 10 {
                    std::env::set_var("SCANNER_NVD_SLEEP_MS", "3000");
                }
            }
        }
    }
}

// --- Postgres helpers ---
pub fn pg_connect() -> Option<PgClient> {
    let raw_url = std::env::var("DATABASE_URL").ok()?;
    // Support schema in URL via ?schema=..., but strip it before connecting (postgres crate rejects unknown params)
    let (clean_url, schema_in_url) = strip_param_from_url(&raw_url, "schema");
    progress("nvd.cache.pg.connect.start", "");
    match PgClient::connect(&clean_url, NoTls) {
        Ok(mut client) => {
            // Determine schema from URL or env override
            let schema = schema_in_url.or_else(|| std::env::var("SCANNER_PG_SCHEMA").ok());
            if let Some(schema) = schema {
                let _ = client.execute(&*format!("SET search_path TO {}", schema), &[]);
                progress("nvd.cache.pg.search_path", &schema);
            }
            progress("nvd.cache.pg.connect.ok", "");
            Some(client)
        }
        Err(e) => {
            progress("nvd.cache.pg.connect.err", &format!("{}", e));
            None
        }
    }
}

pub fn pg_init_schema(client: &mut PgClient) {
    let res = client.batch_execute(
        "CREATE TABLE IF NOT EXISTS nvd_cve_cache (\n            cve_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            nvd_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS osv_vuln_cache (\n            vuln_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            osv_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS redhat_csaf_cache (\n            errata_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            redhat_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS redhat_cve_cache (\n            cve_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            redhat_last_modified TIMESTAMPTZ\n        );\n        CREATE INDEX IF NOT EXISTS idx_nvd_cve_cache_last_checked ON nvd_cve_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_osv_vuln_cache_last_checked ON osv_vuln_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_redhat_csaf_cache_last_checked ON redhat_csaf_cache (last_checked_at);\n        CREATE INDEX IF NOT EXISTS idx_redhat_cve_cache_last_checked ON redhat_cve_cache (last_checked_at);"
    );
    match res {
        Ok(_) => progress("nvd.cache.pg.init.ok", ""),
        Err(e) => progress("nvd.cache.pg.init.err", &format!("{}", e)),
    }
}

fn strip_param_from_url(url: &str, key: &str) -> (String, Option<String>) {
    let mut parts = url.splitn(2, '?');
    let base = parts.next().unwrap_or("");
    if let Some(query) = parts.next() {
        let mut kept: Vec<String> = Vec::new();
        let mut found: Option<String> = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == key {
                if !v.is_empty() {
                    found = Some(v.to_string());
                }
                continue;
            }
            kept.push(format!("{}={}", k, v));
        }
        if kept.is_empty() {
            (base.to_string(), found)
        } else {
            (format!("{}?{}", base, kept.join("&")), found)
        }
    } else {
        (url.to_string(), None)
    }
}

fn parse_nvd_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let s = json["vulnerabilities"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|it| it["cve"]["lastModified"].as_str())?;
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // If missing timezone, try appending Z
    if !s.ends_with('Z') {
        let mut t = String::from(s);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    // Try naive formats
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

fn parse_osv_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let s = json["modified"].as_str()?; // OSV schema top-level
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if !s.ends_with('Z') {
        let mut t = String::from(s);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

fn parse_redhat_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let tracking = json.get("document").and_then(|d| d.get("tracking"));
    let ts = tracking
        .and_then(|t| t.get("current_release_date"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            tracking
                .and_then(|t| t.get("initial_release_date"))
                .and_then(|v| v.as_str())
        })?;
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.with_timezone(&Utc));
    }
    if !ts.ends_with('Z') {
        let mut t = String::from(ts);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

fn parse_redhat_cve_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let ts = json
        .get("public_date")
        .and_then(|v| v.as_str())
        .or_else(|| {
            json.get("affected_release")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .filter_map(|x| x.get("release_date").and_then(|v| v.as_str()))
                        .max()
                })
        })?;
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.with_timezone(&Utc));
    }
    if !ts.ends_with('Z') {
        let mut t = String::from(ts);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

fn compute_dynamic_ttl_days(last_mod: Option<DateTime<Utc>>, default_days: i64) -> i64 {
    let min_days: i64 = std::env::var("SCANNER_TTL_MIN_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    let max_days: i64 = std::env::var("SCANNER_TTL_MAX_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);
    if let Some(lm) = last_mod {
        let age_days = (Utc::now() - lm).num_days().clamp(1, 3650);
        age_days.clamp(min_days, max_days)
    } else {
        default_days.clamp(min_days, max_days)
    }
}

fn pg_get_osv(
    client: &mut PgClient,
    vuln_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client.query_opt(
        "SELECT payload, last_checked_at, osv_last_modified FROM osv_vuln_cache WHERE vuln_id = $1",
        &[&vuln_id]
    ).ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let osv_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, osv_last_modified))
}

fn pg_put_osv(
    client: &mut PgClient,
    vuln_id: &str,
    payload: &Value,
    osv_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO osv_vuln_cache (vuln_id, payload, last_checked_at, osv_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (vuln_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), osv_last_modified = EXCLUDED.osv_last_modified",
        &[&vuln_id, &payload, &osv_last_modified]
    );
    match res {
        Ok(_) => progress(
            "osv.cache.pg.put",
            &format!(
                "{} lm={}",
                vuln_id,
                osv_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("osv.cache.pg.put.err", &format!("{} {}", vuln_id, e)),
    }
}

fn pg_get_cve(
    client: &mut PgClient,
    cve_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client.query_opt(
        "SELECT payload, last_checked_at, nvd_last_modified FROM nvd_cve_cache WHERE cve_id = $1",
        &[&cve_id]
    ).ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let nvd_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, nvd_last_modified))
}

fn pg_get_redhat(
    client: &mut PgClient,
    errata_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client
        .query_opt(
            "SELECT payload, last_checked_at, redhat_last_modified FROM redhat_csaf_cache WHERE errata_id = $1",
            &[&errata_id],
        )
        .ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let redhat_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, redhat_last_modified))
}

fn pg_get_redhat_cve(
    client: &mut PgClient,
    cve_id: &str,
) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client
        .query_opt(
            "SELECT payload, last_checked_at, redhat_last_modified FROM redhat_cve_cache WHERE cve_id = $1",
            &[&cve_id],
        )
        .ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let redhat_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, redhat_last_modified))
}

fn pg_put_cve(
    client: &mut PgClient,
    cve_id: &str,
    payload: &Value,
    nvd_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO nvd_cve_cache (cve_id, payload, last_checked_at, nvd_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), nvd_last_modified = EXCLUDED.nvd_last_modified",
        &[&cve_id, &payload, &nvd_last_modified]
    );
    match res {
        Ok(_) => progress(
            "nvd.cache.pg.put",
            &format!(
                "{} lm={}",
                cve_id,
                nvd_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("nvd.cache.pg.put.err", &format!("{} {}", cve_id, e)),
    }
}

fn pg_put_redhat(
    client: &mut PgClient,
    errata_id: &str,
    payload: &Value,
    redhat_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO redhat_csaf_cache (errata_id, payload, last_checked_at, redhat_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (errata_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), redhat_last_modified = EXCLUDED.redhat_last_modified",
        &[&errata_id, &payload, &redhat_last_modified],
    );
    match res {
        Ok(_) => progress(
            "redhat.cache.pg.put",
            &format!(
                "{} lm={}",
                errata_id,
                redhat_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("redhat.cache.pg.put.err", &format!("{} {}", errata_id, e)),
    }
}

fn pg_put_redhat_cve(
    client: &mut PgClient,
    cve_id: &str,
    payload: &Value,
    redhat_last_modified: Option<DateTime<Utc>>,
) {
    let res = client.execute(
        "INSERT INTO redhat_cve_cache (cve_id, payload, last_checked_at, redhat_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), redhat_last_modified = EXCLUDED.redhat_last_modified",
        &[&cve_id, &payload, &redhat_last_modified],
    );
    match res {
        Ok(_) => progress(
            "redhat.cve.cache.pg.put",
            &format!(
                "{} lm={}",
                cve_id,
                redhat_last_modified
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "null".into())
            ),
        ),
        Err(e) => progress("redhat.cve.cache.pg.put.err", &format!("{} {}", cve_id, e)),
    }
}

/// Returns the cache directory for enrichment functions to use from other modules.
pub fn resolve_enrich_cache_dir() -> Option<PathBuf> {
    std::env::var("SCANNER_CACHE").ok().map(PathBuf::from)
}

// ─── EPSS enrichment ───────────────────────────────────────────────

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

    // Batch in groups of 100
    for chunk in cve_ids.chunks(100) {
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

// ─── CISA KEV enrichment ──────────────────────────────────────────

fn kev_enrich_enabled() -> bool {
    std::env::var("SCANNER_KEV_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Enrich findings with CISA KEV (Known Exploited Vulnerabilities) data.
/// Downloads the full KEV catalog JSON and marks matching findings.
pub fn kev_enrich_findings(findings: &mut [Finding], cache_dir: Option<&std::path::Path>) {
    if !kev_enrich_enabled() {
        progress("kev.enrich.skip", "disabled by SCANNER_KEV_ENRICH");
        return;
    }
    let has_cves = findings.iter().any(|f| f.id.starts_with("CVE-"));
    if !has_cves {
        return;
    }
    progress("kev.enrich.start", "downloading CISA KEV catalog");
    let started = std::time::Instant::now();

    let cache_k = cache_key(&["kev_catalog_v1"]);
    let kev_set: HashSet<String> = if let Some(cached) = cache_get(cache_dir, &cache_k) {
        if let Ok(set) = serde_json::from_slice::<HashSet<String>>(&cached) {
            progress("kev.enrich.cache_hit", &format!("cves={}", set.len()));
            set
        } else {
            match fetch_kev_catalog() {
                Some(set) => {
                    if let Ok(serialized) = serde_json::to_vec(&set) {
                        cache_put(cache_dir, &cache_k, &serialized);
                    }
                    set
                }
                None => return,
            }
        }
    } else {
        match fetch_kev_catalog() {
            Some(set) => {
                if let Ok(serialized) = serde_json::to_vec(&set) {
                    cache_put(cache_dir, &cache_k, &serialized);
                }
                set
            }
            None => return,
        }
    };

    let mut enriched = 0usize;
    for finding in findings.iter_mut() {
        if finding.id.starts_with("CVE-") && kev_set.contains(&finding.id) {
            finding.in_kev = Some(true);
            enriched += 1;
        }
    }
    progress_timing("kev.enrich", started);
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

fn fetch_kev_catalog() -> Option<HashSet<String>> {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    match enrich_http_client().get(url).send() {
        Ok(resp) if resp.status().is_success() => {
            let body: Value = resp.json().ok()?;
            let vulns = body.get("vulnerabilities")?.as_array()?;
            let set: HashSet<String> = vulns
                .iter()
                .filter_map(|v| v.get("cveID").and_then(|c| c.as_str()).map(String::from))
                .collect();
            progress("kev.enrich.catalog_fetched", &format!("cves={}", set.len()));
            Some(set)
        }
        Ok(resp) => {
            progress(
                "kev.enrich.http_error",
                &format!("status={}", resp.status()),
            );
            None
        }
        Err(e) => {
            progress("kev.enrich.error", &format!("{}", e));
            None
        }
    }
}

// ─── Debian Security Tracker enrichment ─────────────────────────────

fn debian_tracker_enabled() -> bool {
    std::env::var("SCANNER_DEBIAN_TRACKER")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Detect the Debian release codename from a set of packages.
/// Returns "bookworm" for Debian 12, "bullseye" for 11, "trixie" for 13, etc.
fn detect_debian_release(packages: &[PackageCoordinate]) -> Option<&'static str> {
    // Check versions — Debian packages include the release codename in certain patterns
    // The most reliable way is from the dpkg status which includes versions like "2.36-9+deb12u9"
    for pkg in packages {
        if pkg.ecosystem != "deb" {
            continue;
        }
        let v = &pkg.version;
        if v.contains("deb13") || v.contains("trixie") {
            return Some("trixie");
        }
        if v.contains("deb12") || v.contains("bookworm") {
            return Some("bookworm");
        }
        if v.contains("deb11") || v.contains("bullseye") {
            return Some("bullseye");
        }
        if v.contains("deb10") || v.contains("buster") {
            return Some("buster");
        }
    }
    // Default to bookworm (Debian 12) as the most common current release
    Some("bookworm")
}

/// Enrich findings from the Debian Security Tracker JSON feed.
///
/// Fetches the full DSA/CVE tracker from `security-tracker.debian.org/tracker/data/json`,
/// caches for 24h, then for each deb package checks which CVEs affect the installed version.
pub fn debian_tracker_enrich(
    packages: &[PackageCoordinate],
    findings: &mut Vec<Finding>,
    cache_dir: Option<&std::path::Path>,
) {
    if !debian_tracker_enabled() {
        progress("debian.tracker.skip", "disabled by SCANNER_DEBIAN_TRACKER");
        return;
    }

    let deb_packages: Vec<&PackageCoordinate> =
        packages.iter().filter(|p| p.ecosystem == "deb").collect();
    if deb_packages.is_empty() {
        return;
    }

    let release = detect_debian_release(packages).unwrap_or("bookworm");
    progress(
        "debian.tracker.start",
        &format!("release={} packages={}", release, deb_packages.len()),
    );

    let existing_cve_pkg: HashSet<(String, String)> = findings
        .iter()
        .filter_map(|f| {
            f.package.as_ref().map(|p| (f.id.clone(), p.name.clone()))
        })
        .collect();

    let tracker_json = match fetch_debian_tracker_json(cache_dir) {
        Ok(v) => v,
        Err(e) => {
            progress("debian.tracker.error", &format!("{}", e));
            return;
        }
    };

    let tracker_obj = match tracker_json.as_object() {
        Some(o) => o,
        None => {
            progress("debian.tracker.error", "expected JSON object");
            return;
        }
    };

    let mut new_count = 0usize;
    for pkg in &deb_packages {
        // Strip epoch from version if present for comparison
        let installed_ver = &pkg.version;

        for (cve_id, cve_data) in tracker_obj {
            if !cve_id.starts_with("CVE-") {
                continue;
            }

            // Check if this CVE affects this package in this release
            let releases = match cve_data.get("releases") {
                Some(r) => r,
                None => continue,
            };
            let release_data = match releases.get(release) {
                Some(r) => r,
                None => continue,
            };
            let pkg_data = match release_data.get(&pkg.name) {
                Some(p) => p,
                None => continue,
            };

            let status = pkg_data
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            let urgency = pkg_data
                .get("urgency")
                .and_then(|u| u.as_str())
                .unwrap_or("");

            // Skip resolved (fixed) entries and unimportant ones
            if status == "resolved" {
                continue;
            }
            if urgency == "unimportant" || urgency == "not yet assigned" {
                // Skip CVEs that Debian has marked as unimportant
                continue;
            }

            // Check if we already have this CVE+package combination
            if existing_cve_pkg.contains(&(cve_id.clone(), pkg.name.clone())) {
                continue;
            }

            // Determine if the installed version is affected
            let fixed_version = pkg_data
                .get("fixed_version")
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty() && *v != "0");

            let is_fixed = if let Some(fv) = fixed_version {
                cmp_versions(installed_ver, fv) != std::cmp::Ordering::Less
            } else {
                false // No fix available yet — vulnerable
            };

            if is_fixed {
                continue;
            }

            let description = cve_data
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());

            let severity = urgency_to_severity(urgency);

            findings.push(Finding {
                id: cve_id.clone(),
                source_ids: vec![format!("DST:{}", cve_id)],
                package: Some(PackageInfo {
                    name: pkg.name.clone(),
                    ecosystem: pkg.ecosystem.clone(),
                    version: pkg.version.clone(),
                }),
                confidence_tier: ConfidenceTier::ConfirmedInstalled,
                evidence_source: EvidenceSource::InstalledDb,
                accuracy_note: Some("From Debian Security Tracker".into()),
                fixed: Some(false),
                fixed_in: fixed_version.map(|s| s.to_string()),
                recommendation: fixed_version.map(|fv| format!("Upgrade to {}", fv)),
                severity: Some(severity.to_string()),
                cvss: None,
                description,
                evidence: vec![EvidenceItem {
                    evidence_type: "debian-tracker".into(),
                    path: None,
                    detail: Some(format!("status={} urgency={}", status, urgency)),
                }],
                references: vec![ReferenceInfo {
                    reference_type: "advisory".into(),
                    url: format!(
                        "https://security-tracker.debian.org/tracker/{}",
                        cve_id
                    ),
                }],
                confidence: Some("HIGH".into()),
                epss_score: None,
                epss_percentile: None,
                in_kev: None,
            });
            new_count += 1;
        }
    }

    progress(
        "debian.tracker.done",
        &format!("new_findings={}", new_count),
    );
}

/// Pre-download the Debian Security Tracker JSON to the local cache for seeding.
pub fn debian_tracker_enrich_seed(cache_dir: &std::path::Path) -> anyhow::Result<()> {
    fetch_debian_tracker_json(Some(cache_dir))?;
    Ok(())
}

/// Pre-warm all distro advisory feeds (Ubuntu USN, Alpine SecDB) into the local cache.
pub fn seed_distro_feeds() {
    // Ubuntu Notices
    progress("seed.distro.ubuntu.start", "");
    let _ubuntu = load_ubuntu_notices_data();
    progress("seed.distro.ubuntu.done", "ok");

    // Alpine SecDB (multiple branches and repos)
    progress("seed.distro.alpine.start", "");
    for branch in alpine_secdb_branches() {
        for repo in &["main", "community"] {
            let _alpine = load_alpine_secdb(&branch, repo);
        }
    }
    progress("seed.distro.alpine.done", "ok");
}

fn urgency_to_severity(urgency: &str) -> &'static str {
    match urgency {
        "high" => "HIGH",
        "medium" => "MEDIUM",
        "low" | "low*" | "low**" => "LOW",
        "end-of-life" => "MEDIUM",
        _ => "MEDIUM",
    }
}

fn fetch_debian_tracker_json(
    cache_dir: Option<&std::path::Path>,
) -> anyhow::Result<serde_json::Value> {
    let cache_key_str = "debian_tracker_json_v1";

    // Check file cache
    if let Some(dir) = cache_dir {
        let cached = dir.join("debian_tracker.json");
        if cached.exists() {
            if let Ok(meta) = std::fs::metadata(&cached) {
                if let Ok(modified) = meta.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();
                    if age < std::time::Duration::from_secs(24 * 3600) {
                        progress("debian.tracker.cache_hit", &cached.to_string_lossy());
                        if let Ok(data) = std::fs::read(&cached) {
                            if let Ok(v) = serde_json::from_slice(&data) {
                                return Ok(v);
                            }
                        }
                    }
                }
            }
        }
    }

    // Fetch from Debian Security Tracker
    progress("debian.tracker.fetch", "https://security-tracker.debian.org/tracker/data/json");
    let client = enrich_http_client();
    let resp = client
        .get("https://security-tracker.debian.org/tracker/data/json")
        .timeout(std::time::Duration::from_secs(120))
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "Debian tracker HTTP {}", resp.status()
        ));
    }

    let bytes = resp.bytes()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;

    // Cache
    if let Some(dir) = cache_dir {
        let _ = std::fs::create_dir_all(dir);
        let cached = dir.join("debian_tracker.json");
        let _ = std::fs::write(&cached, &bytes);
        progress("debian.tracker.cached", &cached.to_string_lossy());
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ConfidenceTier, EvidenceSource, Finding, PackageInfo};

    #[test]
    fn parse_redhat_release_package_handles_name_with_dash() {
        let parsed = parse_redhat_release_package("kernel-rt-4.18.0-193.6.3.rt13.70.el8_2");
        let (name, evr) = parsed.expect("package should parse");
        assert_eq!(name, "kernel-rt");
        assert_eq!(evr, "4.18.0-193.6.3.rt13.70.el8_2");
    }

    #[test]
    fn best_redhat_fixed_release_prefers_matching_el_stream() {
        let pkg = PackageInfo {
            name: "mariadb".into(),
            ecosystem: "redhat".into(),
            version: "3:10.3.25-1.module+el8.10.0+1234".into(),
        };
        let all = vec![
            RedHatFixedRelease {
                advisory: Some("RHSA-2020:4026".into()),
                package_name: "mariadb".into(),
                fixed_evr: "1:5.5.68-1.el7".into(),
            },
            RedHatFixedRelease {
                advisory: Some("RHSA-2020:5654".into()),
                package_name: "mariadb".into(),
                fixed_evr: "3:10.3.27-3.module+el8.2.0+9158".into(),
            },
        ];
        let best = best_redhat_fixed_release(&pkg, &all).expect("best release");
        assert_eq!(best.advisory.as_deref(), Some("RHSA-2020:5654"));
        assert_eq!(best.fixed_evr, "3:10.3.27-3.module+el8.2.0+9158");
    }

    #[test]
    fn best_redhat_fixed_release_rejects_cross_stream_only_match() {
        let pkg = PackageInfo {
            name: "bind-license".into(),
            ecosystem: "redhat".into(),
            version: "32:9.11.4-26.P2.el7".into(),
        };
        let all = vec![RedHatFixedRelease {
            advisory: Some("RHSA-2023:7177".into()),
            package_name: "bind".into(),
            fixed_evr: "32:9.11.36-11.el8_9".into(),
        }];
        assert!(best_redhat_fixed_release(&pkg, &all).is_none());
    }

    #[test]
    fn extract_el_tag_detects_rhel_tag() {
        assert_eq!(
            extract_el_tag("3:10.3.27-3.module+el8.2.0+9158"),
            Some("el8".into())
        );
        assert_eq!(extract_el_tag("1:5.5.68-1.el7"), Some("el7".into()));
        assert_eq!(extract_el_tag("1.2.3"), None);
    }

    #[test]
    fn package_name_matches_rpm_subpackage_to_base_package() {
        assert!(package_name_matches("bind-license", "bind"));
        assert!(package_name_matches("bind-libs.x86_64", "bind"));
        assert!(!package_name_matches("openssl-libs", "bind"));
    }

    #[test]
    fn extract_redhat_errata_from_url_decodes_colon() {
        let url = "https://access.redhat.com/errata/RHSA-2022%3A8162";
        assert_eq!(
            extract_redhat_errata_from_url(url).as_deref(),
            Some("RHSA-2022:8162")
        );
    }

    #[test]
    fn retain_relevant_redhat_references_filters_errata_links() {
        let mut refs = vec![
            ReferenceInfo {
                reference_type: "redhat".into(),
                url: "https://access.redhat.com/errata/RHSA-2022%3A8162".into(),
            },
            ReferenceInfo {
                reference_type: "redhat".into(),
                url: "https://access.redhat.com/security/cve/CVE-2022-0001".into(),
            },
            ReferenceInfo {
                reference_type: "nvd".into(),
                url: "https://nvd.nist.gov/vuln/detail/CVE-2022-0001".into(),
            },
        ];
        retain_relevant_redhat_references(&mut refs, Some("RHSA-2022:8162"));
        assert_eq!(refs.len(), 3);

        retain_relevant_redhat_references(&mut refs, None);
        assert_eq!(refs.len(), 2);
        assert!(refs
            .iter()
            .all(|r| !r.url.contains("/errata/RHSA-2022%3A8162")));
    }

    fn mk_finding(id: &str, pkg_name: &str, fixed: Option<bool>) -> Finding {
        Finding {
            id: id.to_string(),
            source_ids: Vec::new(),
            package: Some(PackageInfo {
                name: pkg_name.to_string(),
                ecosystem: "redhat".to_string(),
                version: "1:1.2.3-1.el8".to_string(),
            }),
            confidence_tier: ConfidenceTier::ConfirmedInstalled,
            evidence_source: EvidenceSource::InstalledDb,
            accuracy_note: None,
            fixed,
            fixed_in: None,
            recommendation: None,
            severity: Some("HIGH".to_string()),
            cvss: None,
            description: None,
            evidence: Vec::new(),
            references: Vec::new(),
            confidence: Some("HIGH".to_string()),
            epss_score: None,
            epss_percentile: None,
            in_kev: None,
        }
    }

    #[test]
    fn drop_fixed_findings_removes_resolved_rows() {
        let mut findings = vec![
            mk_finding("CVE-2021-0001", "pkg-a", Some(true)),
            mk_finding("CVE-2021-0002", "pkg-b", Some(false)),
            mk_finding("CVE-2021-0003", "pkg-c", None),
        ];
        let dropped = drop_fixed_findings(&mut findings);
        assert_eq!(dropped, 1);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.fixed != Some(true)));
    }

    #[test]
    fn select_best_candidate_prefers_nearest_fix() {
        let candidates = vec![
            DistroFixCandidate {
                fixed_version: "1.2.0".into(),
                source_id: "src".into(),
                reference_url: "https://example.test/a".into(),
                note: "a".into(),
            },
            DistroFixCandidate {
                fixed_version: "1.1.0".into(),
                source_id: "src".into(),
                reference_url: "https://example.test/b".into(),
                note: "b".into(),
            },
            DistroFixCandidate {
                fixed_version: "2.0.0".into(),
                source_id: "src".into(),
                reference_url: "https://example.test/c".into(),
                note: "c".into(),
            },
        ];
        let best = select_best_candidate("1.0.5", &candidates).expect("best candidate");
        assert_eq!(best.fixed_version, "1.1.0");
    }

    #[test]
    fn build_ubuntu_candidate_index_maps_notice_to_pkg_cve_key() {
        let data = serde_json::json!({
            "notices": [
                {
                    "id": "USN-1000-1",
                    "cves_ids": ["CVE-2024-12345"],
                    "release_packages": {
                        "jammy": [
                            {"name":"bash","version":"5.1-2ubuntu3.4"}
                        ]
                    }
                }
            ]
        });
        let mut needed = std::collections::HashSet::new();
        needed.insert(pkg_cve_key("bash", "CVE-2024-12345"));
        let idx = build_ubuntu_candidate_index(&data, &needed);
        let key = pkg_cve_key("bash", "CVE-2024-12345");
        let rows = idx.get(&key).expect("ubuntu candidate present");
        assert_eq!(rows[0].fixed_version, "5.1-2ubuntu3.4");
        assert_eq!(rows[0].source_id, "USN-1000-1");
    }

    #[test]
    fn detect_debian_release_from_package_versions() {
        let pkgs = vec![
            PackageCoordinate {
                ecosystem: "deb".into(),
                name: "libc6".into(),
                version: "2.36-9+deb12u9".into(),
            },
        ];
        assert_eq!(detect_debian_release(&pkgs), Some("bookworm"));

        let pkgs_11 = vec![
            PackageCoordinate {
                ecosystem: "deb".into(),
                name: "bash".into(),
                version: "5.1-2+deb11u1".into(),
            },
        ];
        assert_eq!(detect_debian_release(&pkgs_11), Some("bullseye"));
    }

    #[test]
    fn urgency_to_severity_maps_correctly() {
        assert_eq!(urgency_to_severity("high"), "HIGH");
        assert_eq!(urgency_to_severity("medium"), "MEDIUM");
        assert_eq!(urgency_to_severity("low"), "LOW");
        assert_eq!(urgency_to_severity("low*"), "LOW");
        assert_eq!(urgency_to_severity("end-of-life"), "MEDIUM");
        assert_eq!(urgency_to_severity("unknown"), "MEDIUM");
    }
}
