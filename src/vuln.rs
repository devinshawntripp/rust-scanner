use std::collections::HashSet;
use std::time::Duration;
use std::thread::sleep;

use reqwest::blocking::{Client, Response};
use serde_json::Value;
use crate::container::PackageCoordinate;
use crate::cache::{cache_get, cache_put, cache_key};
use std::path::PathBuf;
use crate::report::{Finding, PackageInfo, ReferenceInfo, EvidenceItem, CvssInfo, severity_from_score};
use crate::utils::progress;
use rand::{thread_rng, Rng};
use rayon::prelude::*;

// --- Postgres cache ---
use postgres::{Client as PgClient, NoTls};
use chrono::{DateTime, Utc, NaiveDateTime, Duration as ChronoDuration};

/// Queries the NVD API for a given component + version
pub fn match_vuln(component: &str, version: &str) {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=10",
        urlencoding::encode(&keyword)
    );

    println!("Querying NVD: {}", url);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

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

            let description = descs.iter()
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
    if packages.is_empty() { return serde_json::json!([]); }

    // Build per-package queries and remember original indices
    let indexed: Vec<(usize, Value)> = packages.iter().enumerate().map(|(i, p)| {
        let (ecosystem, name, version) = map_ecosystem_name_version(p);
        let q = serde_json::json!({ "package": {"ecosystem": ecosystem, "name": name}, "version": version });
        (i, q)
    }).collect();

    // Output buffer aligned to packages (each entry: {"vulns": [...]})
    let mut results: Vec<Value> = vec![serde_json::json!({"vulns": []}); packages.len()];

    let chunk_size: usize = std::env::var("SCANNER_OSV_BATCH_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(50);
    let retries: usize = std::env::var("SCANNER_OSV_RETRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let backoff_ms_base: u64 = std::env::var("SCANNER_OSV_BACKOFF_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(500);

    let client = Client::builder().timeout(Duration::from_secs(45)).build().unwrap();

    for chunk in indexed.chunks(chunk_size) {
        // Prepare body for this chunk
        let body = serde_json::json!({ "queries": chunk.iter().map(|(_, q)| q).collect::<Vec<&Value>>() });
        let cache_tag = cache_key(&["osv_batch", &format!("{}:{}", chunk.first().map(|(i,_)| i).unwrap_or(&0), chunk.len())]);
        progress("osv.query.chunk.start", &format!("offset={} size={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), chunk.len()));

        let mut attempt = 0;
        let mut done = false;
        while attempt < retries && !done {
            attempt += 1;
            // Try cache for this chunk first
            if let Some(bytes) = cache_get(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &cache_tag) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(arr) = v["results"].as_array() {
                        for (idx_in_chunk, item) in arr.iter().enumerate() {
                            let orig_idx = chunk[idx_in_chunk].0;
                            results[orig_idx] = item.clone();
                        }
                        progress("osv.query.chunk.cache", &format!("offset={} size={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), chunk.len()));
                        done = true; break;
                    }
                }
            }

            // Network request
            let resp = client.post("https://api.osv.dev/v1/querybatch").json(&body).send();
            match resp {
                Ok(r) => match r.json::<Value>() {
                    Ok(v) => {
                        if let Some(arr) = v["results"].as_array() {
                            for (idx_in_chunk, item) in arr.iter().enumerate() {
                                let orig_idx = chunk[idx_in_chunk].0;
                                results[orig_idx] = item.clone();
                            }
                            cache_put(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &cache_tag, v.to_string().as_bytes());
                            progress("osv.query.chunk.done", &format!("offset={} size={} attempts={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), chunk.len(), attempt));
                            done = true; break;
                        } else {
                            progress("osv.query.error", &format!("chunk_parse offset={} attempt={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), attempt));
                        }
                    }
                    Err(e) => {
                        progress("osv.query.error", &format!("chunk_json offset={} attempt={} err={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), attempt, e));
                    }
                },
                Err(e) => {
                    progress("osv.query.error", &format!("chunk_http offset={} attempt={} err={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), attempt, e));
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
                    if let Some(bytes) = cache_get(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &single_cache) {
                        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) { results[*orig_idx] = v; break; }
                    }
                    progress("osv.query.pkg.start", &format!("idx={} attempt={}", orig_idx, attempt_p));
                    let resp = client.post("https://api.osv.dev/v1/query").json(&q).send();
                    match resp {
                        Ok(r) => match r.json::<Value>() {
                            Ok(v) => { cache_put(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &single_cache, v.to_string().as_bytes()); results[*orig_idx] = v; progress("osv.query.pkg.ok", &format!("idx={} attempts={}", orig_idx, attempt_p)); break; }
                            Err(e) => { progress("osv.query.pkg.error", &format!("idx={} json err={}", orig_idx, e)); }
                        },
                        Err(e) => { progress("osv.query.pkg.error", &format!("idx={} http err={}", orig_idx, e)); }
                    }
                    if attempt_p >= retries { break; }
                    std::thread::sleep(Duration::from_millis(backoff_ms_base * attempt_p as u64));
                }
            }
            progress("osv.query.chunk.fallback", &format!("offset={} size={}", chunk.first().map(|(i,_)| i).unwrap_or(&0), chunk.len()));
        }
    }

    serde_json::Value::Array(results)
}

fn map_ecosystem_name_version(p: &PackageCoordinate) -> (String, String, String) {
    // Map OS package ecosystems to OSV conventions
    match p.ecosystem.as_str() {
        "deb" => ("Debian".into(), p.name.clone(), p.version.clone()),
        "apk" => ("Alpine".into(), p.name.clone(), p.version.clone()),
        // Fallback: pass through
        other => (other.to_string(), p.name.clone(), p.version.clone()),
    }
}

pub fn map_osv_results_to_findings(packages: &Vec<PackageCoordinate>, osv_results: &serde_json::Value) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for (idx, pkg) in packages.iter().enumerate() {
        let res = &osv_results[idx];
        if let Some(vulns) = res["vulns"].as_array() {
            for v in vulns {
                // Collect CVE ids from aliases, references, OSV id and text
                let aliases: Vec<String> = v["aliases"].as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                let re_cve = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
                let mut cve_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
                if let Some(re) = &re_cve {
                    for a in &aliases {
                        if let Some(m) = re.find(a) { cve_ids.insert(m.as_str().to_string()); }
                    }
                }
                if cve_ids.is_empty() {
                    if let Some(refs) = v["references"].as_array() {
                        if let Some(re) = &re_cve {
                            for u in refs.iter().filter_map(|r| r["url"].as_str()) {
                                if let Some(m) = re.find(u) { cve_ids.insert(m.as_str().to_string()); }
                            }
                        }
                    }
                }
                if cve_ids.is_empty() {
                    if let Some(osv_id_str) = v["id"].as_str() {
                        if let Some(re) = &re_cve { if let Some(m) = re.find(osv_id_str) { cve_ids.insert(m.as_str().to_string()); } }
                    }
                }
                if cve_ids.is_empty() {
                    let mut text = String::new();
                    if let Some(s) = v["summary"].as_str() { text.push_str(s); text.push(' '); }
                    if let Some(d) = v["details"].as_str() { text.push_str(d); }
                    if let Some(re) = &re_cve { if let Some(m) = re.find(&text) { cve_ids.insert(m.as_str().to_string()); } }
                }
                let description = v["summary"].as_str().map(|s| s.to_string())
                    .or_else(|| v["details"].as_str().map(|s| s.to_string()));
                let mut cvss: Option<CvssInfo> = None;
                let mut severity_str: Option<String> = None;
                if let Some(severities) = v["severity"].as_array() {
                    for sev in severities {
                        if sev["type"] == "CVSS_V3" || sev["type"] == "CVSS_V2" {
                            if let Some(score) = sev["score"].as_str().and_then(|s| {
                                // score may be just number or "X.Y/AV:..."
                                let t = s.split('/').next().unwrap_or(s);
                                t.parse::<f32>().ok()
                            }) {
                                let vector = sev["score"].as_str().unwrap_or("").to_string();
                                cvss = Some(CvssInfo { base: score, vector: vector.clone() });
                                severity_str = Some(severity_from_score(score).to_string());
                                break;
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

                let package = Some(PackageInfo { name: pkg.name.clone(), ecosystem: pkg.ecosystem.clone(), version: pkg.version.clone() });
                let evidence = vec![EvidenceItem { evidence_type: "file".into(), path: None, detail: Some("package db record".into()) }];
                let mut references: Vec<ReferenceInfo> = Vec::new();
                if let Some(refs) = v["references"].as_array() {
                    for r in refs {
                        if let Some(url) = r["url"].as_str() {
                            references.push(ReferenceInfo { reference_type: r["type"].as_str().unwrap_or("reference").to_string(), url: url.to_string() });
                        }
                    }
                }

                let mut source_ids = aliases;
                let osv_id = v["id"].as_str().unwrap_or("").to_string();
                if !osv_id.is_empty() { source_ids.push(osv_id.clone()); }
                // Determine fixed status using OSV affected ranges when possible
                let mut fixed: Option<bool> = None;
                if let Some(aff) = v["affected"].as_array() {
                    // OSV affected entries may include ranges with introduced/fixed
                    for a in aff {
                        if let Some(p) = a["package"].get("ecosystem").and_then(|e| e.as_str()) {
                            let eco = p.to_string();
                            let name_match = a["package"].get("name").and_then(|n| n.as_str()).map(|s| s == pkg.name).unwrap_or(false);
                            if !name_match { continue; }
                            if let Some(ranges) = a["ranges"].as_array() {
                                for r in ranges {
                                    if r["type"].as_str() == Some("ECOSYSTEM") {
                                        if let Some(events) = r["events"].as_array() {
                                            // Simplified: if a fixed version exists and pkg.version >= fixed, mark fixed=true
                                            if let Some(fixed_ver) = events.iter().find_map(|e| e.get("fixed").and_then(|s| s.as_str())) {
                                                // Use Debian-style compare for deb/apk when available
                                                // Fallback: naive numeric compare of dotted versions
                                                let is_fixed = cmp_versions(&pkg.version, fixed_ver) != std::cmp::Ordering::Less;
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
                            fixed,
                            severity: severity_str.clone(),
                            cvss: cvss.clone(),
                            description: description.clone(),
                            evidence: evidence.clone(),
                            references: references.clone(),
                            confidence: Some("HIGH".into()),
                        });
                    }
                } else {
                    // Advisory-only if no CVE mapping found yet
                    out.push(Finding {
                        id: osv_id,
                        source_ids,
                        package,
                        fixed,
                        severity: severity_str,
                        cvss,
                        description,
                        evidence,
                        references,
                        confidence: Some("LOW".into()),
                    });
                }
            }
        }
    }
    out
}

/// Enrich findings with details from OSV /v1/vulns/{id} (fills description, severity, references)
pub fn osv_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
    if findings.is_empty() { return; }
    // Deduplicate IDs to query
    let mut unique_ids_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in findings.iter() { unique_ids_set.insert(f.id.clone()); }
    let mut unique_ids: Vec<String> = unique_ids_set.into_iter().collect();
    unique_ids.sort();
    let client = Client::builder().timeout(Duration::from_secs(15)).build().unwrap();
    let sleep_ms: u64 = std::env::var("SCANNER_OSV_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    let total = unique_ids.len();

    if let Some(c) = pg.as_mut() { pg_init_schema(c); }

    for (idx, id) in unique_ids.into_iter().enumerate() {
        progress("osv.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
        // PG first
        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_osv(client_pg, &id) {
                let ttl_days = compute_dynamic_ttl_days(last_mod, 14);
                if Utc::now() - last_checked < ChronoDuration::days(ttl_days) {
                    // Apply cached OSV payload to matching findings (id may be OSV id; we still enrich fields from OSV payload)
                    let description = payload["summary"].as_str().or_else(|| payload["details"].as_str()).map(|s| s.to_string());
                    let mut cvss: Option<CvssInfo> = None;
                    let mut severity_str: Option<String> = None;
                    if let Some(severities) = payload["severity"].as_array() {
                        for sev in severities {
                            if sev["type"] == "CVSS_V3" || sev["type"] == "CVSS_V2" {
                                if let Some(score_num) = sev["score"].as_str().and_then(|s| { let t = s.split('/').next().unwrap_or(s); t.parse::<f32>().ok() }) {
                                    let vector = sev["score"].as_str().unwrap_or("").to_string();
                                    cvss = Some(CvssInfo { base: score_num, vector: vector.clone() });
                                    severity_str = Some(severity_from_score(score_num).to_string());
                                    break;
                                }
                            }
                        }
                    }
                    let mut refs: Vec<ReferenceInfo> = Vec::new();
                    if let Some(references) = payload["references"].as_array() {
                        for r in references {
                            if let Some(url) = r["url"].as_str() {
                                refs.push(ReferenceInfo { reference_type: r["type"].as_str().unwrap_or("reference").to_string(), url: url.to_string() });
                            }
                        }
                    }
                    for f in findings.iter_mut().filter(|f| f.id == id) {
                        if f.description.is_none() { f.description = description.clone(); }
                        if f.cvss.is_none() { f.cvss = cvss.clone(); }
                        if f.severity.is_none() { f.severity = severity_str.clone(); }
                        if f.references.is_empty() && !refs.is_empty() { f.references = refs.clone(); }
                    }
                    progress("osv.cache.pg.hit", &id);
                    continue;
                }
            }
        }

        // file cache next
        let cache_tag = cache_key(&["osv_vuln", &id]);
        let mut json: Option<Value> = None;
        if let Some(bytes) = cache_get(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &cache_tag) {
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) { json = Some(v); }
        }
        if json.is_none() {
            if sleep_ms > 0 { sleep(Duration::from_millis(sleep_ms)); }
            let url = format!("https://api.osv.dev/v1/vulns/{}", id);
            match client.get(&url).send() {
                Ok(r) if r.status().is_success() => {
                    match r.json::<Value>() {
                        Ok(v) => {
                            cache_put(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &cache_tag, v.to_string().as_bytes());
                            json = Some(v);
                        },
                        Err(_) => {}
                    }
                }
                _ => {}
            }
        }
        if json.is_none() { progress("osv.fetch.err", &id); continue; }
        let json = json.unwrap();
        // store to PG once (reuse the single connection)
        if let Some(client_pg) = pg.as_mut() { let lm = parse_osv_last_modified(&json); pg_put_osv(client_pg, &id, &json, lm); }
        progress("osv.fetch.ok", &id);
        // Extract useful fields
        let description = json["summary"].as_str().or_else(|| json["details"].as_str()).map(|s| s.to_string());
        let mut cvss: Option<CvssInfo> = None;
        let mut severity_str: Option<String> = None;
        if let Some(severities) = json["severity"].as_array() {
            for sev in severities {
                if sev["type"] == "CVSS_V3" || sev["type"] == "CVSS_V2" {
                    if let Some(score_num) = sev["score"].as_str().and_then(|s| {
                        let t = s.split('/').next().unwrap_or(s);
                        t.parse::<f32>().ok()
                    }) {
                        let vector = sev["score"].as_str().unwrap_or("").to_string();
                        cvss = Some(CvssInfo { base: score_num, vector: vector.clone() });
                        severity_str = Some(severity_from_score(score_num).to_string());
                        break;
                    }
                }
            }
        }
        let mut refs: Vec<ReferenceInfo> = Vec::new();
        if let Some(references) = json["references"].as_array() {
            for r in references {
                if let Some(url) = r["url"].as_str() {
                    refs.push(ReferenceInfo { reference_type: r["type"].as_str().unwrap_or("reference").to_string(), url: url.to_string() });
                }
            }
        }
        // Apply to all findings matching this id; upgrade advisory to one-or-many CVEs if available
        let mut to_append: Vec<Finding> = Vec::new();
        for i in 0..findings.len() {
            if findings[i].id != id { continue; }
            let f = &mut findings[i];
            if f.description.is_none() { f.description = description.clone(); }
            if f.cvss.is_none() { f.cvss = cvss.clone(); }
            if f.severity.is_none() { f.severity = severity_str.clone(); }
            if f.references.is_empty() && !refs.is_empty() { f.references = refs.clone(); }
            if !f.id.starts_with("CVE-") {
                // Collect all CVEs from aliases/refs/text
                let mut text = String::new();
                if let Some(s) = json["summary"].as_str() { text.push_str(s); text.push(' '); }
                if let Some(d) = json["details"].as_str() { text.push_str(d); }
                let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
                let mut cves: std::collections::HashSet<String> = std::collections::HashSet::new();
                if let Some(arr) = json["aliases"].as_array() {
                    for a in arr.iter().filter_map(|x| x.as_str()) { if a.starts_with("CVE-") { cves.insert(a.to_string()); } }
                }
                if let Some(arr) = json["references"].as_array() { if let Some(re2) = &re { for r in arr { if let Some(u) = r["url"].as_str() { if let Some(m) = re2.find(u) { cves.insert(m.as_str().to_string()); } } } } }
                if let Some(re2) = &re { if let Some(m) = re2.find(&text) { cves.insert(m.as_str().to_string()); } }
                if !cves.is_empty() {
                    // Upgrade current to first CVE, append others
                    let mut cves_iter = cves.into_iter();
                    if let Some(primary) = cves_iter.next() {
                        if !f.source_ids.contains(&f.id) { f.source_ids.push(f.id.clone()); }
                        f.id = primary;
                    }
                    for extra in cves_iter {
                        let mut nf = findings[i].clone();
                        nf.id = extra;
                        to_append.push(nf);
                    }
                }
            }
        }
        findings.extend(to_append);
        // Deduplicate by id after upgrades
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        findings.retain(|f| seen_ids.insert(f.id.clone()));
        // Log upgrade count by counting CVEs that reference this advisory in source_ids
        let upgraded_cve_count = findings.iter()
            .filter(|f| f.id.starts_with("CVE-") && f.source_ids.iter().any(|s| s == &id))
            .count();
        if upgraded_cve_count > 0 {
            progress("osv.upgrade.cve", &format!("{} -> {} CVEs", id, upgraded_cve_count));
        }
        // Drop any remaining advisory-only finding with this id (keep advisory id only in source_ids)
        if !id.starts_with("CVE-") && upgraded_cve_count > 0 {
            let before_len = findings.len();
            findings.retain(|f| f.id != id);
            if findings.len() != before_len {
                progress("osv.advisory.drop", &id);
            }
        }

        // If still advisory-only (DLA/DSA) for this id, fallback to Debian tracker mapping
        if (id.starts_with("DLA-") || id.starts_with("DSA-"))
            && findings.iter().any(|f| f.id == id)
        {
            if let Some(mut mapped) = map_debian_advisory_to_cves(&id) {
                mapped.sort(); mapped.dedup();
                if !mapped.is_empty() {
                    let mut to_append2: Vec<Finding> = Vec::new();
                    for f in findings.iter_mut().filter(|f| f.id == id) {
                        if let Some(first) = mapped.first().cloned() {
                            if !f.source_ids.contains(&f.id) { f.source_ids.push(f.id.clone()); }
                            f.id = first;
                        }
                        for extra in mapped.iter().skip(1) {
                            let mut nf = f.clone();
                            nf.id = extra.clone();
                            to_append2.push(nf);
                        }
                    }
                    findings.extend(to_append2);
                    let mut seen_ids2: std::collections::HashSet<String> = std::collections::HashSet::new();
                    findings.retain(|f| seen_ids2.insert(f.id.clone()));
                    progress("osv.debian.map.ok", &format!("{} -> {} CVEs", id, mapped.len()));
                    // Also drop any remaining advisory-only record now that CVEs were added
                    if !id.starts_with("CVE-") && !mapped.is_empty() {
                        let before_len2 = findings.len();
                        findings.retain(|f| f.id != id);
                        if findings.len() != before_len2 {
                            progress("osv.advisory.drop", &id);
                        }
                    }
                } else {
                    progress("osv.debian.map.empty", &id);
                }
            } else {
                progress("osv.debian.map.skip", &id);
            }
        }
    }

    // Deduplicate by id after any upgrades from advisory -> CVE
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    findings.retain(|f| seen_ids.insert(f.id.clone()));
}

fn map_debian_advisory_to_cves(advisory_id: &str) -> Option<Vec<String>> {
    // Fetch Debian tracker page and extract CVE IDs
    let url = format!("https://security-tracker.debian.org/tracker/{}", advisory_id);
    let client = Client::builder().timeout(Duration::from_secs(10)).build().ok()?;
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() { return None; }
    let body = resp.text().ok()?;
    let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok()?;
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in re.find_iter(&body) { set.insert(m.as_str().to_string()); }
    Some(set.into_iter().collect())
}

pub fn enrich_findings_with_nvd(findings: &mut Vec<Finding>, api_key: Option<&str>, pg: &mut Option<PgClient>) {
    if findings.is_empty() { return; }
    // Deduplicate CVE IDs
    let mut unique_ids_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in findings.iter() { unique_ids_set.insert(f.id.clone()); }
    let mut unique_ids: Vec<String> = unique_ids_set.into_iter().filter(|id| id.starts_with("CVE-")).collect();
    unique_ids.sort();

    // Determine polite sleep between requests
    let default_ms = match api_key { Some(_) => 800u64, None => 6500u64 };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms);
    let jitter_max = (sleep_ms / 4).max(50);
    let ttl_days: i64 = std::env::var("SCANNER_NVD_TTL_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(7);
    let mut rng = thread_rng();

    // Fetch details per unique CVE with caching and rate limiting
    let mut id_to_json: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let total = unique_ids.len();

    // Optional Postgres cache
    if let Some(client) = pg.as_mut() { pg_init_schema(client); }

    // Determine which IDs to fetch from network after consulting PG cache
    let mut to_fetch: Vec<(usize, String)> = Vec::new();
    for (idx, id) in unique_ids.into_iter().enumerate() {
        let mut served_from_cache = false;
        if let Some(client) = pg.as_mut() {
            if let Some((payload, last_checked_at, nvd_last_modified)) = pg_get_cve(client, &id) {
                let ttl_dyn_days = compute_dynamic_ttl_days(nvd_last_modified, ttl_days as i64) as i64;
                if Utc::now() - last_checked_at < ChronoDuration::days(ttl_dyn_days) {
                    id_to_json.insert(id.clone(), payload);
                    progress("nvd.cache.pg.hit", &id);
                    served_from_cache = true;
                }
            }
        }
        if !served_from_cache { to_fetch.push((idx, id)); }
    }

    // Concurrency with politeness via a small threadpool
    let max_concurrent: usize = std::env::var("SCANNER_NVD_CONC").ok().and_then(|v| v.parse().ok()).unwrap_or(if api_key.is_some() { 5 } else { 1 });
    let pool = rayon::ThreadPoolBuilder::new().num_threads(max_concurrent).build().ok();
    if let Some(pool) = pool {
        let fetched: Vec<(String, Value, Option<DateTime<Utc>>)> = pool.install(|| {
            to_fetch.par_iter().filter_map(|(idx, id)| {
                progress("nvd.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
                // jittered sleep per task
                let jitter = rand::thread_rng().gen_range(0..=jitter_max);
                if sleep_ms + jitter > 0 { sleep(Duration::from_millis(sleep_ms + jitter)); }
                let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", id);
                match nvd_get_json(&url, api_key, &format!("cveId:{}", id), 0) {
                    Some(json) => {
                        let lm = parse_nvd_last_modified(&json);
                        Some((id.clone(), json, lm))
                    }
                    None => { progress("nvd.fetch.err", id); None }
                }
            }).collect()
        });
        // Merge results, update PG and memory map sequentially
        if let Some(client) = pg.as_mut() {
            for (id, json, lm) in &fetched { pg_put_cve(client, id, json, *lm); }
        }
        for (id, json, _lm) in fetched.into_iter() {
            id_to_json.insert(id.clone(), json);
            progress("nvd.fetch.ok", &id);
        }
    } else {
        // Fallback sequential loop
        for (idx, id) in to_fetch.into_iter() {
            progress("nvd.fetch.start", &format!("{}/{} {}", idx + 1, total, id));
            let jitter = rand::thread_rng().gen_range(0..=jitter_max);
            if sleep_ms + jitter > 0 { sleep(Duration::from_millis(sleep_ms + jitter)); }
            let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", id);
            match nvd_get_json(&url, api_key, &format!("cveId:{}", id), 0) {
                Some(json) => {
                    let lm = parse_nvd_last_modified(&json);
                    if let Some(client) = pg.as_mut() { pg_put_cve(client, &id, &json, lm); }
                    id_to_json.insert(id.clone(), json);
                    progress("nvd.fetch.ok", &id);
                }
                None => { progress("nvd.fetch.err", &id); }
            }
        }
    }

    // Apply enrichment
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
                    if let Some(cvss3) = cve["metrics"]["cvssMetricV31"].as_array().and_then(|a| a.first())
                        .or_else(|| cve["metrics"]["cvssMetricV30"].as_array().and_then(|a| a.first())) {
                        // vector/score
                        if f.cvss.is_none() {
                            if let (Some(base), Some(vector)) = (cvss3["cvssData"]["baseScore"].as_f64(), cvss3["cvssData"]["vectorString"].as_str()) {
                                let base_f = base as f32;
                                f.cvss = Some(CvssInfo { base: base_f, vector: vector.to_string() });
                                if f.severity.is_none() { f.severity = Some(severity_from_score(base_f).to_string()); }
                            }
                        }
                        // explicit severity if provided
                        if f.severity.is_none() {
                            if let Some(sev) = cvss3["cvssData"]["baseSeverity"].as_str()
                                .or_else(|| cvss3["baseSeverity"].as_str()) {
                                f.severity = Some(sev.to_uppercase());
                            }
                        }
                    } else if let Some(cvss2) = cve["metrics"]["cvssMetricV2"].as_array().and_then(|a| a.first()) {
                        if f.cvss.is_none() {
                            if let Some(base) = cvss2["cvssData"]["baseScore"].as_f64() {
                                let base_f = base as f32;
                                let vector = cvss2["cvssData"]["vectorString"].as_str().unwrap_or("").to_string();
                                f.cvss = Some(CvssInfo { base: base_f, vector });
                                if f.severity.is_none() { f.severity = Some(severity_from_score(base_f).to_string()); }
                            }
                        }
                        if f.severity.is_none() {
                            if let Some(sev) = cvss2["baseSeverity"].as_str() {
                                f.severity = Some(sev.to_uppercase());
                            }
                        }
                    }
                    if f.description.is_none() {
                        let desc = cve["descriptions"].as_array()
                            .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                            .and_then(|d| d["value"].as_str())
                            .map(|s| s.to_string());
                        f.description = desc;
                    }
                    if let Some(refs) = cve["references"]["referenceData"].as_array() {
                        for r in refs {
                            if let Some(url) = r["url"].as_str() {
                                f.references.push(ReferenceInfo { reference_type: "nvd".into(), url: url.into() });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Query NVD by keyword (component + version) and map to findings. Useful fallback when OSV has no package context.
pub fn nvd_keyword_findings(component: &str, version: &str, api_key: Option<&str>, evidence_path: Option<&str>) -> Vec<Finding> {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(&keyword)
    );
    let default_ms = match api_key { Some(_) => 800u64, None => 6500u64 };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("kw:{}", keyword), sleep_ms) { Some(j) => j, None => return Vec::new() };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"].as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str()).map(|s| s.to_string());

            // Prefer CVSS v3.1, then v3.0, then v2
            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"].as_array().and_then(|a| a.first())
                .or_else(|| cve["metrics"]["cvssMetricV30"].as_array().and_then(|a| a.first()))
                .or_else(|| cve["metrics"]["cvssMetricV2"].as_array().and_then(|a| a.first())) {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"].as_str().unwrap_or("").to_string();
                cvss = Some(CvssInfo { base, vector: vector.clone() });
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
                        references.push(ReferenceInfo { reference_type: "nvd".into(), url: url.to_string() });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:keyword:{} {}", component, version)],
                package: Some(PackageInfo { name: component.to_string(), ecosystem: "nvd".into(), version: version.to_string() }),
                fixed: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("MEDIUM".into()),
            });
        }
    }
    out
}

/// Query NVD by CPE name constructed from component/version (best-effort)
pub fn nvd_cpe_findings(component: &str, version: &str, api_key: Option<&str>, evidence_path: Option<&str>) -> Vec<Finding> {
    let vendor = component.to_lowercase();
    let product = component.to_lowercase();
    let cpe = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}",
        urlencoding::encode(&cpe)
    );
    let default_ms = match api_key { Some(_) => 800u64, None => 6500u64 };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("cpe:{}", cpe), sleep_ms) { Some(j) => j, None => return Vec::new() };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"].as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str()).map(|s| s.to_string());

            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"].as_array().and_then(|a| a.first())
                .or_else(|| cve["metrics"]["cvssMetricV30"].as_array().and_then(|a| a.first()))
                .or_else(|| cve["metrics"]["cvssMetricV2"].as_array().and_then(|a| a.first())) {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"].as_str().unwrap_or("").to_string();
                cvss = Some(CvssInfo { base, vector: vector.clone() });
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
                        references.push(ReferenceInfo { reference_type: "nvd".into(), url: url.to_string() });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:cpe:{} {}", component, version)],
                package: Some(PackageInfo { name: component.to_string(), ecosystem: "nvd".into(), version: version.to_string() }),
                fixed: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("MEDIUM".into()),
            });
        }
    }
    out
}

/// NVD keyword search by name only (low confidence). Useful when version unknown or not indexed.
pub fn nvd_keyword_findings_name(component: &str, api_key: Option<&str>, evidence_path: Option<&str>) -> Vec<Finding> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(component)
    );
    let default_ms = match api_key { Some(_) => 800u64, None => 6500u64 };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("kw_only:{}", component), sleep_ms) { Some(j) => j, None => return Vec::new() };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = cve["descriptions"].as_array()
                .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                .and_then(|d| d["value"].as_str()).map(|s| s.to_string());

            let mut cvss: Option<CvssInfo> = None;
            let mut severity: Option<String> = None;
            if let Some(m) = cve["metrics"]["cvssMetricV31"].as_array().and_then(|a| a.first())
                .or_else(|| cve["metrics"]["cvssMetricV30"].as_array().and_then(|a| a.first()))
                .or_else(|| cve["metrics"]["cvssMetricV2"].as_array().and_then(|a| a.first())) {
                let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                let vector = m["cvssData"]["vectorString"].as_str().unwrap_or("").to_string();
                cvss = Some(CvssInfo { base, vector: vector.clone() });
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
                        references.push(ReferenceInfo { reference_type: "nvd".into(), url: url.to_string() });
                    }
                }
            }

            out.push(Finding {
                id,
                source_ids: vec![format!("heuristic:keyword:{}", component)],
                package: Some(PackageInfo { name: component.to_string(), ecosystem: "nvd".into(), version: "unknown".into() }),
                fixed: None,
                severity,
                cvss,
                description,
                evidence,
                references,
                confidence: Some("LOW".into()),
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
        if va < vb { return Ordering::Less; }
        if va > vb { return Ordering::Greater; }
    }
    Ordering::Equal
}

fn is_version_in_range(target: &str, start_inc: Option<&str>, start_exc: Option<&str>, end_inc: Option<&str>, end_exc: Option<&str>) -> bool {
    if let Some(s) = start_inc { if cmp_versions(target, s) == std::cmp::Ordering::Less { return false; } }
    if let Some(s) = start_exc { if cmp_versions(target, s) != std::cmp::Ordering::Greater { return false; } }
    if let Some(e) = end_inc { if cmp_versions(target, e) == std::cmp::Ordering::Greater { return false; } }
    if let Some(e) = end_exc { if cmp_versions(target, e) != std::cmp::Ordering::Less { return false; } }
    true
}

fn cpe_parts(criteria: &str) -> Option<(String,String,Option<String>)> {
    // cpe:2.3:a:vendor:product:version:...
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() >= 5 { Some((parts[3].to_string(), parts[4].to_string(), Some(parts[5].to_string()))) } else { None }
}

/// Broader NVD search for vendor/product and filter by version ranges in CPEs
pub fn nvd_findings_by_product_version(vendor: &str, product: &str, version: &str, api_key: Option<&str>, evidence_path: Option<&str>) -> Vec<Finding> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=2000",
        urlencoding::encode(product)
    );
    let default_ms = match api_key { Some(_) => 800u64, None => 6500u64 };
    let sleep_ms: u64 = std::env::var("SCANNER_NVD_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(default_ms);
    let json = match nvd_get_json(&url, api_key, &format!("prod:{}", product), sleep_ms) { Some(j) => j, None => return Vec::new() };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        'outer: for item in items {
            let cve = &item["cve"];
            let mut matches_product = false;
            if let Some(nodes) = cve["configurations"].get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(cpes) = node.get("cpeMatch").and_then(|m| m.as_array()) {
                        for c in cpes {
                            let criteria = c.get("criteria").and_then(|s| s.as_str()).unwrap_or("");
                            if let Some((ven, prod, ver_opt)) = cpe_parts(criteria) {
                                if ven.eq_ignore_ascii_case(vendor) && prod.eq_ignore_ascii_case(product) {
                                    matches_product = true;
                                    let vulnerable = c.get("vulnerable").and_then(|b| b.as_bool()).unwrap_or(false);
                                    if !vulnerable { continue; }
                                    let start_inc = c.get("versionStartIncluding").and_then(|s| s.as_str());
                                    let start_exc = c.get("versionStartExcluding").and_then(|s| s.as_str());
                                    let end_inc = c.get("versionEndIncluding").and_then(|s| s.as_str());
                                    let end_exc = c.get("versionEndExcluding").and_then(|s| s.as_str());
                                    // If criteria has exact version and no ranges, compare directly
                                    if start_inc.is_none() && start_exc.is_none() && end_inc.is_none() && end_exc.is_none() {
                                        if let Some(ver) = ver_opt.as_deref() {
                                            if ver != "*" && cmp_versions(version, ver) != std::cmp::Ordering::Equal { continue; }
                                        }
                                    } else {
                                        if !is_version_in_range(version, start_inc, start_exc, end_inc, end_exc) { continue; }
                                    }

                                    // Build finding
                                    let id = cve["id"].as_str().unwrap_or("unknown").to_string();
                                    let description = cve["descriptions"].as_array()
                                        .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
                                        .and_then(|d| d["value"].as_str()).map(|s| s.to_string());
                                    let mut cvss: Option<CvssInfo> = None;
                                    let mut severity: Option<String> = None;
                                    if let Some(m) = cve["metrics"]["cvssMetricV31"].as_array().and_then(|a| a.first())
                                        .or_else(|| cve["metrics"]["cvssMetricV30"].as_array().and_then(|a| a.first()))
                                        .or_else(|| cve["metrics"]["cvssMetricV2"].as_array().and_then(|a| a.first())) {
                                        let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
                                        let vector = m["cvssData"]["vectorString"].as_str().unwrap_or("").to_string();
                                        cvss = Some(CvssInfo { base, vector: vector.clone() });
                                        severity = Some(severity_from_score(base).to_string());
                                    }
                                    let evidence = vec![EvidenceItem { evidence_type: "cpe".into(), path: evidence_path.map(|s| s.to_string()), detail: Some(criteria.to_string()) }];
                                    let mut references: Vec<ReferenceInfo> = Vec::new();
                                    if let Some(refs) = cve["references"]["referenceData"].as_array() {
                                        for r in refs { if let Some(url) = r["url"].as_str() { references.push(ReferenceInfo { reference_type: "nvd".into(), url: url.to_string() }); } }
                                    }
                                    out.push(Finding {
                                        id,
                                        source_ids: vec![format!("heuristic:product:{} {} {}", vendor, product, version)],
                                        package: Some(PackageInfo { name: product.to_string(), ecosystem: "nvd".into(), version: version.to_string() }),
                                        fixed: None,
                                        severity,
                                        cvss,
                                        description,
                                        evidence,
                                        references,
                                        confidence: Some("MEDIUM".into())
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
    // Cache by URL
    let key = cache_key(&["nvd", cache_tag, url]);
    if let Some(bytes) = cache_get(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &key) {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) { return Some(v); }
    }
    // Rate limiting sleep
    if sleep_ms > 0 { sleep(Duration::from_millis(sleep_ms)); }
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("scanner/0.1 (+https://github.com/devintripp/rust_scanner)")
        .build();
    let client = match client {
        Ok(c) => c,
        Err(e) => { progress("nvd.http.err", &format!("client_build: {}", e)); return None; }
    };
    let mut req = client.get(url).header("Accept", "application/json");
    if let Some(k) = api_key {
        req = req.header("apiKey", k).header("X-Api-Key", k);
    }
    let resp = match req.send() {
       Ok(r) => r,
       Err(e) => { progress("nvd.http.err", &format!("send: {}", e)); return None; }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let rem = resp.headers().get("X-RateLimit-Remaining").and_then(|v| v.to_str().ok()).unwrap_or("");
        let lim = resp.headers().get("X-RateLimit-Limit").and_then(|v| v.to_str().ok()).unwrap_or("");
        progress("nvd.http.err", &format!("status={} remaining={} limit={} url={}", status, rem, lim, url));
        return None;
    }
    // Adjust pacing based on headers if provided
    adjust_rate_limits(&resp);
    let v: Value = match resp.json() {
        Ok(j) => j,
        Err(e) => { progress("nvd.json.err", &format!("{}", e)); return None; }
    };
    cache_put(std::env::var_os("SCANNER_CACHE").as_deref().map(PathBuf::from).as_deref(), &key, v.to_string().as_bytes());
    Some(v)
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
        Err(e) => { progress("nvd.cache.pg.connect.err", &format!("{}", e)); None }
    }
}

pub fn pg_init_schema(client: &mut PgClient) {
    let res = client.batch_execute(
        "CREATE TABLE IF NOT EXISTS nvd_cve_cache (\n            cve_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            nvd_last_modified TIMESTAMPTZ\n        );\n        CREATE TABLE IF NOT EXISTS osv_vuln_cache (\n            vuln_id TEXT PRIMARY KEY,\n            payload JSONB NOT NULL,\n            last_checked_at TIMESTAMPTZ NOT NULL,\n            osv_last_modified TIMESTAMPTZ\n        );"
    );
    match res { Ok(_) => progress("nvd.cache.pg.init.ok", ""), Err(e) => progress("nvd.cache.pg.init.err", &format!("{}", e)) }
}

fn extract_schema_from_url(url: &str) -> Option<String> {
    let q = url.split('?').nth(1)?;
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if k == "schema" && !v.is_empty() { return Some(v.to_string()); }
    }
    None
}

fn strip_param_from_url(url: &str, key: &str) -> (String, Option<String>) {
    let mut parts = url.splitn(2, '?');
    let base = parts.next().unwrap_or("");
    if let Some(query) = parts.next() {
        let mut kept: Vec<String> = Vec::new();
        let mut found: Option<String> = None;
        for pair in query.split('&') {
            if pair.is_empty() { continue; }
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == key {
                if !v.is_empty() { found = Some(v.to_string()); }
                continue;
            }
            kept.push(format!("{}={}", k, v));
        }
        if kept.is_empty() { (base.to_string(), found) }
        else { (format!("{}?{}", base, kept.join("&")), found) }
    } else {
        (url.to_string(), None)
    }
}

fn parse_nvd_last_modified(json: &Value) -> Option<DateTime<Utc>> {
    let s = json["vulnerabilities"].as_array()
        .and_then(|a| a.first())
        .and_then(|it| it["cve"]["lastModified"].as_str())?;
    // Try RFC3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) { return Some(dt.with_timezone(&Utc)); }
    // If missing timezone, try appending Z
    if !s.ends_with('Z') {
        let mut t = String::from(s);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) { return Some(dt.with_timezone(&Utc)); }
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
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) { return Some(dt.with_timezone(&Utc)); }
    if !s.ends_with('Z') {
        let mut t = String::from(s);
        t.push('Z');
        if let Ok(dt) = DateTime::parse_from_rfc3339(&t) { return Some(dt.with_timezone(&Utc)); }
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") { return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc)); }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") { return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc)); }
    None
}

fn compute_dynamic_ttl_days(last_mod: Option<DateTime<Utc>>, default_days: i64) -> i64 {
    let min_days: i64 = std::env::var("SCANNER_TTL_MIN_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(7);
    let max_days: i64 = std::env::var("SCANNER_TTL_MAX_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(180);
    if let Some(lm) = last_mod {
        let age_days = (Utc::now() - lm).num_days().clamp(1, 3650);
        age_days.clamp(min_days, max_days)
    } else {
        default_days.clamp(min_days, max_days)
    }
}

fn pg_get_osv(client: &mut PgClient, vuln_id: &str) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client.query_opt(
        "SELECT payload, last_checked_at, osv_last_modified FROM osv_vuln_cache WHERE vuln_id = $1",
        &[&vuln_id]
    ).ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let osv_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, osv_last_modified))
}

fn pg_put_osv(client: &mut PgClient, vuln_id: &str, payload: &Value, osv_last_modified: Option<DateTime<Utc>>) {
    let res = client.execute(
        "INSERT INTO osv_vuln_cache (vuln_id, payload, last_checked_at, osv_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (vuln_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), osv_last_modified = EXCLUDED.osv_last_modified",
        &[&vuln_id, &payload, &osv_last_modified]
    );
    match res {
        Ok(_) => progress("osv.cache.pg.put", &format!("{} lm={}", vuln_id, osv_last_modified.map(|d| d.to_rfc3339()).unwrap_or_else(|| "null".into()))),
        Err(e) => progress("osv.cache.pg.put.err", &format!("{} {}", vuln_id, e)),
    }
}

fn pg_get_cve(client: &mut PgClient, cve_id: &str) -> Option<(Value, DateTime<Utc>, Option<DateTime<Utc>>)> {
    let row = client.query_opt(
        "SELECT payload, last_checked_at, nvd_last_modified FROM nvd_cve_cache WHERE cve_id = $1",
        &[&cve_id]
    ).ok()??;
    let payload: serde_json::Value = row.get(0);
    let last_checked_at: DateTime<Utc> = row.get(1);
    let nvd_last_modified: Option<DateTime<Utc>> = row.get(2);
    Some((payload, last_checked_at, nvd_last_modified))
}

fn pg_put_cve(client: &mut PgClient, cve_id: &str, payload: &Value, nvd_last_modified: Option<DateTime<Utc>>) {
    let res = client.execute(
        "INSERT INTO nvd_cve_cache (cve_id, payload, last_checked_at, nvd_last_modified)\n         VALUES ($1, $2, NOW(), $3)\n         ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), nvd_last_modified = EXCLUDED.nvd_last_modified",
        &[&cve_id, &payload, &nvd_last_modified]
    );
    match res {
        Ok(_) => progress("nvd.cache.pg.put", &format!("{} lm={}", cve_id, nvd_last_modified.map(|d| d.to_rfc3339()).unwrap_or_else(|| "null".into()))),
        Err(e) => progress("nvd.cache.pg.put.err", &format!("{} {}", cve_id, e)),
    }
}
