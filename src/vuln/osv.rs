use std::path::PathBuf;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use reqwest::blocking::Client;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};
use crate::utils::{progress, progress_timing};

use super::cvss::parse_cvss_score;
use super::env_bool;
use super::http::build_http_client;
use super::pg::{
    compute_dynamic_ttl_days, parse_osv_last_modified, pg_get_osv, pg_init_schema, pg_put_osv,
    resolve_enrich_cache_dir,
};
use super::version::cmp_versions;

/// Batch query OSV with package coordinates. Returns a JSON value (array of results)
pub fn osv_batch_query(packages: &Vec<PackageCoordinate>) -> serde_json::Value {
    if packages.is_empty() {
        return serde_json::json!([]);
    }

    let cache_dir = resolve_enrich_cache_dir();

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
                                            cache_dir.as_deref(),
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
        if let Some(mut mapped) = super::map_debian_advisory_to_cves(id, pg) {
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

pub(super) fn drop_fixed_findings(findings: &mut Vec<Finding>) -> usize {
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

pub(super) fn dedupe_findings_by_id_and_package(findings: &mut Vec<Finding>) {
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
            osv_apply_payload_to_findings(&id, json, findings, pg);
            progress("osv.fetch.ok", &id);
        }
    }
    progress_timing("osv.enrich.apply", phase_apply_started);

    // Advisory-level enrichment for Red Hat errata IDs (RHSA/RHBA/RHEA).
    // This fills severity/cvss/description/references so they don't stay as empty "Other" rows.
    super::redhat_enrich_findings(findings, pg);
    // CVE-level Red Hat enrichment computes package applicability and fixed package versions.
    super::redhat_enrich_cve_findings(findings, pg);
    // First-class distro advisory enrichment for Debian/Ubuntu/Alpine.
    super::distro_feed_enrich_findings(findings, pg);
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
