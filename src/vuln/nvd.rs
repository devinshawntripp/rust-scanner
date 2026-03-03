use std::collections::HashSet;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use rayon::prelude::*;
use serde_json::Value;

use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};
use crate::utils::{progress, progress_timing};

use super::env_bool;
use super::http::{build_http_client, nvd_get_json};
use super::pg::{
    compute_dynamic_ttl_days, parse_nvd_last_modified, pg_get_cve, pg_init_schema, pg_put_cve,
};
use super::version::{cmp_versions, cpe_parts, is_version_in_range};

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
            // Support both full NVD API format ({"vulnerabilities":[{"cve":{...}}]})
            // and inner CVE object format ({"id":"CVE-...", "metrics":{...}}) from bulk import
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
