use std::collections::HashSet;

use serde_json::Value;

use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};
use super::super::http::{build_http_client, nvd_get_json};
use super::super::version::{cmp_versions, cpe_parts, is_version_in_range};
use super::super::circuit::CircuitBreaker;

/// Queries the NVD API for a given component + version (CLI interactive output)
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
                    println!("No descriptions found for CVE");
                    continue;
                }
            };

            let description = descs
                .iter()
                .find(|d| d["lang"] == "en")
                .and_then(|d| d["value"].as_str())
                .unwrap_or("No English description found");

            if seen.insert(id.to_string()) {
                println!("{}: {}", id, description);
                found = true;
            }
        }
    }

    if !found {
        println!("No CVEs found for: {} {}", component, version);
    }
}

/// Extract CVSS info from NVD CVE JSON (v3.1 -> v3.0 -> v2 fallback)
fn extract_nvd_cvss(cve: &Value) -> (Option<CvssInfo>, Option<String>) {
    let metric = cve["metrics"]["cvssMetricV31"]
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
        });

    if let Some(m) = metric {
        let base = m["cvssData"]["baseScore"].as_f64().unwrap_or(0.0) as f32;
        let vector = m["cvssData"]["vectorString"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let cvss = Some(CvssInfo {
            base,
            vector,
        });
        let severity = Some(severity_from_score(base).to_string());
        (cvss, severity)
    } else {
        (None, None)
    }
}

/// Extract English description from NVD CVE JSON
fn extract_nvd_description(cve: &Value) -> Option<String> {
    cve["descriptions"]
        .as_array()
        .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
        .and_then(|d| d["value"].as_str())
        .map(|s| s.to_string())
}

/// Extract references from NVD CVE JSON
fn extract_nvd_references(cve: &Value) -> Vec<ReferenceInfo> {
    let mut references = Vec::new();
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
    references
}

/// Resolve NVD sleep duration from env or API key presence
fn nvd_sleep_ms(api_key: Option<&str>) -> u64 {
    let default_ms = match api_key {
        Some(_) => 400u64,
        None => 6000u64,
    };
    std::env::var("SCANNER_NVD_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_ms)
}

/// Query NVD by keyword (component + version) and map to findings.
pub fn nvd_keyword_findings(
    component: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
    breaker: &CircuitBreaker,
) -> Vec<Finding> {
    if breaker.is_open() {
        return Vec::new();
    }
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(&keyword)
    );
    let sleep_ms = nvd_sleep_ms(api_key);
    let json = match nvd_get_json(&url, api_key, &format!("kw:{}", keyword), sleep_ms) {
        Some(j) => { breaker.record_success(); j }
        None => { breaker.record_failure(); return Vec::new(); }
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = extract_nvd_description(cve);
            let (cvss, severity) = extract_nvd_cvss(cve);
            let references = extract_nvd_references(cve);
            let evidence = vec![EvidenceItem {
                evidence_type: "hint".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(format!("keyword match: {} {}", component, version)),
            }];
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

/// Query NVD by CPE name constructed from component/version
pub fn nvd_cpe_findings(
    component: &str,
    version: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
    breaker: &CircuitBreaker,
) -> Vec<Finding> {
    if breaker.is_open() {
        return Vec::new();
    }
    let vendor = component.to_lowercase();
    let product = component.to_lowercase();
    let cpe = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}",
        urlencoding::encode(&cpe)
    );
    let sleep_ms = nvd_sleep_ms(api_key);
    let json = match nvd_get_json(&url, api_key, &format!("cpe:{}", cpe), sleep_ms) {
        Some(j) => { breaker.record_success(); j }
        None => { breaker.record_failure(); return Vec::new(); }
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = extract_nvd_description(cve);
            let (cvss, severity) = extract_nvd_cvss(cve);
            let references = extract_nvd_references(cve);
            let evidence = vec![EvidenceItem {
                evidence_type: "cpe".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(cpe.clone()),
            }];
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

/// NVD keyword search by name only (low confidence).
pub fn nvd_keyword_findings_name(
    component: &str,
    api_key: Option<&str>,
    evidence_path: Option<&str>,
    breaker: &CircuitBreaker,
) -> Vec<Finding> {
    if breaker.is_open() {
        return Vec::new();
    }
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=50",
        urlencoding::encode(component)
    );
    let sleep_ms = nvd_sleep_ms(api_key);
    let json = match nvd_get_json(&url, api_key, &format!("kw_only:{}", component), sleep_ms) {
        Some(j) => { breaker.record_success(); j }
        None => { breaker.record_failure(); return Vec::new(); }
    };

    let mut out = Vec::new();
    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let cve = &item["cve"];
            let id = cve["id"].as_str().unwrap_or("unknown").to_string();
            let description = extract_nvd_description(cve);
            let (cvss, severity) = extract_nvd_cvss(cve);
            let references = extract_nvd_references(cve);
            let evidence = vec![EvidenceItem {
                evidence_type: "hint".into(),
                path: evidence_path.map(|s| s.to_string()),
                detail: Some(format!("keyword match: {}", component)),
            }];
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
    breaker: &CircuitBreaker,
) -> Vec<Finding> {
    if breaker.is_open() {
        return Vec::new();
    }
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=2000",
        urlencoding::encode(product)
    );
    let sleep_ms = nvd_sleep_ms(api_key);
    let json = match nvd_get_json(&url, api_key, &format!("prod:{}", product), sleep_ms) {
        Some(j) => { breaker.record_success(); j }
        None => { breaker.record_failure(); return Vec::new(); }
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
                                    } else if !is_version_in_range(
                                        version, start_inc, start_exc, end_inc, end_exc,
                                    ) {
                                        continue;
                                    }

                                    let id = cve["id"].as_str().unwrap_or("unknown").to_string();
                                    let description = extract_nvd_description(cve);
                                    let (cvss, severity) = extract_nvd_cvss(cve);
                                    let references = extract_nvd_references(cve);
                                    let evidence = vec![EvidenceItem {
                                        evidence_type: "cpe".into(),
                                        path: evidence_path.map(|s| s.to_string()),
                                        detail: Some(criteria.to_string()),
                                    }];
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
            let _ = matches_product;
        }
    }
    out
}
