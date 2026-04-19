use crate::container::PackageCoordinate;
use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};

use super::super::cvss::parse_cvss_score;
use super::super::version::cmp_versions;

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
                    license: pkg.license.clone(),
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
                    let mut cve_iter = cve_ids.into_iter();
                    let first_cve = cve_iter.next().unwrap();
                    // Build base finding once, clone for remaining aliases
                    let base = Finding {
                        id: first_cve.trim().to_string(),
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
                    };
                    out.push(base);
                    for cid in cve_iter {
                        let mut cloned = out.last().unwrap().clone();
                        cloned.id = cid.trim().to_string();
                        out.push(cloned);
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
