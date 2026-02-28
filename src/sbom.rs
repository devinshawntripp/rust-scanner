use crate::container::PackageCoordinate;
use crate::report::{
    compute_summary, retag_findings, ConfidenceTier, EvidenceSource, InventoryStatus, Report,
    SbomInfo, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

const SBOM_HEURISTIC_NOTE: &str =
    "Findings were derived from imported SBOM package metadata, not runtime installed-state extraction.";

pub fn build_sbom_report(
    path: &str,
    _mode: ScanMode,
    nvd_api_key: Option<String>,
) -> Option<Report> {
    crate::utils::progress("sbom.import.start", path);
    let parsed = parse_sbom_packages(path).ok()?;
    crate::utils::progress(
        "sbom.import.detect.done",
        &format!(
            "format={} packages={}",
            parsed.format,
            parsed.packages.len()
        ),
    );

    let mut findings = if parsed.packages.is_empty() {
        Vec::new()
    } else {
        let mut pg = crate::vuln::pg_connect();
        if let Some(c) = pg.as_mut() {
            crate::vuln::pg_init_schema(c);
        }

        crate::utils::progress(
            "sbom.osv.query.start",
            &format!("packages={}", parsed.packages.len()),
        );
        let osv_results = osv_batch_query(&parsed.packages);
        let mut rows = map_osv_results_to_findings(&parsed.packages, &osv_results);

        crate::utils::progress(
            "sbom.enrich.osv.start",
            &format!("findings_pre_enrich={}", rows.len()),
        );
        osv_enrich_findings(&mut rows, &mut pg);

        let nvd_enabled = std::env::var("SCANNER_NVD_ENRICH")
            .map(|v| v != "0")
            .unwrap_or(true);
        if nvd_enabled {
            crate::utils::progress(
                "sbom.enrich.nvd.start",
                &format!("findings_pre_nvd={}", rows.len()),
            );
            enrich_findings_with_nvd(&mut rows, nvd_api_key.as_deref(), &mut pg);
        } else {
            crate::utils::progress("sbom.enrich.nvd.skip", "disabled by SCANNER_NVD_ENRICH");
        }

        retag_findings(
            &mut rows,
            ConfidenceTier::HeuristicUnverified,
            EvidenceSource::RepoMetadata,
            Some(SBOM_HEURISTIC_NOTE),
        );
        rows
    };

    findings.sort_by(|a, b| {
        let ak = a
            .package
            .as_ref()
            .map(|p| format!("{}:{}:{}", p.ecosystem, p.name, p.version))
            .unwrap_or_default();
        let bk = b
            .package
            .as_ref()
            .map(|p| format!("{}:{}:{}", p.ecosystem, p.name, p.version))
            .unwrap_or_default();
        ak.cmp(&bk).then_with(|| a.id.cmp(&b.id))
    });

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::vuln::epss_enrich_findings(&mut findings, cache_dir.as_deref());
    crate::vuln::kev_enrich_findings(&mut findings, cache_dir.as_deref());

    let summary = compute_summary(&findings);
    let (scan_status, inventory_status, inventory_reason) = if parsed.packages.is_empty() {
        (
            ScanStatus::Unsupported,
            InventoryStatus::Missing,
            Some("sbom_contains_no_packages".to_string()),
        )
    } else {
        (
            ScanStatus::Complete,
            InventoryStatus::Partial,
            Some("external_sbom_inventory".to_string()),
        )
    };

    crate::utils::progress(
        "sbom.import.done",
        &format!(
            "packages={} findings={}",
            parsed.packages.len(),
            summary.total_findings
        ),
    );

    Some(Report {
        scanner: ScannerInfo {
            name: "scanrook",
            version: env!("CARGO_PKG_VERSION"),
        },
        target: TargetInfo {
            target_type: "sbom".into(),
            source: path.into(),
            id: None,
        },
        scan_status,
        inventory_status,
        inventory_reason,
        sbom: Some(SbomInfo {
            format: parsed.format,
            path: path.into(),
        }),
        findings,
        files: Vec::new(),
        summary,
    })
}

#[derive(Debug)]
pub struct ParsedSbom {
    pub format: String,
    pub packages: Vec<PackageCoordinate>,
}

pub fn parse_sbom_packages(path: &str) -> anyhow::Result<ParsedSbom> {
    let raw = std::fs::read_to_string(path)?;
    let json: Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse SBOM JSON: {}", e))?;

    let (format, mut packages) = if is_cyclonedx(&json) {
        ("cyclonedx".to_string(), parse_cyclonedx_packages(&json))
    } else if is_spdx(&json) {
        ("spdx".to_string(), parse_spdx_packages(&json))
    } else if is_syft_native(&json) {
        ("syft".to_string(), parse_syft_packages(&json))
    } else {
        return Err(anyhow::anyhow!(
            "unsupported SBOM format (expected CycloneDX JSON, SPDX JSON, or Syft JSON)"
        ));
    };

    dedupe_and_sort_packages(&mut packages);
    Ok(ParsedSbom { format, packages })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangedPackage {
    pub ecosystem: String,
    pub name: String,
    pub from_version: String,
    pub to_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SbomDiffSummary {
    pub baseline_packages: usize,
    pub current_packages: usize,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SbomDiff {
    pub baseline_format: String,
    pub current_format: String,
    pub summary: SbomDiffSummary,
    pub added: Vec<PackageCoordinate>,
    pub removed: Vec<PackageCoordinate>,
    pub changed: Vec<ChangedPackage>,
}

pub fn build_sbom_diff(baseline: &str, current: &str) -> anyhow::Result<SbomDiff> {
    let base = parse_sbom_packages(baseline)?;
    let curr = parse_sbom_packages(current)?;

    let mut base_map: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut curr_map: BTreeMap<(String, String), String> = BTreeMap::new();

    for p in &base.packages {
        base_map.insert((p.ecosystem.clone(), p.name.clone()), p.version.clone());
    }
    for p in &curr.packages {
        curr_map.insert((p.ecosystem.clone(), p.name.clone()), p.version.clone());
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for ((eco, name), ver) in &curr_map {
        match base_map.get(&(eco.clone(), name.clone())) {
            None => added.push(PackageCoordinate {
                ecosystem: eco.clone(),
                name: name.clone(),
                version: ver.clone(),
            source_name: None,
            }),
            Some(old) if old != ver => changed.push(ChangedPackage {
                ecosystem: eco.clone(),
                name: name.clone(),
                from_version: old.clone(),
                to_version: ver.clone(),
            }),
            _ => {}
        }
    }

    for ((eco, name), ver) in &base_map {
        if !curr_map.contains_key(&(eco.clone(), name.clone())) {
            removed.push(PackageCoordinate {
                ecosystem: eco.clone(),
                name: name.clone(),
                version: ver.clone(),
            source_name: None,
            });
        }
    }

    Ok(SbomDiff {
        baseline_format: base.format,
        current_format: curr.format,
        summary: SbomDiffSummary {
            baseline_packages: base.packages.len(),
            current_packages: curr.packages.len(),
            added: added.len(),
            removed: removed.len(),
            changed: changed.len(),
        },
        added,
        removed,
        changed,
    })
}

fn is_cyclonedx(v: &Value) -> bool {
    v.get("bomFormat")
        .and_then(|x| x.as_str())
        .map(|s| s.eq_ignore_ascii_case("cyclonedx"))
        .unwrap_or(false)
}

fn is_spdx(v: &Value) -> bool {
    v.get("spdxVersion")
        .and_then(|x| x.as_str())
        .map(|s| s.to_uppercase().starts_with("SPDX-"))
        .unwrap_or(false)
}

fn is_syft_native(v: &Value) -> bool {
    v.get("artifacts").and_then(|x| x.as_array()).is_some()
}

fn parse_cyclonedx_packages(doc: &Value) -> Vec<PackageCoordinate> {
    let mut out = Vec::new();
    if let Some(components) = doc.get("components").and_then(|x| x.as_array()) {
        for c in components {
            parse_cyclonedx_component(c, &mut out);
        }
    }
    out
}

fn parse_cyclonedx_component(component: &Value, out: &mut Vec<PackageCoordinate>) {
    if let Some(coord) = package_from_component(component) {
        out.push(coord);
    }
    if let Some(children) = component.get("components").and_then(|x| x.as_array()) {
        for c in children {
            parse_cyclonedx_component(c, out);
        }
    }
}

fn package_from_component(component: &Value) -> Option<PackageCoordinate> {
    if let Some(purl) = component.get("purl").and_then(|x| x.as_str()).or_else(|| {
        component
            .get("bom-ref")
            .and_then(|x| x.as_str())
            .filter(|v| v.starts_with("pkg:"))
    }) {
        if let Some((ecosystem, name, version)) = parse_purl(purl) {
            return Some(PackageCoordinate {
                ecosystem,
                name,
                version,
                source_name: None,
            });
        }
    }

    let name = component.get("name").and_then(|x| x.as_str())?.trim();
    let version = component.get("version").and_then(|x| x.as_str())?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let ecosystem = component
        .get("type")
        .and_then(|x| x.as_str())
        .map(map_type_to_ecosystem)
        .unwrap_or_else(|| "unknown".to_string());

    Some(PackageCoordinate {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
    source_name: None,
    })
}

fn parse_spdx_packages(doc: &Value) -> Vec<PackageCoordinate> {
    let mut out = Vec::new();
    let Some(packages) = doc.get("packages").and_then(|x| x.as_array()) else {
        return out;
    };

    for pkg in packages {
        if let Some(coord) = package_from_spdx(pkg) {
            out.push(coord);
        }
    }

    out
}

fn package_from_spdx(pkg: &Value) -> Option<PackageCoordinate> {
    if let Some(ext_refs) = pkg.get("externalRefs").and_then(|x| x.as_array()) {
        for ext in ext_refs {
            let r#type = ext
                .get("referenceType")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if r#type == "purl" {
                if let Some(locator) = ext.get("referenceLocator").and_then(|x| x.as_str()) {
                    if let Some((ecosystem, name, version)) = parse_purl(locator) {
                        return Some(PackageCoordinate {
                            ecosystem,
                            name,
                            version,
                            source_name: None,
                        });
                    }
                }
            }
        }
    }

    let name = pkg
        .get("name")
        .and_then(|x| x.as_str())
        .or_else(|| pkg.get("packageName").and_then(|x| x.as_str()))?
        .trim();
    let version = pkg
        .get("versionInfo")
        .and_then(|x| x.as_str())
        .or_else(|| pkg.get("packageVersion").and_then(|x| x.as_str()))?
        .trim();

    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some(PackageCoordinate {
        ecosystem: "unknown".to_string(),
        name: name.to_string(),
        version: version.to_string(),
    source_name: None,
    })
}

fn parse_syft_packages(doc: &Value) -> Vec<PackageCoordinate> {
    let mut out = Vec::new();
    let Some(artifacts) = doc.get("artifacts").and_then(|x| x.as_array()) else {
        return out;
    };

    for art in artifacts {
        if let Some(purl) = art.get("purl").and_then(|x| x.as_str()) {
            if let Some((ecosystem, name, version)) = parse_purl(purl) {
                out.push(PackageCoordinate {
                    ecosystem,
                    name,
                    version,
                    source_name: None,
                });
                continue;
            }
        }

        let name = art
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim();
        let version = art
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }

        let ecosystem = art
            .get("type")
            .and_then(|x| x.as_str())
            .map(map_type_to_ecosystem)
            .unwrap_or_else(|| "unknown".to_string());

        out.push(PackageCoordinate {
            ecosystem,
            name: name.to_string(),
            version: version.to_string(),
        source_name: None,
        });
    }

    out
}

fn parse_purl(purl: &str) -> Option<(String, String, String)> {
    let raw = purl.trim();
    let s = raw.strip_prefix("pkg:")?;

    let without_frag = s.split('#').next().unwrap_or(s);
    let without_query = without_frag.split('?').next().unwrap_or(without_frag);
    let (body, version) = without_query.split_once('@')?;
    if version.trim().is_empty() {
        return None;
    }

    let mut body_parts = body.split('/');
    let ptype = body_parts.next()?.trim();
    let name = body_parts.last()?.trim();
    if ptype.is_empty() || name.is_empty() {
        return None;
    }

    let ecosystem = map_type_to_ecosystem(ptype);
    Some((ecosystem, name.to_string(), version.trim().to_string()))
}

fn map_type_to_ecosystem(raw: &str) -> String {
    match raw.to_lowercase().as_str() {
        "deb" => "deb".to_string(),
        "apk" => "apk".to_string(),
        "rpm" => "redhat".to_string(),
        "golang" => "go".to_string(),
        "gem" => "ruby".to_string(),
        "cargo" => "rust".to_string(),
        "composer" => "php".to_string(),
        other => other.to_string(),
    }
}

fn dedupe_and_sort_packages(packages: &mut Vec<PackageCoordinate>) {
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    packages.retain(|p| {
        seen.insert((
            p.ecosystem.to_lowercase(),
            p.name.to_lowercase(),
            p.version.to_lowercase(),
        ))
    });
    packages.sort_by(|a, b| {
        a.ecosystem
            .cmp(&b.ecosystem)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
}

// ─── SBOM Policy Gates ────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SbomPolicy {
    /// Maximum number of new CRITICAL findings allowed (0 = block any)
    #[serde(default)]
    pub max_new_critical: Option<usize>,
    /// Maximum number of new HIGH findings allowed
    #[serde(default)]
    pub max_new_high: Option<usize>,
    /// Deny list: glob patterns for package names that must not appear
    #[serde(default)]
    pub deny_list: Vec<String>,
    /// Block if packages were removed between baseline and current
    #[serde(default)]
    pub block_removed: bool,
    /// Block if any findings are in CISA KEV
    #[serde(default)]
    pub block_kev: bool,
}

#[derive(Debug, Serialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct PolicyCheckResult {
    pub passed: bool,
    pub violations: Vec<PolicyViolation>,
    pub diff_summary: SbomDiffSummary,
}

pub fn load_policy(path: &str) -> anyhow::Result<SbomPolicy> {
    let raw = std::fs::read_to_string(path)?;
    // Support both YAML and JSON
    if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse policy YAML: {}", e))
    } else {
        serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse policy JSON: {}", e))
    }
}

/// Check policy using a parsed serde_json::Value for the report (avoids &'static str issue).
pub fn check_policy_from_value(
    policy: &SbomPolicy,
    diff: &SbomDiff,
    report_value: Option<&Value>,
) -> PolicyCheckResult {
    let summary = report_value
        .and_then(|v| v.get("summary"))
        .cloned()
        .unwrap_or_default();
    let findings = report_value
        .and_then(|v| v.get("findings"))
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();

    let critical = summary
        .get("critical")
        .and_then(|n| n.as_u64())
        .unwrap_or(0) as usize;
    let high = summary.get("high").and_then(|n| n.as_u64()).unwrap_or(0) as usize;
    let kev_count = findings
        .iter()
        .filter(|f| f.get("in_kev").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();

    check_policy_inner(policy, diff, critical, high, kev_count)
}

pub fn check_policy(
    policy: &SbomPolicy,
    diff: &SbomDiff,
    current_report: Option<&crate::report::Report>,
) -> PolicyCheckResult {
    let (critical, high, kev_count) = current_report
        .map(|r| {
            let kev = r.findings.iter().filter(|f| f.in_kev == Some(true)).count();
            (r.summary.critical, r.summary.high, kev)
        })
        .unwrap_or((0, 0, 0));
    check_policy_inner(policy, diff, critical, high, kev_count)
}

fn check_policy_inner(
    policy: &SbomPolicy,
    diff: &SbomDiff,
    critical: usize,
    high: usize,
    kev_count: usize,
) -> PolicyCheckResult {
    let mut violations = Vec::new();

    // Check deny list against added packages
    for pattern in &policy.deny_list {
        let pat_lower = pattern.to_lowercase();
        for pkg in &diff.added {
            let name_lower = pkg.name.to_lowercase();
            let matches = if pat_lower.contains('*') {
                let parts: Vec<&str> = pat_lower.split('*').collect();
                if parts.len() == 2 {
                    name_lower.starts_with(parts[0]) && name_lower.ends_with(parts[1])
                } else {
                    name_lower.contains(pat_lower.trim_matches('*'))
                }
            } else {
                name_lower == pat_lower
            };
            if matches {
                violations.push(PolicyViolation {
                    rule: "deny_list".into(),
                    detail: format!(
                        "package '{}@{}' matches denied pattern '{}'",
                        pkg.name, pkg.version, pattern
                    ),
                });
            }
        }
    }

    // Check block_removed
    if policy.block_removed && !diff.removed.is_empty() {
        violations.push(PolicyViolation {
            rule: "block_removed".into(),
            detail: format!(
                "{} packages were removed: {}",
                diff.removed.len(),
                diff.removed
                    .iter()
                    .take(5)
                    .map(|p| format!("{}@{}", p.name, p.version))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }

    // Check severity thresholds
    if let Some(max_crit) = policy.max_new_critical {
        if critical > max_crit {
            violations.push(PolicyViolation {
                rule: "max_new_critical".into(),
                detail: format!(
                    "found {} CRITICAL findings, max allowed is {}",
                    critical, max_crit
                ),
            });
        }
    }
    if let Some(max_high) = policy.max_new_high {
        if high > max_high {
            violations.push(PolicyViolation {
                rule: "max_new_high".into(),
                detail: format!("found {} HIGH findings, max allowed is {}", high, max_high),
            });
        }
    }
    if policy.block_kev && kev_count > 0 {
        violations.push(PolicyViolation {
            rule: "block_kev".into(),
            detail: format!(
                "{} findings are in CISA KEV (actively exploited)",
                kev_count
            ),
        });
    }

    PolicyCheckResult {
        passed: violations.is_empty(),
        violations,
        diff_summary: SbomDiffSummary {
            baseline_packages: diff.summary.baseline_packages,
            current_packages: diff.summary.current_packages,
            added: diff.summary.added,
            removed: diff.summary.removed,
            changed: diff.summary.changed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cyclonedx_with_purl() {
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "components": [
                {"name":"bash","version":"5.2.15","purl":"pkg:deb/debian/bash@5.2.15-2"},
                {"name":"openssl","version":"3.0.10","purl":"pkg:rpm/redhat/openssl@3.0.10-1"}
            ]
        });
        let mut pkgs = parse_cyclonedx_packages(&doc);
        dedupe_and_sort_packages(&mut pkgs);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "deb");
        assert_eq!(pkgs[1].ecosystem, "redhat");
    }

    #[test]
    fn parse_spdx_with_external_purl() {
        let doc = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "musl",
                    "versionInfo": "1.2.4-r0",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:apk/alpine/musl@1.2.4-r0"}
                    ]
                }
            ]
        });
        let pkgs = parse_spdx_packages(&doc);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, "apk");
        assert_eq!(pkgs[0].name, "musl");
    }

    #[test]
    fn parse_purl_handles_query_fragment() {
        let p = parse_purl("pkg:deb/debian/coreutils@8.32-4?arch=amd64#x").unwrap();
        assert_eq!(p.0, "deb");
        assert_eq!(p.1, "coreutils");
        assert_eq!(p.2, "8.32-4");
    }
}
