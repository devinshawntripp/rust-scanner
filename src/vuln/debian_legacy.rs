use std::collections::HashSet;

use crate::container::PackageCoordinate;
use crate::report::{
    ConfidenceTier, EvidenceItem, EvidenceSource, Finding, PackageInfo, ReferenceInfo,
};
use crate::utils::progress;
use serde_json::Value;

use super::http::enrich_http_client;
use super::version::cmp_versions;

fn debian_tracker_enabled() -> bool {
    std::env::var("SCANNER_DEBIAN_TRACKER")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

/// Detect the Debian release codename from a set of packages.
/// Returns "bookworm" for Debian 12, "bullseye" for 11, "trixie" for 13, etc.
pub(super) fn detect_debian_release(packages: &[PackageCoordinate]) -> Option<&'static str> {
    // Check versions — Debian packages include the release codename in certain patterns
    // The most reliable way is from the dpkg status which includes versions like "2.36-9+deb12u9"
    for pkg in packages {
        if pkg.ecosystem != "deb" && pkg.ecosystem != "ubuntu-deb" {
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

    let deb_packages: Vec<&PackageCoordinate> = packages
        .iter()
        .filter(|p| (p.ecosystem == "deb" || p.ecosystem == "ubuntu-deb"))
        .collect();
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
        .filter_map(|f| f.package.as_ref().map(|p| (f.id.clone(), p.name.clone())))
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
                    url: format!("https://security-tracker.debian.org/tracker/{}", cve_id),
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

pub(super) fn urgency_to_severity(urgency: &str) -> &'static str {
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
    let _cache_key_str = "debian_tracker_json_v1";

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
    progress(
        "debian.tracker.fetch",
        "https://security-tracker.debian.org/tracker/data/json",
    );
    let client = enrich_http_client();
    let resp = client
        .get("https://security-tracker.debian.org/tracker/data/json")
        .timeout(std::time::Duration::from_secs(120))
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Debian tracker HTTP {}", resp.status()));
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
