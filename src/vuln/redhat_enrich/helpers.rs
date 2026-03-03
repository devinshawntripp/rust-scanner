

use crate::redhat::compare_evr;
use crate::report::{CvssInfo, PackageInfo, ReferenceInfo};

pub(in crate::vuln) fn normalize_redhat_errata_id(id: &str) -> String {
    id.trim()
        .to_ascii_uppercase()
        .replace("%3A", ":")
        .replace("%3a", ":")
}

pub(in crate::vuln) fn retain_relevant_redhat_source_ids(source_ids: &mut Vec<String>, keep: Option<&str>) {
    source_ids.retain(|sid| {
        let norm = normalize_redhat_errata_id(sid);
        if is_redhat_errata_id(&norm) {
            return keep.map(|k| norm.eq_ignore_ascii_case(k)).unwrap_or(false);
        }
        true
    });
}

pub(in crate::vuln) fn extract_redhat_errata_from_url(url: &str) -> Option<String> {
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

pub(in crate::vuln) fn retain_relevant_redhat_references(refs: &mut Vec<ReferenceInfo>, keep: Option<&str>) {
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

pub(in crate::vuln) fn is_redhat_family_ecosystem(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "redhat" | "rpm" | "centos" | "rocky" | "almalinux"
    )
}

pub(in crate::vuln) fn normalize_reference_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    urlencoding::decode(trimmed)
        .map(|v| v.into_owned())
        .unwrap_or_else(|_| trimmed.to_string())
}

pub(in crate::vuln) fn append_unique_references(dest: &mut Vec<ReferenceInfo>, refs: Vec<ReferenceInfo>) {
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

pub(in crate::vuln) fn is_redhat_errata_id(id: &str) -> bool {
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

pub(in crate::vuln) fn redhat_cvss_from_vuln(vuln: &serde_json::Value) -> Option<CvssInfo> {
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

pub(in crate::vuln) fn redhat_note_text(document: &serde_json::Value) -> Option<String> {
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
pub(in crate::vuln) struct RedHatFixedRelease {
    pub(in crate::vuln) advisory: Option<String>,
    pub(in crate::vuln) package_name: String,
    pub(in crate::vuln) fixed_evr: String,
}

#[derive(Debug, Clone)]
pub(in crate::vuln) struct RedHatPackageState {
    pub(in crate::vuln) package_name: String,
    pub(in crate::vuln) fix_state: String,
    pub(in crate::vuln) cpe: Option<String>,
}

pub(in crate::vuln) fn parse_redhat_release_package(raw: &str) -> Option<(String, String)> {
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

pub(in crate::vuln) fn parse_redhat_package_states(json: &serde_json::Value) -> Vec<RedHatPackageState> {
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

pub(in crate::vuln) fn parse_redhat_cve_cvss(json: &serde_json::Value) -> Option<CvssInfo> {
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

pub(in crate::vuln) fn redhat_cve_references(json: &serde_json::Value) -> Vec<ReferenceInfo> {
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

pub(in crate::vuln) fn rpm_epoch(evr: &str) -> i64 {
    evr.split_once(':')
        .and_then(|(lhs, _)| lhs.parse::<i64>().ok())
        .unwrap_or(0)
}

pub(in crate::vuln) fn extract_el_tag(text: &str) -> Option<String> {
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

pub(in crate::vuln) fn extract_rhel_major_from_cpe(cpe: &str) -> Option<String> {
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

pub(in crate::vuln) fn extract_rhel_major_from_version(version: &str) -> Option<String> {
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

pub(in crate::vuln) fn strip_rpm_arch_suffix(name: &str) -> String {
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

pub(in crate::vuln) fn package_name_matches(installed: &str, candidate: &str) -> bool {
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

pub(in crate::vuln) fn parse_redhat_fixed_releases(json: &serde_json::Value) -> Vec<RedHatFixedRelease> {
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

pub(in crate::vuln) fn best_redhat_fixed_release(
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

pub(in crate::vuln) fn best_redhat_package_state(
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
