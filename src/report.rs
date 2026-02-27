use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Complete,
    PartialFailed,
    Unsupported,
}

impl Default for ScanStatus {
    fn default() -> Self {
        Self::Complete
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Complete,
    Partial,
    Missing,
}

impl Default for InventoryStatus {
    fn default() -> Self {
        Self::Complete
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    ConfirmedInstalled,
    HeuristicUnverified,
}

impl Default for ConfidenceTier {
    fn default() -> Self {
        Self::ConfirmedInstalled
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    InstalledDb,
    RepoMetadata,
    FilenameHeuristic,
    BinaryHeuristic,
}

impl Default for EvidenceSource {
    fn default() -> Self {
        Self::InstalledDb
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct ScannerInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TargetInfo {
    #[serde(rename = "type")]
    pub target_type: String,
    pub source: String,
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomInfo {
    pub format: String,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CvssInfo {
    pub base: f32,
    pub vector: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub ecosystem: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReferenceInfo {
    #[serde(rename = "type")]
    pub reference_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EvidenceItem {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub path: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub id: String,
    pub source_ids: Vec<String>,
    pub package: Option<PackageInfo>,
    pub confidence_tier: ConfidenceTier,
    pub evidence_source: EvidenceSource,
    pub accuracy_note: Option<String>,
    pub fixed: Option<bool>,
    pub fixed_in: Option<String>,
    pub recommendation: Option<String>,
    pub severity: Option<String>,
    pub cvss: Option<CvssInfo>,
    pub description: Option<String>,
    pub evidence: Vec<EvidenceItem>,
    pub references: Vec<ReferenceInfo>,
    pub confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_kev: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub path: String,
    pub entry_type: String,
    pub size_bytes: Option<u64>,
    pub mode: Option<String>,
    pub mtime: Option<String>,
    pub sha256: Option<String>,
    pub parent_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Summary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub confirmed_total_findings: usize,
    pub heuristic_total_findings: usize,
    pub confirmed_critical: usize,
    pub confirmed_high: usize,
    pub confirmed_medium: usize,
    pub confirmed_low: usize,
    pub heuristic_critical: usize,
    pub heuristic_high: usize,
    pub heuristic_medium: usize,
    pub heuristic_low: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct Report {
    pub scanner: ScannerInfo,
    pub target: TargetInfo,
    pub scan_status: ScanStatus,
    pub inventory_status: InventoryStatus,
    pub inventory_reason: Option<String>,
    pub sbom: Option<SbomInfo>,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileEntry>,
    pub summary: Summary,
}

pub fn compute_summary(findings: &[Finding]) -> Summary {
    let mut s = Summary::default();
    s.total_findings = findings.len();
    for f in findings {
        let is_confirmed = matches!(f.confidence_tier, ConfidenceTier::ConfirmedInstalled);
        if is_confirmed {
            s.confirmed_total_findings += 1;
        } else {
            s.heuristic_total_findings += 1;
        }
        match f.severity.as_deref() {
            Some("CRITICAL") => {
                s.critical += 1;
                if is_confirmed {
                    s.confirmed_critical += 1;
                } else {
                    s.heuristic_critical += 1;
                }
            }
            Some("HIGH") => {
                s.high += 1;
                if is_confirmed {
                    s.confirmed_high += 1;
                } else {
                    s.heuristic_high += 1;
                }
            }
            Some("MEDIUM") => {
                s.medium += 1;
                if is_confirmed {
                    s.confirmed_medium += 1;
                } else {
                    s.heuristic_medium += 1;
                }
            }
            Some("LOW") => {
                s.low += 1;
                if is_confirmed {
                    s.confirmed_low += 1;
                } else {
                    s.heuristic_low += 1;
                }
            }
            _ => {}
        }
    }
    s
}

pub fn retag_findings(
    findings: &mut [Finding],
    tier: ConfidenceTier,
    source: EvidenceSource,
    note: Option<&str>,
) {
    for f in findings.iter_mut() {
        f.confidence_tier = tier;
        f.evidence_source = source;
        if let Some(n) = note {
            if f.accuracy_note.is_none() {
                f.accuracy_note = Some(n.to_string());
            }
        }
    }
}

pub fn severity_from_score(score: f32) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "None"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_finding(id: &str, severity: &str, tier: ConfidenceTier) -> Finding {
        Finding {
            id: id.to_string(),
            source_ids: Vec::new(),
            package: None,
            confidence_tier: tier,
            evidence_source: EvidenceSource::InstalledDb,
            accuracy_note: None,
            fixed: None,
            fixed_in: None,
            recommendation: None,
            severity: Some(severity.to_string()),
            cvss: None,
            description: None,
            evidence: Vec::new(),
            references: Vec::new(),
            confidence: None,
            epss_score: None,
            epss_percentile: None,
            in_kev: None,
        }
    }

    #[test]
    fn compute_summary_tracks_confirmed_and_heuristic_splits() {
        let findings = vec![
            mk_finding(
                "CVE-2024-0001",
                "CRITICAL",
                ConfidenceTier::ConfirmedInstalled,
            ),
            mk_finding("CVE-2024-0002", "HIGH", ConfidenceTier::ConfirmedInstalled),
            mk_finding(
                "CVE-2024-0003",
                "CRITICAL",
                ConfidenceTier::HeuristicUnverified,
            ),
            mk_finding(
                "CVE-2024-0004",
                "MEDIUM",
                ConfidenceTier::HeuristicUnverified,
            ),
        ];
        let summary = compute_summary(&findings);
        assert_eq!(summary.total_findings, 4);
        assert_eq!(summary.confirmed_total_findings, 2);
        assert_eq!(summary.heuristic_total_findings, 2);
        assert_eq!(summary.confirmed_critical, 1);
        assert_eq!(summary.confirmed_high, 1);
        assert_eq!(summary.heuristic_critical, 1);
        assert_eq!(summary.heuristic_medium, 1);
    }
}
