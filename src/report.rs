use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct ScannerInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct TargetInfo {
    #[serde(rename = "type")]
    pub target_type: String,
    pub source: String,
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SbomInfo {
    pub format: String,
    pub path: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct CvssInfo {
    pub base: f32,
    pub vector: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub ecosystem: String,
    pub version: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ReferenceInfo {
    #[serde(rename = "type")]
    pub reference_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct EvidenceItem {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub path: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub source_ids: Vec<String>,
    pub package: Option<PackageInfo>,
    pub fixed: Option<bool>,
    pub severity: Option<String>,
    pub cvss: Option<CvssInfo>,
    pub description: Option<String>,
    pub evidence: Vec<EvidenceItem>,
    pub references: Vec<ReferenceInfo>,
    pub confidence: Option<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Summary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct Report {
    pub scanner: ScannerInfo,
    pub target: TargetInfo,
    pub sbom: Option<SbomInfo>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

pub fn compute_summary(findings: &[Finding]) -> Summary {
    let mut s = Summary::default();
    s.total_findings = findings.len();
    for f in findings {
        match f.severity.as_deref() {
            Some("CRITICAL") => s.critical += 1,
            Some("HIGH") => s.high += 1,
            Some("MEDIUM") => s.medium += 1,
            Some("LOW") => s.low += 1,
            _ => {}
        }
    }
    s
}

pub fn severity_from_score(score: f32) -> &'static str {
    if score >= 9.0 { "CRITICAL" }
    else if score >= 7.0 { "HIGH" }
    else if score >= 4.0 { "MEDIUM" }
    else if score > 0.0 { "LOW" }
    else { "LOW" }
}

