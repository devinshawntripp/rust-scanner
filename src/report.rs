use serde::{Deserialize, Serialize};
use std::io::Write;

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
    /// User-facing warnings (e.g. circuit breaker trips). Absent from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_profile: Option<IsoProfile>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IsoProfile {
    pub environment: String,
    pub environment_name: String,
    pub total_available_packages: usize,
    pub default_install_packages: usize,
    pub mandatory_groups: Vec<String>,
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

/// Convert a monolithic JSON report Value into NDJSON string.
/// Used by subcommands (scan, sbom) that work with serde_json::Value.
pub fn value_to_ndjson(v: &serde_json::Value) -> String {
    let mut lines = Vec::new();
    // header
    let header = serde_json::json!({
        "type": "header",
        "scanner": v.get("scanner"),
        "target": v.get("target"),
    });
    lines.push(serde_json::to_string(&header).unwrap());
    // metadata
    let metadata = serde_json::json!({
        "type": "metadata",
        "scan_status": v.get("scan_status"),
        "inventory_status": v.get("inventory_status"),
        "inventory_reason": v.get("inventory_reason"),
    });
    lines.push(serde_json::to_string(&metadata).unwrap());
    // findings
    if let Some(findings) = v.get("findings").and_then(|f| f.as_array()) {
        for finding in findings {
            let line = serde_json::json!({ "type": "finding", "data": finding });
            lines.push(serde_json::to_string(&line).unwrap());
        }
    }
    // files
    if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
        for file in files {
            let line = serde_json::json!({ "type": "file", "data": file });
            lines.push(serde_json::to_string(&line).unwrap());
        }
    }
    // summary
    let summary = serde_json::json!({ "type": "summary", "data": v.get("summary") });
    lines.push(serde_json::to_string(&summary).unwrap());
    lines.push(String::new()); // trailing newline
    lines.join("\n")
}

/// Streaming NDJSON report writer. Each method writes one JSON line.
pub struct NdjsonWriter<W: Write> {
    writer: std::io::BufWriter<W>,
    finding_count: usize,
    severity_counts: SeverityCounts,
}

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    confirmed_critical: usize,
    confirmed_high: usize,
    confirmed_medium: usize,
    confirmed_low: usize,
    heuristic_critical: usize,
    heuristic_high: usize,
    heuristic_medium: usize,
    heuristic_low: usize,
}

impl Default for SeverityCounts {
    fn default() -> Self {
        SeverityCounts {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            confirmed_critical: 0,
            confirmed_high: 0,
            confirmed_medium: 0,
            confirmed_low: 0,
            heuristic_critical: 0,
            heuristic_high: 0,
            heuristic_medium: 0,
            heuristic_low: 0,
        }
    }
}

impl<W: Write> NdjsonWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: std::io::BufWriter::new(writer),
            finding_count: 0,
            severity_counts: SeverityCounts::default(),
        }
    }

    pub fn write_header(
        &mut self,
        scanner: &ScannerInfo,
        target: &TargetInfo,
    ) -> std::io::Result<()> {
        let line = serde_json::json!({
            "type": "header",
            "scanner": scanner,
            "target": target,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    pub fn write_finding(&mut self, finding: &Finding) -> std::io::Result<()> {
        self.finding_count += 1;
        let sev = finding
            .severity
            .as_deref()
            .unwrap_or("")
            .to_uppercase();
        let confirmed = matches!(finding.confidence_tier, ConfidenceTier::ConfirmedInstalled);
        match sev.as_str() {
            "CRITICAL" => {
                self.severity_counts.critical += 1;
                if confirmed {
                    self.severity_counts.confirmed_critical += 1;
                } else {
                    self.severity_counts.heuristic_critical += 1;
                }
            }
            "HIGH" => {
                self.severity_counts.high += 1;
                if confirmed {
                    self.severity_counts.confirmed_high += 1;
                } else {
                    self.severity_counts.heuristic_high += 1;
                }
            }
            "MEDIUM" => {
                self.severity_counts.medium += 1;
                if confirmed {
                    self.severity_counts.confirmed_medium += 1;
                } else {
                    self.severity_counts.heuristic_medium += 1;
                }
            }
            "LOW" => {
                self.severity_counts.low += 1;
                if confirmed {
                    self.severity_counts.confirmed_low += 1;
                } else {
                    self.severity_counts.heuristic_low += 1;
                }
            }
            _ => {}
        }

        let line = serde_json::json!({
            "type": "finding",
            "data": finding,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    pub fn write_file(&mut self, file: &FileEntry) -> std::io::Result<()> {
        let line = serde_json::json!({
            "type": "file",
            "data": file,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    pub fn write_summary(&mut self, extra: &Summary) -> std::io::Result<()> {
        let sc = &self.severity_counts;
        let summary = Summary {
            total_findings: self.finding_count,
            critical: sc.critical,
            high: sc.high,
            medium: sc.medium,
            low: sc.low,
            confirmed_total_findings: sc.confirmed_critical
                + sc.confirmed_high
                + sc.confirmed_medium
                + sc.confirmed_low,
            heuristic_total_findings: sc.heuristic_critical
                + sc.heuristic_high
                + sc.heuristic_medium
                + sc.heuristic_low,
            confirmed_critical: sc.confirmed_critical,
            confirmed_high: sc.confirmed_high,
            confirmed_medium: sc.confirmed_medium,
            confirmed_low: sc.confirmed_low,
            heuristic_critical: sc.heuristic_critical,
            heuristic_high: sc.heuristic_high,
            heuristic_medium: sc.heuristic_medium,
            heuristic_low: sc.heuristic_low,
            warnings: extra.warnings.clone(),
        };
        let line = serde_json::json!({
            "type": "summary",
            "data": summary,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    pub fn write_metadata(
        &mut self,
        scan_status: &ScanStatus,
        inventory_status: &InventoryStatus,
        inventory_reason: &Option<String>,
    ) -> std::io::Result<()> {
        let line = serde_json::json!({
            "type": "metadata",
            "scan_status": scan_status,
            "inventory_status": inventory_status,
            "inventory_reason": inventory_reason,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    /// Write an entire Report as NDJSON (header, metadata, findings, files, summary).
    pub fn write_report(&mut self, report: &Report) -> std::io::Result<()> {
        self.write_header(&report.scanner, &report.target)?;
        self.write_metadata(
            &report.scan_status,
            &report.inventory_status,
            &report.inventory_reason,
        )?;
        for finding in &report.findings {
            self.write_finding(finding)?;
        }
        for file in &report.files {
            self.write_file(file)?;
        }
        self.write_summary(&report.summary)?;
        Ok(())
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

    #[test]
    fn ndjson_writer_produces_valid_lines() {
        let mut buf = Vec::new();
        {
            let mut writer = NdjsonWriter::new(&mut buf);
            let scanner = ScannerInfo {
                name: "scanrook",
                version: "1.12.2",
            };
            let target = TargetInfo {
                target_type: "container".into(),
                source: "test.tar".into(),
                id: None,
            };
            writer.write_header(&scanner, &target).unwrap();
            writer
                .write_finding(&mk_finding(
                    "CVE-2024-0001",
                    "HIGH",
                    ConfidenceTier::ConfirmedInstalled,
                ))
                .unwrap();
            writer.write_summary(&Summary::default()).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.trim().lines().collect();
        assert!(
            lines.len() >= 3,
            "expected at least 3 lines, got {}",
            lines.len()
        );
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|_| panic!("invalid JSON line: {}", line));
        }
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["type"], "header");
        let summary: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(summary["type"], "summary");
    }

    #[test]
    fn ndjson_writer_counts_severities() {
        let mut buf = Vec::new();
        {
            let mut writer = NdjsonWriter::new(&mut buf);
            let scanner = ScannerInfo {
                name: "scanrook",
                version: "1.12.2",
            };
            let target = TargetInfo {
                target_type: "container".into(),
                source: "test.tar".into(),
                id: None,
            };
            writer.write_header(&scanner, &target).unwrap();
            writer
                .write_finding(&mk_finding(
                    "CVE-2024-0001",
                    "CRITICAL",
                    ConfidenceTier::ConfirmedInstalled,
                ))
                .unwrap();
            writer
                .write_finding(&mk_finding(
                    "CVE-2024-0002",
                    "HIGH",
                    ConfidenceTier::HeuristicUnverified,
                ))
                .unwrap();
            writer
                .write_finding(&mk_finding(
                    "CVE-2024-0003",
                    "HIGH",
                    ConfidenceTier::ConfirmedInstalled,
                ))
                .unwrap();
            writer.write_summary(&Summary::default()).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.trim().lines().collect();
        let summary: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        let data = &summary["data"];
        assert_eq!(data["total_findings"], 3);
        assert_eq!(data["critical"], 1);
        assert_eq!(data["high"], 2);
        assert_eq!(data["confirmed_critical"], 1);
        assert_eq!(data["confirmed_high"], 1);
        assert_eq!(data["heuristic_high"], 1);
    }

    #[test]
    fn ndjson_write_report_roundtrip() {
        let report = Report {
            scanner: ScannerInfo {
                name: "scanrook",
                version: "1.12.2",
            },
            target: TargetInfo {
                target_type: "binary".into(),
                source: "test.bin".into(),
                id: None,
            },
            scan_status: ScanStatus::Complete,
            inventory_status: InventoryStatus::Complete,
            inventory_reason: None,
            sbom: None,
            findings: vec![mk_finding(
                "CVE-2024-0001",
                "MEDIUM",
                ConfidenceTier::ConfirmedInstalled,
            )],
            files: vec![],
            summary: compute_summary(&[mk_finding(
                "CVE-2024-0001",
                "MEDIUM",
                ConfidenceTier::ConfirmedInstalled,
            )]),
            iso_profile: None,
        };
        let mut buf = Vec::new();
        NdjsonWriter::new(&mut buf).write_report(&report).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.trim().lines().collect();
        // header, metadata, 1 finding, summary = 4 lines
        assert_eq!(lines.len(), 4);
        let types: Vec<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(types, vec!["header", "metadata", "finding", "summary"]);
    }
}
