//! DMG (macOS disk image) extraction and scanning.

use crate::report::{
    compute_summary, InventoryStatus, Report, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::{progress, progress_timing};
use crate::vuln::{
    enrich_findings_with_nvd, epss_enrich_findings, kev_enrich_findings,
    map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

use super::detect::detect_app_packages;

/// Extract a DMG file to a temporary directory.
/// On macOS, uses hdiutil; falls back to 7z if available.
pub fn extract_dmg(path: &str, dest: &Path) -> anyhow::Result<()> {
    use std::process::Command;

    // Try hdiutil first (macOS only)
    if cfg!(target_os = "macos") {
        let mount_point = dest.join("dmg_mount");
        fs::create_dir_all(&mount_point)?;
        let status = Command::new("hdiutil")
            .args([
                "attach",
                "-mountpoint",
                &mount_point.to_string_lossy(),
                "-nobrowse",
                "-readonly",
                "-noverify",
                path,
            ])
            .status();

        if let Ok(s) = status {
            if s.success() {
                // Copy contents from mount to dest (so we can unmount)
                let copy_dest = dest.join("contents");
                fs::create_dir_all(&copy_dest)?;
                let cp_status = Command::new("cp")
                    .args([
                        "-R",
                        &format!("{}/.", mount_point.to_string_lossy()),
                        &copy_dest.to_string_lossy(),
                    ])
                    .status();
                // Always try to unmount
                let _ = Command::new("hdiutil")
                    .args(["detach", &mount_point.to_string_lossy(), "-quiet"])
                    .status();
                if let Ok(s) = cp_status {
                    if s.success() {
                        return Ok(());
                    }
                }
            }
        }
    }

    // Fallback: try 7z
    let status = Command::new("7z")
        .args(["x", path, &format!("-o{}", dest.to_string_lossy()), "-y"])
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => anyhow::bail!(
            "7z extraction failed with exit code {}. Install hdiutil (macOS) or 7z for DMG support.",
            s.code().unwrap_or(-1)
        ),
        Err(_) => anyhow::bail!(
            "DMG extraction requires hdiutil (macOS) or 7z. Neither was found."
        ),
    }
}

/// Build a report for a DMG disk image.
pub fn build_dmg_report(path: &str, mode: ScanMode, nvd_api_key: Option<String>) -> Option<Report> {
    let started = std::time::Instant::now();
    progress("dmg.extract.start", path);

    let tmp = tempdir().ok()?;
    if let Err(e) = extract_dmg(path, tmp.path()) {
        progress("dmg.extract.error", &format!("{}", e));
        return None;
    }
    progress_timing("dmg.extract", started);
    progress("dmg.extract.done", path);

    // Walk the extracted DMG contents for packages and binaries
    let contents = tmp.path().join("contents");
    let scan_root = if contents.exists() {
        &contents
    } else {
        tmp.path()
    };

    let pkg_started = std::time::Instant::now();
    let packages = detect_app_packages(scan_root);
    let binary_findings = scan_embedded_binaries_dmg(scan_root, &mode, &nvd_api_key);
    progress_timing("dmg.packages.detect", pkg_started);
    progress(
        "dmg.packages.detect.done",
        &format!("packages={}", packages.len()),
    );

    // Enrichment pipeline
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }

    // Create per-scan circuit breakers (one per API source, not static/shared)
    let osv_breaker = crate::vuln::CircuitBreaker::new("osv", 5);
    let nvd_breaker = crate::vuln::CircuitBreaker::new("nvd", 5);
    let epss_breaker = crate::vuln::CircuitBreaker::new("epss", 5);
    let kev_breaker = crate::vuln::CircuitBreaker::new("kev", 5);

    let osv_started = std::time::Instant::now();
    let osv_results = osv_batch_query(&packages, &mut pg, &osv_breaker);
    progress_timing("dmg.osv.query", osv_started);

    let mut findings = map_osv_results_to_findings(&packages, &osv_results);

    osv_enrich_findings(&mut findings, &mut pg, &osv_breaker);
    enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg, &nvd_breaker);

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    epss_enrich_findings(&mut findings, &mut pg, cache_dir.as_deref(), &epss_breaker);
    kev_enrich_findings(&mut findings, &mut pg, cache_dir.as_deref(), &kev_breaker);

    findings.extend(binary_findings);

    let mut summary = compute_summary(&findings);

    // Collect warnings from tripped circuit breakers into summary.warnings
    let all_breakers: [&crate::vuln::CircuitBreaker; 4] =
        [&osv_breaker, &nvd_breaker, &epss_breaker, &kev_breaker];
    for b in &all_breakers {
        if b.is_open() {
            summary.warnings.push(format!(
                "{} unavailable — results may be incomplete (5 consecutive failures)",
                b.source_name()
            ));
        }
    }
    progress_timing("dmg.scan", started);

    Some(Report {
        scanner: ScannerInfo {
            name: "scanrook",
            version: env!("CARGO_PKG_VERSION"),
        },
        target: TargetInfo {
            target_type: "dmg".to_string(),
            source: path.to_string(),
            id: None,
        },
        scan_status: ScanStatus::Complete,
        inventory_status: if packages.is_empty() && findings.is_empty() {
            InventoryStatus::Missing
        } else {
            InventoryStatus::Complete
        },
        inventory_reason: None,
        sbom: None,
        findings,
        files: Vec::new(),
        summary,
    })
}

// Re-use the same embedded binary scanning logic from scan.rs
// but scoped to the DMG context. We call build_binary_report directly.
fn scan_embedded_binaries_dmg(
    root: &Path,
    _mode: &ScanMode,
    nvd_api_key: &Option<String>,
) -> Vec<crate::report::Finding> {
    use crate::report::{ConfidenceTier, EvidenceSource};
    use walkdir::WalkDir;

    let mut findings = Vec::new();
    let binary_exts = ["so", "dll", "dylib"];

    for entry in WalkDir::new(root)
        .max_depth(8)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if binary_exts.contains(&ext) {
            if let Some(report) = crate::binary::build_binary_report(
                &path.to_string_lossy(),
                ScanMode::Light,
                None,
                nvd_api_key.clone(),
            ) {
                for mut f in report.findings {
                    f.confidence_tier = ConfidenceTier::HeuristicUnverified;
                    f.evidence_source = EvidenceSource::BinaryHeuristic;
                    if f.accuracy_note.is_none() {
                        f.accuracy_note = Some("embedded binary in archive".to_string());
                    }
                    findings.push(f);
                }
            }
        }
    }

    findings
}
