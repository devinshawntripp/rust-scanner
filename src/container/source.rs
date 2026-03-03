//! Source tarball scan orchestration.

use crate::container::extract::extract_tar;
use crate::report::{
    compute_summary, InventoryStatus, Report, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::{parse_name_version_from_filename, write_output_if_needed};
use crate::vuln::{nvd_cpe_findings, nvd_keyword_findings, nvd_keyword_findings_name};
use crate::OutputFormat;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tempfile::tempdir;
use walkdir::WalkDir;

use super::scan::collect_file_tree_if_enabled;

/// Build a source tarball report (no printing)
pub fn build_source_report(tar_path: &str, nvd_api_key: Option<String>) -> Option<Report> {
    let tmp = tempdir().ok()?;
    extract_tar(tar_path, tmp.path()).ok()?;

    let mut candidates: Vec<(String, String)> = Vec::new();
    if let Some((n, v)) = parse_name_version_from_filename(tar_path) {
        candidates.push((n, v));
    }
    if let Some((n, v)) = detect_busybox_version_in_tree(tmp.path()) {
        candidates.push((n, v));
    }
    if let Some((n, v)) = detect_busybox_version_from_makefile(tmp.path()) {
        candidates.push((n, v));
    }

    let mut findings = Vec::new();
    for (name, ver) in candidates {
        let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        if extra.is_empty() {
            extra = crate::vuln::nvd_findings_by_product_version(
                &name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path),
            );
        }
        if extra.is_empty() {
            extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        }
        if extra.is_empty() {
            extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path));
        }
        findings.extend(extra);
    }

    let scanner = ScannerInfo {
        name: "scanrook",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "source".into(),
        source: tar_path.to_string(),
        id: None,
    };
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    crate::vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::vuln::epss_enrich_findings(&mut findings, &mut pg, cache_dir.as_deref());
    crate::vuln::kev_enrich_findings(&mut findings, &mut pg, cache_dir.as_deref());

    let mut report = Report {
        scanner,
        target,
        scan_status: ScanStatus::Complete,
        inventory_status: InventoryStatus::Complete,
        inventory_reason: None,
        sbom: None,
        findings,
        files: collect_file_tree_if_enabled(tmp.path()),
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);
    Some(report)
}

pub fn scan_source_tarball(
    tar_path: &str,
    format: OutputFormat,
    nvd_api_key: Option<String>,
    out: Option<String>,
) {
    let tmp = match tempdir() {
        Ok(td) => td,
        Err(e) => {
            eprintln!("Failed to create tempdir: {}", e);
            return;
        }
    };
    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        eprintln!("Failed to extract {}: {}", tar_path, e);
        return;
    }

    let mut candidates: Vec<(String, String)> = Vec::new();
    if let Some((n, v)) = parse_name_version_from_filename(tar_path) {
        candidates.push((n, v));
    }
    if let Some((n, v)) = detect_busybox_version_in_tree(tmp.path()) {
        candidates.push((n, v));
    }
    if let Some((n, v)) = detect_busybox_version_from_makefile(tmp.path()) {
        candidates.push((n, v));
    }

    let mut findings = Vec::new();
    for (name, ver) in candidates {
        let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        if extra.is_empty() {
            extra = crate::vuln::nvd_findings_by_product_version(
                &name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path),
            );
        }
        if extra.is_empty() {
            extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        }
        if extra.is_empty() {
            extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path));
        }
        findings.extend(extra);
    }

    let mut pg2 = if crate::vuln::cluster_mode() {
        crate::vuln::pg_connect()
    } else {
        None
    };

    match format {
        OutputFormat::Text => {
            println!("Source: {}", tar_path);
            println!("Findings: {}", findings.len());
        }
        OutputFormat::Json => {
            let cache_dir = crate::vuln::resolve_enrich_cache_dir();
            crate::vuln::epss_enrich_findings(&mut findings, &mut pg2, cache_dir.as_deref());
            crate::vuln::kev_enrich_findings(&mut findings, &mut pg2, cache_dir.as_deref());

            let scanner = ScannerInfo {
                name: "scanrook",
                version: env!("CARGO_PKG_VERSION"),
            };
            let target = TargetInfo {
                target_type: "source".into(),
                source: tar_path.to_string(),
                id: None,
            };
            let mut report = Report {
                scanner,
                target,
                scan_status: ScanStatus::Complete,
                inventory_status: InventoryStatus::Complete,
                inventory_reason: None,
                sbom: None,
                findings,
                files: collect_file_tree_if_enabled(tmp.path()),
                summary: Default::default(),
            };
            report.summary = compute_summary(&report.findings);
            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("{}", json);
            write_output_if_needed(&out, &json);
        }
    }
}

pub(super) fn detect_busybox_version_in_tree(root: &Path) -> Option<(String, String)> {
    let re = regex::Regex::new(r"BusyBox v(\d+\.\d+(?:\.\d+)?)").ok()?;
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(mut f) = File::open(entry.path()) {
                let mut buf = [0u8; 65536];
                if let Ok(n) = f.read(&mut buf) {
                    let s = String::from_utf8_lossy(&buf[..n]);
                    if let Some(caps) = re.captures(&s) {
                        if let Some(ver) = caps.get(1) {
                            return Some(("busybox".into(), ver.as_str().to_string()));
                        }
                    }
                }
            }
        }
    }
    None
}

fn detect_busybox_version_from_makefile(root: &Path) -> Option<(String, String)> {
    let makefile = root.join("Makefile");
    if !makefile.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&makefile).ok()?;
    let re_ver = regex::Regex::new(r"(?m)^\s*VERSION\s*=\s*(\d+)\s*$").ok()?;
    let re_patch = regex::Regex::new(r"(?m)^\s*PATCHLEVEL\s*=\s*(\d+)\s*$").ok()?;
    let re_sub = regex::Regex::new(r"(?m)^\s*SUBLEVEL\s*=\s*(\d+)\s*$").ok()?;
    let v = re_ver.captures(&content)?.get(1)?.as_str().to_string();
    let p = re_patch.captures(&content)?.get(1)?.as_str().to_string();
    let s = re_sub.captures(&content)?.get(1)?.as_str().to_string();
    Some(("busybox".into(), format!("{}.{}.{}", v, p, s)))
}
