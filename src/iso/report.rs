//! ISO vulnerability report building: the main build_iso_report function and scan status logic.

use crate::redhat::filter_findings_with_redhat_oval;
use crate::report::{
    compute_summary, retag_findings, ConfidenceTier, EvidenceSource, FileEntry, InventoryStatus,
    Report, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::{progress, progress_timing};
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use std::collections::HashSet;

use super::extract::{list_iso_entries, normalize_path_like};
use super::inventory::{
    dedupe_packages, packages_from_rpm_entries, packages_from_runtime_inventory,
};
use super::repodata::packages_from_repodata;

pub(super) const ISO_HEURISTIC_NOTE: &str =
    "Installed package inventory could not be fully determined for this ISO. Finding may be false positive.";

fn light_allow_heuristic_fallback() -> bool {
    std::env::var("SCANNER_LIGHT_ALLOW_HEURISTIC_FALLBACK")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

fn deep_require_installed_inventory() -> bool {
    std::env::var("SCANNER_DEEP_REQUIRE_INSTALLED_INVENTORY")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

fn heuristic_fallback_allowed(mode: &ScanMode) -> bool {
    match mode {
        ScanMode::Light => light_allow_heuristic_fallback(),
        ScanMode::Deep => !deep_require_installed_inventory(),
    }
}

pub fn build_iso_report(
    path: &str,
    mode: ScanMode,
    _yara_rules: Option<String>,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Report> {
    crate::progress::init_pipeline("iso");
    crate::progress::enter_stage("detect");
    progress("iso.detect.start", path);
    let detect_started = std::time::Instant::now();
    let entries = match list_iso_entries(path) {
        Ok(v) => v,
        Err(e) => {
            progress("iso.detect.error", &format!("{}", e));
            return None;
        }
    };
    progress_timing("iso.detect", detect_started);
    progress("iso.detect.done", &format!("entries={}", entries.len()));

    crate::progress::enter_stage("inventory");
    let runtime_started = std::time::Instant::now();
    let mut runtime_error_reason: Option<String> = None;
    let runtime_packages = match packages_from_runtime_inventory(path, &entries) {
        Ok(pkgs) => pkgs,
        Err(e) => {
            progress("iso.inventory.runtime.error", &format!("{}", e));
            runtime_error_reason = Some("runtime_inventory_extraction_failed".into());
            Vec::new()
        }
    };
    progress_timing("iso.inventory.runtime", runtime_started);
    let inventory_complete = !runtime_packages.is_empty();
    if inventory_complete {
        progress(
            "iso.inventory.runtime.done",
            &format!("packages={}", runtime_packages.len()),
        );
    } else {
        progress(
            "iso.inventory.runtime.missing",
            "no directly extractable installed package database found",
        );
    }

    let allow_heuristic_fallback = heuristic_fallback_allowed(&mode);
    let mut fallback_source = EvidenceSource::RepoMetadata;
    let mut used_repodata = false;
    let mut packages = if inventory_complete {
        runtime_packages
    } else if !allow_heuristic_fallback {
        progress(
            "iso.packages.fallback.skip",
            "heuristic fallback disabled by strict inventory policy",
        );
        Vec::new()
    } else {
        let fallback_started = std::time::Instant::now();
        let mut p = packages_from_rpm_entries(&entries);
        progress("iso.packages.filenames", &format!("packages={}", p.len()));
        match packages_from_repodata(path, &entries) {
            Ok(mut from_repodata) => {
                if !from_repodata.is_empty() {
                    used_repodata = true;
                    progress(
                        "iso.repodata.done",
                        &format!("packages={}", from_repodata.len()),
                    );
                    p.append(&mut from_repodata);
                } else {
                    progress("iso.repodata.skip", "no-primary-packages");
                }
            }
            Err(e) => progress("iso.repodata.error", &format!("{}", e)),
        }
        progress_timing("iso.packages.fallback", fallback_started);
        p
    };
    if !used_repodata {
        fallback_source = EvidenceSource::FilenameHeuristic;
    }
    packages = dedupe_packages(packages);
    progress(
        "iso.packages.detect.done",
        &format!("packages={}", packages.len()),
    );

    let mut findings_norm = Vec::new();
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }

    if !packages.is_empty() {
        crate::progress::enter_stage("osv_query");
        progress(
            "iso.osv.query.start",
            &format!("packages={}", packages.len()),
        );
        let osv_query_started = std::time::Instant::now();
        let osv_results = osv_batch_query(&packages);
        progress_timing("iso.osv.query", osv_query_started);
        progress("iso.osv.query.done", "ok");
        findings_norm = map_osv_results_to_findings(&packages, &osv_results);
        crate::progress::enter_stage("osv_enrich");
        progress(
            "iso.enrich.osv.start",
            &format!("findings_pre_enrich={}", findings_norm.len()),
        );
        let osv_enrich_started = std::time::Instant::now();
        osv_enrich_findings(&mut findings_norm, &mut pg);
        progress_timing("iso.enrich.osv", osv_enrich_started);
        progress(
            "iso.enrich.osv.done",
            &format!("findings={}", findings_norm.len()),
        );

        let nvd_enrich_enabled = std::env::var("SCANNER_NVD_ENRICH")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true);
        if nvd_enrich_enabled {
            crate::progress::enter_stage("nvd_enrich");
            let unique_cves = findings_norm
                .iter()
                .filter(|f| f.id.starts_with("CVE-"))
                .map(|f| f.id.clone())
                .collect::<HashSet<_>>();
            progress(
                "iso.enrich.nvd.start",
                &format!("cves={}", unique_cves.len()),
            );
            let nvd_enrich_started = std::time::Instant::now();
            enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
            progress_timing("iso.enrich.nvd", nvd_enrich_started);
            progress("iso.enrich.nvd.done", "ok");
        } else {
            progress("iso.enrich.nvd.skip", "disabled by SCANNER_NVD_ENRICH");
        }

        if !inventory_complete && allow_heuristic_fallback {
            retag_findings(
                &mut findings_norm,
                ConfidenceTier::HeuristicUnverified,
                fallback_source,
                Some(ISO_HEURISTIC_NOTE),
            );
        }

        let oval_redhat = oval_redhat
            .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                let has_rpm = packages
                    .iter()
                    .any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem));
                if has_rpm {
                    let cache = crate::vuln::resolve_enrich_cache_dir();
                    crate::redhat::fetch_redhat_oval(&packages, cache.as_deref())
                } else {
                    None
                }
            });
        crate::progress::enter_stage("redhat");
        if let Some(oval_path) = oval_redhat.as_deref() {
            progress("iso.enrich.redhat.start", oval_path);
            let redhat_started = std::time::Instant::now();
            match filter_findings_with_redhat_oval(&mut findings_norm, &packages, oval_path) {
                Ok(stats) => {
                    progress_timing("iso.enrich.redhat", redhat_started);
                    progress(
                        "iso.enrich.redhat.done",
                        &format!(
                            "defs={}/{} cves={}/{} findings={}->{} filtered={}",
                            stats.definitions_evaluable,
                            stats.definitions_total,
                            stats.vulnerable_cves,
                            stats.covered_cves,
                            stats.findings_before,
                            stats.findings_after,
                            stats.findings_filtered
                        ),
                    );
                }
                Err(e) => {
                    progress_timing("iso.enrich.redhat", redhat_started);
                    progress("iso.enrich.redhat.error", &format!("{}", e));
                }
            }
        }
    }

    let (scan_status, inventory_status, inventory_reason) = if inventory_complete {
        (ScanStatus::Complete, InventoryStatus::Complete, None)
    } else if !allow_heuristic_fallback {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Missing,
            Some("deep_mode_requires_installed_inventory".into()),
        )
    } else if !packages.is_empty() {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Partial,
            Some(
                runtime_error_reason
                    .clone()
                    .unwrap_or_else(|| "runtime_inventory_unavailable_used_repo_metadata".into()),
            ),
        )
    } else {
        (
            ScanStatus::Unsupported,
            InventoryStatus::Missing,
            Some(
                runtime_error_reason
                    .unwrap_or_else(|| "installed_package_inventory_missing".into()),
            ),
        )
    };

    crate::progress::enter_stage("report");
    let scanner = ScannerInfo {
        name: "scanrook",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "iso".into(),
        source: path.to_string(),
        id: None,
    };
    let files = iso_entries_to_file_rows(&entries, 20_000);
    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::progress::enter_stage("epss");
    crate::vuln::epss_enrich_findings(&mut findings_norm, cache_dir.as_deref());
    crate::progress::enter_stage("kev");
    crate::vuln::kev_enrich_findings(&mut findings_norm, cache_dir.as_deref());

    let mut report = Report {
        scanner,
        target,
        scan_status,
        inventory_status,
        inventory_reason,
        sbom: None,
        findings: findings_norm,
        files,
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);
    crate::progress::finish_pipeline();
    Some(report)
}

fn iso_entries_to_file_rows(entries: &[String], limit: usize) -> Vec<FileEntry> {
    let cap = if limit == 0 { 20_000 } else { limit };
    let mut out: Vec<FileEntry> = Vec::new();
    for entry in entries.iter().take(cap) {
        let norm = normalize_path_like(entry);
        if norm.is_empty() {
            continue;
        }
        let is_dir = norm.ends_with('/');
        let clean = norm.trim_end_matches('/').to_string();
        if clean.is_empty() {
            continue;
        }
        let parent_path = std::path::Path::new(&clean)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .filter(|p| !p.is_empty());
        out.push(FileEntry {
            path: clean,
            entry_type: if is_dir { "dir" } else { "file" }.to_string(),
            size_bytes: None,
            mode: None,
            mtime: None,
            sha256: None,
            parent_path,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}
