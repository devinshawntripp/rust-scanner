use crate::redhat::filter_findings_with_redhat_oval;
use crate::report::{
    compute_summary, retag_findings, ConfidenceTier, EvidenceSource, InventoryStatus, Report,
    SbomInfo, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::parse_name_version_from_filename;
use crate::utils::{progress, progress_timing, run_syft_generate_sbom, write_output_if_needed};
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, nvd_cpe_findings, nvd_keyword_findings,
    nvd_keyword_findings_name, osv_batch_query,
};
use crate::{OutputFormat, ScanMode};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tar::Archive;
use tempfile::tempdir;
use walkdir::WalkDir;
#[cfg(feature = "yara")]
use yara::Compiler;

/// Extracts a tar archive (optionally gzipped) to ./extracted
pub fn extract_tar(tar_path: &str, dest: &Path) -> anyhow::Result<()> {
    let file = File::open(tar_path)?;
    let mut archive: Archive<Box<dyn std::io::Read>> =
        if tar_path.ends_with(".gz") || tar_path.ends_with(".tgz") {
            Archive::new(Box::new(GzDecoder::new(file)))
        } else if tar_path.ends_with(".bz2")
            || tar_path.ends_with(".tbz")
            || tar_path.ends_with(".tbz2")
        {
            Archive::new(Box::new(BzDecoder::new(file)))
        } else {
            Archive::new(Box::new(file))
        };
    archive.unpack(dest)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PackageCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

const IMAGE_HEURISTIC_NOTE: &str =
    "Installed package inventory could not be fully determined for this image. Finding may be false positive.";

fn report_state_for_inventory(
    packages_detected: usize,
    mode: &ScanMode,
    heuristic_used: bool,
) -> (ScanStatus, InventoryStatus, Option<String>) {
    if packages_detected > 0 {
        (ScanStatus::Complete, InventoryStatus::Complete, None)
    } else if heuristic_used {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Partial,
            Some("runtime_inventory_unavailable_used_heuristics".into()),
        )
    } else if matches!(mode, ScanMode::Deep) && deep_require_installed_inventory() {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Missing,
            Some("deep_mode_requires_installed_inventory".into()),
        )
    } else {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Missing,
            Some("installed_package_inventory_missing".into()),
        )
    }
}

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

fn include_file_tree() -> bool {
    std::env::var("SCANNER_INCLUDE_FILE_TREE")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn file_tree_limit() -> usize {
    std::env::var("SCANNER_TREE_MAX_ENTRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

fn collect_file_tree_if_enabled(root: &Path) -> Vec<crate::report::FileEntry> {
    if !include_file_tree() {
        progress("files.collect.skip", "disabled by SCANNER_INCLUDE_FILE_TREE");
        return Vec::new();
    }
    let started = std::time::Instant::now();
    let limit = file_tree_limit();
    progress("files.collect.start", &format!("limit={}", limit));
    let files = crate::utils::collect_file_tree(root, limit);
    progress_timing("files.collect", started);
    progress("files.collect.done", &format!("entries={}", files.len()));
    files
}

pub fn scan_container(
    tar_path: &str,
    mode: ScanMode,
    format: OutputFormat,
    _cache_dir: Option<String>,
    yara_rules: Option<String>,
    out: Option<String>,
    sbom: bool,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) {
    let tmp = match tempdir() {
        Ok(td) => td,
        Err(e) => {
            eprintln!("Failed to create tempdir: {}", e);
            return;
        }
    };
    #[cfg(not(feature = "yara"))]
    let _ = &yara_rules;

    let extract_started = std::time::Instant::now();
    progress("container.extract.start", tar_path);

    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        eprintln!("Failed to extract {}: {}", tar_path, e);
        progress("container.extract.error", &format!("{}", e));
        return;
    }
    progress_timing("container.extract", extract_started);
    progress("container.extract.done", tar_path);

    let needs_full_rootfs = include_file_tree()
        || sbom
        || matches!(mode, ScanMode::Deep) && yara_rules.as_deref().is_some();

    // Try to merge layers from supported container layouts.
    let manifest_path = tmp.path().join("manifest.json");
    let oci_index_path = tmp.path().join("index.json");
    let mut rootfs = tmp.path().to_path_buf();
    let mut packages = Vec::new();
    if !needs_full_rootfs {
        let fast_started = std::time::Instant::now();
        progress("container.packages.detect.fast.start", "");
        match try_detect_os_packages_from_layout(tmp.path()) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress(
                    "container.packages.detect.fast.done",
                    &format!("packages={}", pkgs.len()),
                );
                progress("container.layers.merge.skip", "reason=fast_inventory");
                packages = pkgs;
            }
            Ok(_) => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress("container.packages.detect.fast.empty", "");
            }
            Err(e) => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress("container.packages.detect.fast.error", &format!("{}", e));
            }
        }
    }

    if packages.is_empty() {
        rootfs = if manifest_path.exists() {
            progress("container.layers.merge.start", "layout=docker-save");
            match merge_layers_docker_save(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    eprintln!("Failed to merge docker-save layers: {}", e);
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else if oci_index_path.exists() {
            progress("container.layers.merge.start", "layout=oci");
            match merge_layers_oci_layout(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    eprintln!("Failed to merge OCI layers: {}", e);
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else {
            progress(
                "container.layers.merge.skip",
                &format!("layout=unknown; rootfs={}", tmp.path().display()),
            );
            tmp.path().to_path_buf()
        };

        progress(
            "container.packages.detect.start",
            rootfs.to_string_lossy().as_ref(),
        );
        let packages_started = std::time::Instant::now();
        packages = detect_os_packages(&rootfs);
        progress_timing("container.packages.detect", packages_started);
        progress(
            "container.packages.detect.done",
            &format!("packages={}", packages.len()),
        );
    }

    // Light mode: only OSV lookups for packages; Deep mode: run YARA too
    progress(
        "container.osv.query.start",
        &format!("packages={}", packages.len()),
    );
    let osv_query_started = std::time::Instant::now();
    let osv_results = osv_batch_query(&packages);
    progress_timing("container.osv.query", osv_query_started);
    progress("container.osv.query.done", "ok");
    let mut findings_norm = map_osv_results_to_findings(&packages, &osv_results);
    let mut heuristic_used = false;

    // Enrich with OSV details first, then NVD for CVSS/refs
    progress(
        "container.enrich.osv.start",
        &format!("findings_pre_enrich={}", findings_norm.len()),
    );
    let osv_enrich_started = std::time::Instant::now();
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    crate::vuln::osv_enrich_findings(&mut findings_norm, &mut pg);
    progress_timing("container.enrich.osv", osv_enrich_started);
    progress(
        "container.enrich.osv.done",
        &format!("findings={}", findings_norm.len()),
    );
    let nvd_enrich_enabled = std::env::var("SCANNER_NVD_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if nvd_enrich_enabled {
        let unique: HashSet<String> = findings_norm
            .iter()
            .filter(|f| f.id.starts_with("CVE-"))
            .map(|f| f.id.clone())
            .collect();
        progress(
            "container.enrich.nvd.start",
            &format!("cves={}", unique.len()),
        );
        let nvd_enrich_started = std::time::Instant::now();
        crate::vuln::enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
        progress_timing("container.enrich.nvd", nvd_enrich_started);
        progress("container.enrich.nvd.done", "ok");
    } else {
        progress(
            "container.enrich.nvd.skip",
            "disabled by SCANNER_NVD_ENRICH",
        );
    }

    // Fallback: only in light mode (or when deep strict is explicitly disabled).
    let allow_heuristic_fallback = heuristic_fallback_allowed(&mode);
    if packages.is_empty()
        && (manifest_path.exists() || oci_index_path.exists())
        && allow_heuristic_fallback
    {
        if let Some((name, ver)) = parse_name_version_from_filename(tar_path) {
            // Try structured (vendor=product=name) CPE first, then product/version filter, then keyword
            let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
            if extra.is_empty() {
                extra = crate::vuln::nvd_findings_by_product_version(
                    &name,
                    &name,
                    &ver,
                    nvd_api_key.as_deref(),
                    Some(tar_path),
                );
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path));
            }
            let start = findings_norm.len();
            findings_norm.append(&mut extra);
            if findings_norm.len() > start {
                retag_findings(
                    &mut findings_norm[start..],
                    ConfidenceTier::HeuristicUnverified,
                    EvidenceSource::FilenameHeuristic,
                    Some(IMAGE_HEURISTIC_NOTE),
                );
                heuristic_used = true;
            }
        }
        if findings_norm.is_empty() {
            if let Some((name, ver)) = detect_busybox_version_in_tree(&rootfs) {
                progress("container.filename.heuristic", &format!("{} {}", name, ver));
                let mut extra =
                    nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
                if extra.is_empty() {
                    extra = crate::vuln::nvd_findings_by_product_version(
                        &name,
                        &name,
                        &ver,
                        nvd_api_key.as_deref(),
                        Some(tar_path),
                    );
                }
                if extra.is_empty() {
                    extra =
                        nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
                }
                if extra.is_empty() {
                    extra =
                        nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path));
                }
                let start = findings_norm.len();
                findings_norm.append(&mut extra);
                if findings_norm.len() > start {
                    retag_findings(
                        &mut findings_norm[start..],
                        ConfidenceTier::HeuristicUnverified,
                        EvidenceSource::BinaryHeuristic,
                        Some(IMAGE_HEURISTIC_NOTE),
                    );
                    heuristic_used = true;
                }
            }
        }
    } else if packages.is_empty() && !allow_heuristic_fallback {
        progress(
            "container.heuristic.skip",
            "heuristic fallback disabled by deep inventory policy",
        );
    }

    let oval_redhat = oval_redhat
        .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
        .filter(|v| !v.trim().is_empty());
    if let Some(oval_path) = oval_redhat.as_deref() {
        progress("container.enrich.redhat.start", oval_path);
        let redhat_started = std::time::Instant::now();
        match filter_findings_with_redhat_oval(&mut findings_norm, &packages, oval_path) {
            Ok(stats) => {
                progress_timing("container.enrich.redhat", redhat_started);
                progress(
                    "container.enrich.redhat.done",
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
                eprintln!("Failed Red Hat OVAL evaluation: {}", e);
                progress_timing("container.enrich.redhat", redhat_started);
                progress("container.enrich.redhat.error", &format!("{}", e));
            }
        }
    }

    #[cfg(feature = "yara")]
    let mut yara_hits: Vec<String> = Vec::new();
    #[cfg(not(feature = "yara"))]
    let yara_hits: Vec<String> = Vec::new();
    if let ScanMode::Deep = mode {
        if packages.is_empty() && deep_require_installed_inventory() {
            progress(
                "container.yara.skip",
                "deep mode requires installed inventory; skipping heuristic binary scan",
            );
        } else {
            #[cfg(feature = "yara")]
            if let Some(rule_path) = yara_rules.as_deref() {
                if let Ok(mut compiler) = Compiler::new() {
                    if let Err(e) = compiler.add_rules_file(rule_path) {
                        eprintln!("Failed to add YARA rules: {}", e);
                    } else if let Ok(rules) = compiler.compile_rules() {
                        for entry in WalkDir::new(&rootfs).into_iter().filter_map(|e| e.ok()) {
                            if entry.file_type().is_file() {
                                if let Ok(scan) = rules.scan_file(entry.path(), 5) {
                                    for m in scan.matches {
                                        yara_hits.push(format!(
                                            "{}: {}",
                                            entry.path().display(),
                                            m.identifier
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    match format {
        OutputFormat::Text => {
            println!("Merged RootFS: {}", rootfs.display());
            println!("Detected packages: {}", packages.len());
            for p in &packages {
                println!("- {}:{}@{}", p.ecosystem, p.name, p.version);
            }
            println!("Findings: {}", findings_norm.len());
            if !yara_hits.is_empty() {
                println!("YARA hits: {}", yara_hits.len());
            }
        }
        OutputFormat::Json => {
            let scanner = ScannerInfo {
                name: "scanrook",
                version: env!("CARGO_PKG_VERSION"),
            };
            let target = TargetInfo {
                target_type: "container".into(),
                source: tar_path.to_string(),
                id: None,
            };
            let mut sbom_info: Option<SbomInfo> = None;
            if sbom {
                progress("container.sbom.start", rootfs.to_string_lossy().as_ref());
                let sbom_started = std::time::Instant::now();
                let sbom_path = tmp.path().join("sbom.cdx.json");
                if let Err(e) = run_syft_generate_sbom(
                    rootfs.to_str().unwrap_or("."),
                    sbom_path.to_str().unwrap_or("sbom.cdx.json"),
                ) {
                    eprintln!("Syft SBOM generation failed: {}", e);
                    progress("container.sbom.error", &format!("{}", e));
                } else {
                    sbom_info = Some(SbomInfo {
                        format: "cyclonedx".into(),
                        path: sbom_path.display().to_string(),
                    });
                    progress("container.sbom.done", "ok");
                }
                progress_timing("container.sbom", sbom_started);
            }
            let (scan_status, inventory_status, inventory_reason) =
                report_state_for_inventory(packages.len(), &mode, heuristic_used);
            let mut report = Report {
                scanner,
                target,
                scan_status,
                inventory_status,
                inventory_reason,
                sbom: sbom_info,
                findings: findings_norm,
                files: collect_file_tree_if_enabled(&rootfs),
                summary: Default::default(),
            };
            report.summary = compute_summary(&report.findings);
            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("{}", json);
            write_output_if_needed(&out, &json);
        }
    }
}

/// Build a container report (no printing)
pub fn build_container_report(
    tar_path: &str,
    mode: ScanMode,
    sbom: bool,
    nvd_api_key: Option<String>,
    yara_rules: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Report> {
    let tmp = tempdir().ok()?;
    #[cfg(not(feature = "yara"))]
    let _ = &yara_rules;

    let extract_started = std::time::Instant::now();
    progress("container.extract.start", tar_path);
    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        progress("container.extract.error", &format!("{}", e));
        return None;
    }
    progress_timing("container.extract", extract_started);
    progress("container.extract.done", tar_path);
    let manifest_path = tmp.path().join("manifest.json");
    let oci_index_path = tmp.path().join("index.json");
    let has_manifest = manifest_path.exists();
    let has_oci_index = oci_index_path.exists();
    let needs_full_rootfs = include_file_tree()
        || sbom
        || matches!(mode, ScanMode::Deep) && yara_rules.as_deref().is_some();

    let mut rootfs = tmp.path().to_path_buf();
    let mut packages = Vec::new();
    if !needs_full_rootfs {
        let fast_started = std::time::Instant::now();
        progress("container.packages.detect.fast.start", "");
        match try_detect_os_packages_from_layout(tmp.path()) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress(
                    "container.packages.detect.fast.done",
                    &format!("packages={}", pkgs.len()),
                );
                progress("container.layers.merge.skip", "reason=fast_inventory");
                packages = pkgs;
            }
            Ok(_) => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress("container.packages.detect.fast.empty", "");
            }
            Err(e) => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress("container.packages.detect.fast.error", &format!("{}", e));
            }
        }
    }

    if packages.is_empty() {
        rootfs = if has_manifest {
            progress("container.layers.merge.start", "layout=docker-save");
            match merge_layers_docker_save(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else if has_oci_index {
            progress("container.layers.merge.start", "layout=oci");
            match merge_layers_oci_layout(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else {
            progress(
                "container.layers.merge.skip",
                &format!("layout=unknown; rootfs={}", tmp.path().display()),
            );
            tmp.path().to_path_buf()
        };

        progress(
            "container.packages.detect.start",
            rootfs.to_string_lossy().as_ref(),
        );
        let packages_started = std::time::Instant::now();
        packages = detect_os_packages(&rootfs);
        progress_timing("container.packages.detect", packages_started);
        progress(
            "container.packages.detect.done",
            &format!("packages={}", packages.len()),
        );
    }
    progress(
        "container.osv.query.start",
        &format!("packages={}", packages.len()),
    );
    let osv_query_started = std::time::Instant::now();
    let osv_results = osv_batch_query(&packages);
    progress_timing("container.osv.query", osv_query_started);
    progress("container.osv.query.done", "ok");
    let mut findings_norm = map_osv_results_to_findings(&packages, &osv_results);
    let mut heuristic_used = false;
    progress(
        "container.enrich.osv.start",
        &format!("findings_pre_enrich={}", findings_norm.len()),
    );
    let osv_enrich_started = std::time::Instant::now();
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    crate::vuln::osv_enrich_findings(&mut findings_norm, &mut pg);
    progress_timing("container.enrich.osv", osv_enrich_started);
    progress(
        "container.enrich.osv.done",
        &format!("findings={}", findings_norm.len()),
    );
    let nvd_enrich_enabled = std::env::var("SCANNER_NVD_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if nvd_enrich_enabled {
        let unique: HashSet<String> = findings_norm
            .iter()
            .filter(|f| f.id.starts_with("CVE-"))
            .map(|f| f.id.clone())
            .collect();
        progress(
            "container.enrich.nvd.start",
            &format!("cves={}", unique.len()),
        );
        let nvd_enrich_started = std::time::Instant::now();
        enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
        progress_timing("container.enrich.nvd", nvd_enrich_started);
        progress("container.enrich.nvd.done", "ok");
    } else {
        progress(
            "container.enrich.nvd.skip",
            "disabled by SCANNER_NVD_ENRICH",
        );
    }

    // Fallback heuristics when package DBs are absent (light mode by default).
    let allow_heuristic_fallback = heuristic_fallback_allowed(&mode);
    if packages.is_empty() && (has_manifest || has_oci_index) && allow_heuristic_fallback {
        if let Some((name, ver)) = parse_name_version_from_filename(tar_path) {
            let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
            if extra.is_empty() {
                extra = crate::vuln::nvd_findings_by_product_version(
                    &name,
                    &name,
                    &ver,
                    nvd_api_key.as_deref(),
                    Some(tar_path),
                );
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path));
            }
            let start = findings_norm.len();
            findings_norm.append(&mut extra);
            if findings_norm.len() > start {
                retag_findings(
                    &mut findings_norm[start..],
                    ConfidenceTier::HeuristicUnverified,
                    EvidenceSource::FilenameHeuristic,
                    Some(IMAGE_HEURISTIC_NOTE),
                );
                heuristic_used = true;
            }
        }
        if findings_norm.is_empty() {
            if let Some((name, ver)) = detect_busybox_version_in_tree(&rootfs) {
                progress("container.filename.heuristic", &format!("{} {}", name, ver));
                let mut extra =
                    nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
                if extra.is_empty() {
                    extra = crate::vuln::nvd_findings_by_product_version(
                        &name,
                        &name,
                        &ver,
                        nvd_api_key.as_deref(),
                        Some(tar_path),
                    );
                }
                if extra.is_empty() {
                    extra =
                        nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
                }
                if extra.is_empty() {
                    extra =
                        nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path));
                }
                let start = findings_norm.len();
                findings_norm.append(&mut extra);
                if findings_norm.len() > start {
                    retag_findings(
                        &mut findings_norm[start..],
                        ConfidenceTier::HeuristicUnverified,
                        EvidenceSource::BinaryHeuristic,
                        Some(IMAGE_HEURISTIC_NOTE),
                    );
                    heuristic_used = true;
                }
            }
        }
    } else if packages.is_empty() && !allow_heuristic_fallback {
        progress(
            "container.heuristic.skip",
            "heuristic fallback disabled by deep inventory policy",
        );
    }

    let oval_redhat = oval_redhat
        .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
        .filter(|v| !v.trim().is_empty());
    if let Some(oval_path) = oval_redhat.as_deref() {
        progress("container.enrich.redhat.start", oval_path);
        let redhat_started = std::time::Instant::now();
        match filter_findings_with_redhat_oval(&mut findings_norm, &packages, oval_path) {
            Ok(stats) => {
                progress_timing("container.enrich.redhat", redhat_started);
                progress(
                    "container.enrich.redhat.done",
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
                progress_timing("container.enrich.redhat", redhat_started);
                progress("container.enrich.redhat.error", &format!("{}", e));
            }
        }
    }

    // If this doesn't look like a container and we still found nothing, let caller
    // fall back to source/binary handlers.
    if !has_manifest && !has_oci_index && packages.is_empty() && findings_norm.is_empty() {
        return None;
    }

    // Optional YARA in deep mode (ignored if feature not enabled)
    if let ScanMode::Deep = mode {
        if packages.is_empty() && deep_require_installed_inventory() {
            progress(
                "container.yara.skip",
                "deep mode requires installed inventory; skipping heuristic binary scan",
            );
        } else {
            #[cfg(feature = "yara")]
            if let Some(rule_path) = yara_rules.as_deref() {
                if let Ok(mut compiler) = Compiler::new() {
                    let _ = compiler.add_rules_file(rule_path);
                    if let Ok(rules) = compiler.compile_rules() {
                        for entry in WalkDir::new(&rootfs).into_iter().filter_map(|e| e.ok()) {
                            if entry.file_type().is_file() {
                                if let Ok(scan) = rules.scan_file(entry.path(), 5) {
                                    for m in scan.matches {
                                        findings_norm.push(crate::report::Finding {
                                        id: format!("YARA:{}", m.identifier),
                                        source_ids: Vec::new(),
                                        package: None,
                                        confidence_tier: ConfidenceTier::HeuristicUnverified,
                                        evidence_source: EvidenceSource::BinaryHeuristic,
                                        accuracy_note: Some(
                                            "Derived from binary pattern matching; package inventory is not available."
                                                .into(),
                                        ),
                                        fixed: None,
                                        fixed_in: None,
                                        recommendation: None,
                                        severity: None,
                                        cvss: None,
                                        description: None,
                                        evidence: vec![crate::report::EvidenceItem {
                                            evidence_type: "yara".into(),
                                            path: Some(entry.path().display().to_string()),
                                            detail: Some(m.identifier.to_string()),
                                        }],
                                        references: Vec::new(),
                                        confidence: Some("MEDIUM".into()),
                                    });
                                        heuristic_used = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let scanner = ScannerInfo {
        name: "scanrook",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "container".into(),
        source: tar_path.to_string(),
        id: None,
    };
    let mut sbom_info: Option<SbomInfo> = None;
    if sbom {
        progress("container.sbom.start", rootfs.to_string_lossy().as_ref());
        let sbom_started = std::time::Instant::now();
        let sbom_path = tmp.path().join("sbom.cdx.json");
        if run_syft_generate_sbom(
            rootfs.to_str().unwrap_or("."),
            sbom_path.to_str().unwrap_or("sbom.cdx.json"),
        )
        .is_ok()
        {
            sbom_info = Some(SbomInfo {
                format: "cyclonedx".into(),
                path: sbom_path.display().to_string(),
            });
        }
        progress_timing("container.sbom", sbom_started);
        progress("container.sbom.done", "ok");
    }

    let (scan_status, inventory_status, inventory_reason) =
        report_state_for_inventory(packages.len(), &mode, heuristic_used);
    let mut report = Report {
        scanner,
        target,
        scan_status,
        inventory_status,
        inventory_reason,
        sbom: sbom_info,
        findings: findings_norm,
        files: collect_file_tree_if_enabled(&rootfs),
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);
    Some(report)
}

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
                &name,
                &name,
                &ver,
                nvd_api_key.as_deref(),
                Some(tar_path),
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
    // Enrich with NVD using Postgres cache
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    crate::vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);

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
fn detect_busybox_version_in_tree(root: &Path) -> Option<(String, String)> {
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

    // Try specific detections (BusyBox) and general filename/version
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
    // TODO: parse generic Makefile for VERSION/PKGNAME

    let mut findings = Vec::new();
    for (name, ver) in candidates {
        let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        if extra.is_empty() {
            extra = crate::vuln::nvd_findings_by_product_version(
                &name,
                &name,
                &ver,
                nvd_api_key.as_deref(),
                Some(tar_path),
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

    match format {
        OutputFormat::Text => {
            println!("Source: {}", tar_path);
            println!("Findings: {}", findings.len());
        }
        OutputFormat::Json => {
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

fn try_detect_os_packages_from_layout(extracted: &Path) -> anyhow::Result<Vec<PackageCoordinate>> {
    let manifest_path = extracted.join("manifest.json");
    let oci_index_path = extracted.join("index.json");

    let layer_paths = if manifest_path.exists() {
        docker_save_layer_paths(extracted)?
    } else if oci_index_path.exists() {
        oci_layer_paths(extracted)?
    } else {
        return Ok(Vec::new());
    };

    detect_os_packages_from_layers(&layer_paths)
}

fn docker_save_layer_paths(extracted: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let manifest_path = extracted.join("manifest.json");
    let mut manifest_str = String::new();
    File::open(&manifest_path)?.read_to_string(&mut manifest_str)?;
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)?;
    let first = &manifest_json[0];
    let layers = first["Layers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No Layers"))?;

    let mut out = Vec::with_capacity(layers.len());
    for layer_rel in layers {
        let layer_rel = layer_rel
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Layer not string"))?;
        out.push(extracted.join(layer_rel));
    }
    Ok(out)
}

fn oci_layer_paths(extracted: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let index_path = extracted.join("index.json");
    let index_str = fs::read_to_string(&index_path)?;
    let index_json: serde_json::Value = serde_json::from_str(&index_str)?;
    let manifests = index_json["manifests"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("OCI index missing manifests"))?;
    let first = manifests
        .first()
        .ok_or_else(|| anyhow::anyhow!("OCI index manifests empty"))?;
    let manifest_digest = first["digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("OCI descriptor missing digest"))?;
    let manifest_blob = blob_path_from_digest(extracted, manifest_digest)?;

    let manifest_str = fs::read_to_string(&manifest_blob)?;
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)?;
    let layers = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("OCI manifest missing layers"))?;

    let mut out = Vec::with_capacity(layers.len());
    for layer in layers {
        let digest = layer["digest"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("OCI layer missing digest"))?;
        out.push(blob_path_from_digest(extracted, digest)?);
    }
    Ok(out)
}

fn detect_os_packages_from_layers(layer_paths: &[PathBuf]) -> anyhow::Result<Vec<PackageCoordinate>> {
    let mut dpkg_status: Option<Vec<u8>> = None;
    let mut apk_installed: Option<Vec<u8>> = None;

    for layer_path in layer_paths {
        apply_layer_file_overrides(layer_path, &mut dpkg_status, &mut apk_installed)?;
    }

    let mut packages = Vec::new();
    if let Some(bytes) = dpkg_status {
        if let Ok(s) = String::from_utf8(bytes) {
            parse_dpkg_status(&s, &mut packages);
        }
    }
    if let Some(bytes) = apk_installed {
        if let Ok(s) = String::from_utf8(bytes) {
            parse_apk_installed(&s, &mut packages);
        }
    }
    Ok(packages)
}

fn apply_layer_file_overrides(
    layer_tar: &Path,
    dpkg_status: &mut Option<Vec<u8>>,
    apk_installed: &mut Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut file = File::open(layer_tar)?;
    let mut head = [0u8; 3];
    let n = file.read(&mut head)?;
    file.seek(SeekFrom::Start(0))?;

    let is_gz = n >= 2 && head[0] == 0x1f && head[1] == 0x8b;
    let is_bz2 = n >= 3 && head[0] == b'B' && head[1] == b'Z' && head[2] == b'h';

    let mut archive: Archive<Box<dyn Read>> = if is_gz {
        Archive::new(Box::new(GzDecoder::new(file)))
    } else if is_bz2 {
        Archive::new(Box::new(BzDecoder::new(file)))
    } else {
        Archive::new(Box::new(file))
    };

    for entry in archive.entries()? {
        let mut entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(v) => v.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if path.is_empty() {
            continue;
        }

        let parent = std::path::Path::new(&path)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let base = std::path::Path::new(&path)
            .file_name()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // overlayfs whiteout for whole directory content
        if base == ".wh..wh..opq" {
            if parent == "var/lib/dpkg" {
                *dpkg_status = None;
            }
            if parent == "lib/apk/db" {
                *apk_installed = None;
            }
            continue;
        }
        // overlayfs whiteout for single file
        if let Some(stripped) = base.strip_prefix(".wh.") {
            let target = if parent.is_empty() {
                stripped.to_string()
            } else {
                format!("{}/{}", parent, stripped)
            };
            if target == "var/lib/dpkg/status" {
                *dpkg_status = None;
            } else if target == "lib/apk/db/installed" {
                *apk_installed = None;
            }
            continue;
        }

        if path == "var/lib/dpkg/status" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            *dpkg_status = Some(buf);
        } else if path == "lib/apk/db/installed" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            *apk_installed = Some(buf);
        }
    }

    Ok(())
}

fn merge_layers_docker_save(extracted: &Path) -> anyhow::Result<PathBuf> {
    // docker save layout: manifest.json + layer tarballs and config
    let layers = docker_save_layer_paths(extracted)?;

    let rootfs_dir = extracted.join("rootfs");
    fs::create_dir_all(&rootfs_dir)?;

    for layer_path in layers {
        apply_layer_tar(&layer_path, &rootfs_dir)?;
    }

    Ok(rootfs_dir)
}

fn merge_layers_oci_layout(extracted: &Path) -> anyhow::Result<PathBuf> {
    // OCI image layout: index.json -> manifest blob -> layer blobs
    let layers = oci_layer_paths(extracted)?;

    let rootfs_dir = extracted.join("rootfs");
    fs::create_dir_all(&rootfs_dir)?;

    for layer in layers {
        apply_layer_tar(&layer, &rootfs_dir)?;
    }

    Ok(rootfs_dir)
}

fn blob_path_from_digest(extracted: &Path, digest: &str) -> anyhow::Result<PathBuf> {
    let mut parts = digest.splitn(2, ':');
    let algo = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid digest: missing algorithm"))?;
    let hash = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid digest: missing hash"))?;
    Ok(extracted.join("blobs").join(algo).join(hash))
}

fn apply_layer_tar(layer_tar: &Path, rootfs: &Path) -> anyhow::Result<()> {
    let mut file = File::open(layer_tar)?;
    let mut head = [0u8; 3];
    let n = file.read(&mut head)?;
    file.seek(SeekFrom::Start(0))?;

    let is_gz = n >= 2 && head[0] == 0x1f && head[1] == 0x8b;
    let is_bz2 = n >= 3 && head[0] == b'B' && head[1] == b'Z' && head[2] == b'h';

    if is_gz {
        let gz = GzDecoder::new(file);
        let mut ar = Archive::new(gz);
        ar.unpack(rootfs)?;
    } else if is_bz2 {
        let bz = BzDecoder::new(file);
        let mut ar = Archive::new(bz);
        ar.unpack(rootfs)?;
    } else {
        let mut ar = Archive::new(file);
        ar.unpack(rootfs)?;
    }
    Ok(())
}

fn detect_os_packages(rootfs: &Path) -> Vec<PackageCoordinate> {
    let mut packages = Vec::new();

    // Debian/Ubuntu: /var/lib/dpkg/status
    let dpkg_status = rootfs.join("var/lib/dpkg/status");
    if dpkg_status.exists() {
        if let Ok(s) = fs::read_to_string(&dpkg_status) {
            parse_dpkg_status(&s, &mut packages);
        }
    }

    // Alpine: /lib/apk/db/installed
    let apk_db = rootfs.join("lib/apk/db/installed");
    if apk_db.exists() {
        if let Ok(s) = fs::read_to_string(&apk_db) {
            parse_apk_installed(&s, &mut packages);
        }
    }

    // RPM: try host rpm CLI as a fallback (if available)
    // RHEL-like images may use /var/lib/rpm, newer distros may use /usr/lib/sysimage/rpm.
    let rpmdb_legacy = rootfs.join("var/lib/rpm");
    let rpmdb_modern = rootfs.join("usr/lib/sysimage/rpm");
    if rpmdb_legacy.exists() || rpmdb_modern.exists() {
        let rpm_ecosystem = detect_rpm_ecosystem(rootfs);
        progress(
            "container.rpm.ecosystem",
            &format!("detected={}", rpm_ecosystem),
        );
        match detect_rpm_packages_cli(rootfs) {
            Ok(list) => {
                if list.is_empty() {
                    progress("container.rpm.detect.warn", "rpm CLI returned 0 packages");
                } else {
                    progress(
                        "container.rpm.detect.done",
                        &format!("ecosystem={} packages={}", rpm_ecosystem, list.len()),
                    );
                }
                for (name, version) in list {
                    packages.push(PackageCoordinate {
                        ecosystem: rpm_ecosystem.clone(),
                        name,
                        version,
                    });
                }
            }
            Err(e) => {
                progress(
                    "container.rpm.detect.warn",
                    &format!("rpm CLI failed: {}", e),
                );
                eprintln!("Warning: RPM package detection failed: {}", e);
            }
        }
    }

    packages
}

fn detect_rpm_ecosystem(rootfs: &Path) -> String {
    let os_release = rootfs.join("etc/os-release");
    let content = match fs::read_to_string(os_release) {
        Ok(s) => s,
        Err(_) => return "redhat".to_string(),
    };

    let mut id = String::new();
    let mut like = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = trim_os_release_value(v).to_lowercase();
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            like = trim_os_release_value(v).to_lowercase();
        }
    }
    let hay = format!("{} {}", id, like);

    if hay.contains("rocky") {
        return "rocky".to_string();
    }
    if hay.contains("alma") {
        return "almalinux".to_string();
    }
    if hay.contains("opensuse") {
        return "opensuse".to_string();
    }
    if hay.contains("sles") || hay.contains("suse") {
        return "suse".to_string();
    }
    if id == "fedora" {
        return "fedora".to_string();
    }
    if id == "centos" {
        return "centos".to_string();
    }

    // Default all RHEL-like RPM families to Red Hat for OSV queries.
    "redhat".to_string()
}

fn trim_os_release_value(v: &str) -> String {
    v.trim().trim_matches('"').to_string()
}

fn parse_dpkg_status(contents: &str, out: &mut Vec<PackageCoordinate>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut installed_ok: bool = false;
    for line in contents.lines() {
        if line.starts_with("Package:") {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                if installed_ok {
                    out.push(PackageCoordinate {
                        ecosystem: "deb".into(),
                        name: n,
                        version: v,
                    });
                }
            }
            name = Some(line[8..].trim().to_string());
            version = None;
            installed_ok = false;
        } else if line.starts_with("Version:") {
            version = Some(line[8..].trim().to_string());
        } else if line.starts_with("Status:") {
            // Expect: Status: install ok installed
            installed_ok = line.contains("install ok installed");
        } else if line.is_empty() {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                if installed_ok {
                    out.push(PackageCoordinate {
                        ecosystem: "deb".into(),
                        name: n,
                        version: v,
                    });
                }
            }
        }
    }
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        if installed_ok {
            out.push(PackageCoordinate {
                ecosystem: "deb".into(),
                name: n,
                version: v,
            });
        }
    }
}

fn parse_apk_installed(contents: &str, out: &mut Vec<PackageCoordinate>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in contents.lines() {
        if line.starts_with("P:") {
            name = Some(line[2..].trim().to_string());
        } else if line.starts_with("V:") {
            version = Some(line[2..].trim().to_string());
        } else if line.is_empty() {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                out.push(PackageCoordinate {
                    ecosystem: "apk".into(),
                    name: n,
                    version: v,
                });
            }
        }
    }
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        out.push(PackageCoordinate {
            ecosystem: "apk".into(),
            name: n,
            version: v,
        });
    }
}

fn detect_rpm_packages_cli(rootfs: &Path) -> anyhow::Result<Vec<(String, String)>> {
    use std::process::Command;
    let dbpaths = [
        rootfs.join("var/lib/rpm"),
        rootfs.join("usr/lib/sysimage/rpm"),
    ];

    let mut last_err: Option<anyhow::Error> = None;
    for dbpath in dbpaths.iter() {
        if !dbpath.exists() {
            continue;
        }

        let output = Command::new("rpm")
            .arg("-qa")
            .arg("--dbpath")
            .arg(dbpath)
            .arg("--qf")
            .arg("%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n")
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout);
                let mut results = Vec::new();
                for line in s.lines() {
                    let mut parts = line.split_whitespace();
                    if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
                        // Strip "(none):" epoch prefix that rpm outputs when epoch is unset
                        let ver = ver.trim_start_matches("(none):");
                        results.push((name.to_string(), ver.to_string()));
                    }
                }
                if !results.is_empty() {
                    return Ok(results);
                }
                last_err = Some(anyhow::anyhow!(
                    "rpm query returned no packages for dbpath {}",
                    dbpath.display()
                ));
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                last_err = Some(anyhow::anyhow!(
                    "rpm exited with status {} for dbpath {}: {}",
                    out.status,
                    dbpath.display(),
                    stderr.trim()
                ));
            }
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "failed to invoke rpm for dbpath {}: {}",
                    dbpath.display(),
                    e
                ));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no rpm database found in rootfs")))
}
