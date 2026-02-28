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
use tempfile::{tempdir, TempDir};
use walkdir::WalkDir;
#[cfg(feature = "yara")]
use yara::Compiler;

/// Maximum decompressed size per tar entry (2 GB) to guard against decompression bombs
const MAX_ENTRY_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Pull and save a container image to a temporary tar file using docker or podman.
///
/// Returns (TempDir, path_string) — the TempDir must be kept alive for the duration
/// of scanning; it is cleaned up when dropped.
pub fn pull_and_save_image(image_ref: &str) -> anyhow::Result<(TempDir, String)> {
    use std::process::Command;

    let tmpdir = tempdir()?;
    let tar_path = tmpdir.path().join("image.tar");
    let tar_str = tar_path.to_string_lossy().to_string();

    // Try docker first, then podman
    for runtime in &["docker", "podman"] {
        // Check if runtime exists
        let exists = Command::new(runtime)
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if exists.is_err() || !exists.unwrap().success() {
            continue;
        }

        progress("image.runtime", runtime);

        // Try to save directly (image may already be pulled)
        let save = Command::new(runtime)
            .arg("save")
            .arg(image_ref)
            .arg("-o")
            .arg(&tar_str)
            .output()?;

        if save.status.success() && tar_path.exists() {
            let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
            if size > 0 {
                progress(
                    "image.saved",
                    &format!("runtime={} size={}", runtime, size),
                );
                return Ok((tmpdir, tar_str));
            }
        }

        // Image not pulled yet — pull first, then save
        progress("image.pull.start", &format!("{} pull {}", runtime, image_ref));
        let pull = Command::new(runtime)
            .arg("pull")
            .arg(image_ref)
            .output()?;

        if !pull.status.success() {
            let stderr = String::from_utf8_lossy(&pull.stderr);
            progress(
                "image.pull.error",
                &format!("{}: {}", runtime, stderr.trim()),
            );
            continue;
        }

        // Now save
        let save = Command::new(runtime)
            .arg("save")
            .arg(image_ref)
            .arg("-o")
            .arg(&tar_str)
            .output()?;

        if save.status.success() && tar_path.exists() {
            let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
            if size > 0 {
                progress(
                    "image.saved",
                    &format!("runtime={} size={}", runtime, size),
                );
                return Ok((tmpdir, tar_str));
            }
        }

        let stderr = String::from_utf8_lossy(&save.stderr);
        progress(
            "image.save.error",
            &format!("{}: {}", runtime, stderr.trim()),
        );
    }

    Err(anyhow::anyhow!(
        "No container runtime (docker/podman) available or failed to save image '{}'. \
         Install docker or podman, or use --file with a pre-saved tar.",
        image_ref
    ))
}

/// Extracts a tar archive (optionally gzipped) to dest with path-traversal protection.
///
/// Each entry's path is validated to stay within `dest`. Symlinks pointing outside
/// the destination are rejected. Individual entry sizes are capped at MAX_ENTRY_SIZE.
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

    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let raw_path = entry.path()?.to_path_buf();

        // Reject entries with absolute paths or path-traversal components
        if raw_path.is_absolute() {
            anyhow::bail!(
                "tar entry has absolute path (potential path traversal): {}",
                raw_path.display()
            );
        }
        for component in raw_path.components() {
            if let std::path::Component::ParentDir = component {
                anyhow::bail!(
                    "tar entry contains '..' (potential path traversal): {}",
                    raw_path.display()
                );
            }
        }

        let target = dest.join(&raw_path);
        // After joining, canonicalize parent to verify it's within dest
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let canonical_target = target
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.join(target.file_name().unwrap_or_default()))
            .unwrap_or_else(|| target.clone());
        if !canonical_target.starts_with(&canonical_dest) {
            anyhow::bail!(
                "tar entry escapes destination directory (path traversal): {}",
                raw_path.display()
            );
        }

        // Reject symlinks that point outside the destination
        if entry.header().entry_type().is_symlink() {
            if let Ok(link_target) = entry.link_name() {
                if let Some(link_path) = link_target.as_ref() {
                    let resolved = if link_path.is_absolute() {
                        link_path.to_path_buf()
                    } else {
                        canonical_target
                            .parent()
                            .unwrap_or(&canonical_dest)
                            .join(link_path)
                    };
                    // Normalize the resolved path by stripping .. components
                    let mut normalized = PathBuf::new();
                    for comp in resolved.components() {
                        match comp {
                            std::path::Component::ParentDir => {
                                normalized.pop();
                            }
                            std::path::Component::CurDir => {}
                            other => normalized.push(other),
                        }
                    }
                    if !normalized.starts_with(&canonical_dest) {
                        anyhow::bail!(
                            "tar symlink escapes destination directory: {} -> {}",
                            raw_path.display(),
                            link_path.display()
                        );
                    }
                }
            }
        }

        // Guard against decompression bombs
        if entry.header().size()? > MAX_ENTRY_SIZE {
            anyhow::bail!(
                "tar entry exceeds maximum allowed size ({} bytes): {}",
                MAX_ENTRY_SIZE,
                raw_path.display()
            );
        }

        entry.unpack(&target)?;
    }
    Ok(())
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Hash)]
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
        progress(
            "files.collect.skip",
            "disabled by SCANNER_INCLUDE_FILE_TREE",
        );
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

    // Debian Security Tracker enrichment (for deb/dpkg packages)
    {
        let has_deb = packages.iter().any(|p| p.ecosystem == "deb");
        if has_deb {
            progress("container.enrich.debian_tracker.start", "");
            let dst_started = std::time::Instant::now();
            let dst_cache = crate::vuln::resolve_enrich_cache_dir();
            crate::vuln::debian_tracker_enrich(&packages, &mut findings_norm, dst_cache.as_deref());
            progress_timing("container.enrich.debian_tracker", dst_started);
        }
    }

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
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            // Auto-download OVAL for RPM-based images when not explicitly provided
            let has_rpm = packages.iter().any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem));
            if has_rpm {
                let cache = crate::vuln::resolve_enrich_cache_dir();
                crate::redhat::fetch_redhat_oval(&packages, cache.as_deref())
            } else {
                None
            }
        });
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
            let cache_dir = crate::vuln::resolve_enrich_cache_dir();
            crate::vuln::epss_enrich_findings(&mut findings_norm, cache_dir.as_deref());
            crate::vuln::kev_enrich_findings(&mut findings_norm, cache_dir.as_deref());

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

    // Debian Security Tracker enrichment (for deb/dpkg packages)
    let has_deb_packages = packages.iter().any(|p| p.ecosystem == "deb");
    if has_deb_packages {
        progress("container.enrich.debian_tracker.start", "");
        let dst_started = std::time::Instant::now();
        let dst_cache_dir = crate::vuln::resolve_enrich_cache_dir();
        crate::vuln::debian_tracker_enrich(&packages, &mut findings_norm, dst_cache_dir.as_deref());
        progress_timing("container.enrich.debian_tracker", dst_started);
    }

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
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            // Auto-download OVAL for RPM-based images when not explicitly provided
            let has_rpm = packages.iter().any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem));
            if has_rpm {
                let cache = crate::vuln::resolve_enrich_cache_dir();
                crate::redhat::fetch_redhat_oval(&packages, cache.as_deref())
            } else {
                None
            }
        });
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
                                        epss_score: None,
                                        epss_percentile: None,
                                        in_kev: None,
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

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::vuln::epss_enrich_findings(&mut findings_norm, cache_dir.as_deref());
    crate::vuln::kev_enrich_findings(&mut findings_norm, cache_dir.as_deref());

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

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::vuln::epss_enrich_findings(&mut findings, cache_dir.as_deref());
    crate::vuln::kev_enrich_findings(&mut findings, cache_dir.as_deref());

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
            let cache_dir = crate::vuln::resolve_enrich_cache_dir();
            crate::vuln::epss_enrich_findings(&mut findings, cache_dir.as_deref());
            crate::vuln::kev_enrich_findings(&mut findings, cache_dir.as_deref());

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

fn detect_os_packages_from_layers(
    layer_paths: &[PathBuf],
) -> anyhow::Result<Vec<PackageCoordinate>> {
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

    // Alpine / Chainguard / Wolfi: /lib/apk/db/installed
    let apk_db = rootfs.join("lib/apk/db/installed");
    if apk_db.exists() {
        let apk_eco = detect_apk_ecosystem(rootfs);
        if let Ok(s) = fs::read_to_string(&apk_db) {
            parse_apk_installed_with_ecosystem(&s, &apk_eco, &mut packages);
        }
    }

    // RPM: try native parsing first (SQLite/BDB), then fall back to rpm CLI.
    // RHEL-like images may use /var/lib/rpm, newer distros may use /usr/lib/sysimage/rpm.
    let rpmdb_legacy = rootfs.join("var/lib/rpm");
    let rpmdb_modern = rootfs.join("usr/lib/sysimage/rpm");
    if rpmdb_legacy.exists() || rpmdb_modern.exists() {
        let rpm_ecosystem = detect_rpm_ecosystem(rootfs);
        progress(
            "container.rpm.ecosystem",
            &format!("detected={}", rpm_ecosystem),
        );
        match detect_rpm_packages_native(rootfs) {
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
    if id == "amzn" || hay.contains("amazon") {
        return "amazonlinux".to_string();
    }
    if hay.contains("opensuse") {
        return "opensuse".to_string();
    }
    if hay.contains("sles") || hay.contains("suse") {
        return "suse".to_string();
    }
    if id == "ol" || hay.contains("oracle") {
        return "oraclelinux".to_string();
    }
    if id == "fedora" {
        return "fedora".to_string();
    }
    if id == "centos" {
        return "centos".to_string();
    }
    if id == "chainguard" || hay.contains("chainguard") {
        return "chainguard".to_string();
    }
    if id == "wolfi" || hay.contains("wolfi") {
        return "wolfi".to_string();
    }

    // Default all RHEL-like RPM families to Red Hat for OSV queries.
    "redhat".to_string()
}

fn detect_apk_ecosystem(rootfs: &Path) -> String {
    let os_release = rootfs.join("etc/os-release");
    let content = match fs::read_to_string(os_release) {
        Ok(s) => s,
        Err(_) => return "apk".to_string(),
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
    if id == "chainguard" || hay.contains("chainguard") {
        return "chainguard".to_string();
    }
    if id == "wolfi" || hay.contains("wolfi") {
        return "wolfi".to_string();
    }
    "apk".to_string()
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
    parse_apk_installed_with_ecosystem(contents, "apk", out);
}

fn parse_apk_installed_with_ecosystem(
    contents: &str,
    ecosystem: &str,
    out: &mut Vec<PackageCoordinate>,
) {
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
                    ecosystem: ecosystem.into(),
                    name: n,
                    version: v,
                });
            }
        }
    }
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        out.push(PackageCoordinate {
            ecosystem: ecosystem.into(),
            name: n,
            version: v,
        });
    }
}

/// Detect RPM packages using native parsing (SQLite + BerkeleyDB), falling back to rpm CLI.
fn detect_rpm_packages_native(rootfs: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let db_candidates = [
        rootfs.join("var/lib/rpm/rpmdb.sqlite"),
        rootfs.join("usr/lib/sysimage/rpm/rpmdb.sqlite"),
    ];

    // 1. Try SQLite databases first (modern RPM: RHEL 9+, Fedora 33+, Rocky 9+)
    for sqlite_path in &db_candidates {
        if !sqlite_path.exists() {
            continue;
        }
        progress("container.rpm.native.sqlite", &sqlite_path.to_string_lossy());
        match parse_rpm_sqlite(sqlite_path) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress(
                    "container.rpm.native.sqlite.done",
                    &format!("packages={}", pkgs.len()),
                );
                return Ok(pkgs);
            }
            Ok(_) => {
                progress("container.rpm.native.sqlite.empty", &sqlite_path.to_string_lossy());
            }
            Err(e) => {
                progress(
                    "container.rpm.native.sqlite.error",
                    &format!("{}: {}", sqlite_path.display(), e),
                );
            }
        }
    }

    // 2. Try BerkeleyDB Packages file (legacy RPM: RHEL 7/8, CentOS, older Fedora)
    let bdb_candidates = [
        rootfs.join("var/lib/rpm/Packages"),
        rootfs.join("var/lib/rpm/Packages.db"),
        rootfs.join("usr/lib/sysimage/rpm/Packages"),
        rootfs.join("usr/lib/sysimage/rpm/Packages.db"),
    ];
    for bdb_path in &bdb_candidates {
        if !bdb_path.exists() {
            continue;
        }
        progress("container.rpm.native.bdb", &bdb_path.to_string_lossy());
        match parse_rpm_bdb(bdb_path) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress(
                    "container.rpm.native.bdb.done",
                    &format!("packages={}", pkgs.len()),
                );
                return Ok(pkgs);
            }
            Ok(_) => {
                progress("container.rpm.native.bdb.empty", &bdb_path.to_string_lossy());
            }
            Err(e) => {
                progress(
                    "container.rpm.native.bdb.error",
                    &format!("{}: {}", bdb_path.display(), e),
                );
            }
        }
    }

    // 3. Fall back to rpm CLI as last resort
    progress("container.rpm.native.fallback", "trying rpm CLI");
    detect_rpm_packages_cli(rootfs)
}

/// Parse RPM packages from a SQLite rpmdb.
pub fn parse_rpm_sqlite(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    use rusqlite::Connection;
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare("SELECT hnum, blob FROM Packages")?;
    let mut results = Vec::new();
    let rows = stmt.query_map([], |row| {
        let _hnum: i64 = row.get(0)?;
        let blob: Vec<u8> = row.get(1)?;
        Ok(blob)
    })?;
    for row in rows {
        let blob = match row {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some((name, version)) = parse_rpm_header_blob(&blob) {
            results.push((name, version));
        }
    }
    Ok(results)
}

/// Parse RPM packages from a BerkeleyDB hash-format Packages file.
pub fn parse_rpm_bdb(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let data = fs::read(path)?;
    if data.len() < 512 {
        return Err(anyhow::anyhow!("file too small for BerkeleyDB"));
    }

    // BerkeleyDB hash magic: 0x00061561 (little-endian) at offset 12
    // Or btree magic: 0x00053162 at offset 12
    let magic = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let is_hash = magic == 0x00061561;
    let is_btree = magic == 0x00053162;
    if !is_hash && !is_btree {
        return Err(anyhow::anyhow!(
            "not a BerkeleyDB hash/btree file (magic=0x{:08x})",
            magic
        ));
    }

    // Page size at offset 20 (4 bytes LE)
    let page_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
    if page_size == 0 || page_size > 65536 || data.len() % page_size != 0 {
        // Try common page sizes
        return parse_rpm_bdb_scan(&data);
    }

    parse_rpm_bdb_scan(&data)
}

/// Scan BerkeleyDB data for RPM header blobs by looking for the RPM header magic.
fn parse_rpm_bdb_scan(data: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    let mut results = Vec::new();
    let rpm_magic: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];

    // Scan for RPM header magic bytes throughout the file
    let mut offset = 0;
    while offset + 16 < data.len() {
        if data[offset..offset + 4] == rpm_magic {
            // Found an RPM header; try to parse it
            if let Some((name, version)) = parse_rpm_header_blob(&data[offset..]) {
                results.push((name, version));
            }
        }
        offset += 1;
    }

    if results.is_empty() {
        return Err(anyhow::anyhow!("no RPM headers found in BerkeleyDB file"));
    }
    Ok(results)
}

/// RPM header tag constants
const RPM_TAG_NAME: u32 = 1000;
const RPM_TAG_VERSION: u32 = 1001;
const RPM_TAG_RELEASE: u32 = 1002;
const RPM_TAG_EPOCH: u32 = 1003;
/// RPM tag type: STRING
const RPM_TYPE_STRING: u32 = 6;
/// RPM tag type: INT32
const RPM_TYPE_INT32: u32 = 4;

/// Parse NAME, VERSION, RELEASE, EPOCH from an RPM header binary blob.
///
/// RPM header format:
///   Bytes 0-3:   magic (8e ad e8 01)
///   Bytes 4-7:   reserved (4 bytes)
///   Bytes 8-11:  nindex — number of tag entries (big-endian u32)
///   Bytes 12-15: hsize — size of the data section in bytes (big-endian u32)
///   Bytes 16..:  nindex * 16-byte tag entries, then hsize bytes of data
///
/// Each tag entry (16 bytes):
///   Bytes 0-3: tag id (big-endian u32)
///   Bytes 4-7: type (big-endian u32)
///   Bytes 8-11: offset into data section (big-endian u32)
///   Bytes 12-15: count (big-endian u32)
fn parse_rpm_header_blob(blob: &[u8]) -> Option<(String, String)> {
    if blob.len() < 16 {
        return None;
    }
    // Verify magic
    if blob[0..4] != [0x8e, 0xad, 0xe8, 0x01] {
        return None;
    }
    let nindex = u32::from_be_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let hsize = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;

    // Sanity check: nindex and hsize shouldn't be unreasonably large
    if nindex > 10000 || hsize > 64 * 1024 * 1024 {
        return None;
    }

    let entries_start = 16;
    let entries_size = nindex * 16;
    let data_start = entries_start + entries_size;
    let total_needed = data_start + hsize;
    if blob.len() < total_needed {
        // If the blob is smaller, try with available data
        if blob.len() < data_start {
            return None;
        }
    }

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut release: Option<String> = None;
    let mut epoch: Option<u32> = None;

    for i in 0..nindex {
        let e = entries_start + i * 16;
        if e + 16 > blob.len() {
            break;
        }
        let tag = u32::from_be_bytes([blob[e], blob[e + 1], blob[e + 2], blob[e + 3]]);
        let ttype = u32::from_be_bytes([blob[e + 4], blob[e + 5], blob[e + 6], blob[e + 7]]);
        let toffset =
            u32::from_be_bytes([blob[e + 8], blob[e + 9], blob[e + 10], blob[e + 11]]) as usize;

        let abs_offset = data_start + toffset;

        match tag {
            RPM_TAG_NAME | RPM_TAG_VERSION | RPM_TAG_RELEASE if ttype == RPM_TYPE_STRING => {
                if abs_offset < blob.len() {
                    let end = blob[abs_offset..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(blob.len() - abs_offset);
                    if let Ok(s) = std::str::from_utf8(&blob[abs_offset..abs_offset + end]) {
                        match tag {
                            RPM_TAG_NAME => name = Some(s.to_string()),
                            RPM_TAG_VERSION => version = Some(s.to_string()),
                            RPM_TAG_RELEASE => release = Some(s.to_string()),
                            _ => {}
                        }
                    }
                }
            }
            RPM_TAG_EPOCH if ttype == RPM_TYPE_INT32 => {
                if abs_offset + 4 <= blob.len() {
                    epoch = Some(u32::from_be_bytes([
                        blob[abs_offset],
                        blob[abs_offset + 1],
                        blob[abs_offset + 2],
                        blob[abs_offset + 3],
                    ]));
                }
            }
            _ => {}
        }

        // Short-circuit if we found everything
        if name.is_some() && version.is_some() && release.is_some() {
            // epoch is optional, but check if there could be more entries with it
            if epoch.is_some() || i > nindex / 2 {
                break;
            }
        }
    }

    let n = name?;
    let v = version?;
    let r = release.unwrap_or_default();

    let full_version = if let Some(e) = epoch {
        if e > 0 {
            format!("{}:{}-{}", e, v, r)
        } else if r.is_empty() {
            v
        } else {
            format!("{}-{}", v, r)
        }
    } else if r.is_empty() {
        v
    } else {
        format!("{}-{}", v, r)
    };

    Some((n, full_version))
}

/// Fallback: detect RPM packages using the system rpm CLI.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RPM header blob with NAME, VERSION, RELEASE tags.
    fn make_rpm_header(name: &str, version: &str, release: &str, epoch: Option<u32>) -> Vec<u8> {
        let mut tag_count: u32 = 3; // NAME, VERSION, RELEASE
        if epoch.is_some() {
            tag_count += 1;
        }

        // Data section: strings laid out sequentially with NUL terminators, then optional epoch
        let mut data = Vec::new();
        let name_offset = data.len() as u32;
        data.extend_from_slice(name.as_bytes());
        data.push(0);
        let version_offset = data.len() as u32;
        data.extend_from_slice(version.as_bytes());
        data.push(0);
        let release_offset = data.len() as u32;
        data.extend_from_slice(release.as_bytes());
        data.push(0);
        // Align to 4-byte boundary for INT32 if needed
        let epoch_offset = if epoch.is_some() {
            while data.len() % 4 != 0 {
                data.push(0);
            }
            let off = data.len() as u32;
            let e = epoch.unwrap();
            data.extend_from_slice(&e.to_be_bytes());
            off
        } else {
            0
        };

        let hsize = data.len() as u32;
        let nindex = tag_count;

        let mut blob = Vec::new();
        // Header magic
        blob.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01]);
        // Reserved
        blob.extend_from_slice(&[0, 0, 0, 0]);
        // nindex
        blob.extend_from_slice(&nindex.to_be_bytes());
        // hsize
        blob.extend_from_slice(&hsize.to_be_bytes());
        // Tag entries (16 bytes each): tag, type, offset, count
        // NAME
        blob.extend_from_slice(&RPM_TAG_NAME.to_be_bytes());
        blob.extend_from_slice(&RPM_TYPE_STRING.to_be_bytes());
        blob.extend_from_slice(&name_offset.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        // VERSION
        blob.extend_from_slice(&RPM_TAG_VERSION.to_be_bytes());
        blob.extend_from_slice(&RPM_TYPE_STRING.to_be_bytes());
        blob.extend_from_slice(&version_offset.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        // RELEASE
        blob.extend_from_slice(&RPM_TAG_RELEASE.to_be_bytes());
        blob.extend_from_slice(&RPM_TYPE_STRING.to_be_bytes());
        blob.extend_from_slice(&release_offset.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        // EPOCH (optional)
        if epoch.is_some() {
            blob.extend_from_slice(&RPM_TAG_EPOCH.to_be_bytes());
            blob.extend_from_slice(&RPM_TYPE_INT32.to_be_bytes());
            blob.extend_from_slice(&epoch_offset.to_be_bytes());
            blob.extend_from_slice(&1u32.to_be_bytes());
        }
        // Data section
        blob.extend_from_slice(&data);

        blob
    }

    #[test]
    fn test_parse_rpm_header_blob_basic() {
        let blob = make_rpm_header("bash", "5.1.8", "6.el9", None);
        let result = parse_rpm_header_blob(&blob);
        assert_eq!(
            result,
            Some(("bash".to_string(), "5.1.8-6.el9".to_string()))
        );
    }

    #[test]
    fn test_parse_rpm_header_blob_with_epoch() {
        let blob = make_rpm_header("openssl", "3.0.7", "20.el9", Some(1));
        let result = parse_rpm_header_blob(&blob);
        assert_eq!(
            result,
            Some(("openssl".to_string(), "1:3.0.7-20.el9".to_string()))
        );
    }

    #[test]
    fn test_parse_rpm_header_blob_epoch_zero() {
        let blob = make_rpm_header("glibc", "2.34", "60.el9", Some(0));
        let result = parse_rpm_header_blob(&blob);
        assert_eq!(
            result,
            Some(("glibc".to_string(), "2.34-60.el9".to_string()))
        );
    }

    #[test]
    fn test_parse_rpm_header_blob_bad_magic() {
        let blob = vec![0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_rpm_header_blob(&blob), None);
    }

    #[test]
    fn test_parse_rpm_header_blob_too_short() {
        let blob = vec![0x8e, 0xad, 0xe8, 0x01];
        assert_eq!(parse_rpm_header_blob(&blob), None);
    }

    #[test]
    fn test_parse_rpm_sqlite_nonexistent() {
        let result = parse_rpm_sqlite(Path::new("/nonexistent/rpmdb.sqlite"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dpkg_status_basic() {
        let status = "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\nPackage: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n";
        let mut out = Vec::new();
        parse_dpkg_status(status, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "libc6");
        assert_eq!(out[0].version, "2.36-9");
    }
}
