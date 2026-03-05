//! DMG (macOS disk image) extraction and scanning.
//!
//! # External Tool Requirements
//!
//! DMG extraction uses the following tools in order:
//!
//! - **`dmgwiz + hpcopy`** — Cross-platform Rust-native UDIF decompression via the `dmgwiz`
//!   crate, followed by HFS+ filesystem extraction via `hpcopy` from the `hfsutils` package.
//!   On Linux: `apt-get install hfsutils` or `brew install hfsutils`.
//!   This is the primary extraction path for Linux workers.
//! - **`hdiutil`** — macOS only, built-in. Mounts the DMG and copies the filesystem tree.
//! - **`7z`** — Cross-platform last-resort fallback. Provided by `p7zip-full` on Linux/Debian.
//!
//! # Extraction Fallback Chain
//!
//! 1. `try_extract_dmg_native()` — dmgwiz (UDIF decompression) + hpcopy (HFS+ tree extraction).
//!    Writes raw partition bytes to a temp file, then shells out to `hpcopy -r / <dest>`.
//!    Bails gracefully with a descriptive error if `hpcopy` is not installed.
//! 2. `hdiutil attach` — macOS only (compile-time `cfg!(target_os = "macos")` guard).
//! 3. `7z x` — Cross-platform fallback.
//!
//! # Graceful Degradation
//!
//! If all extraction methods fail (e.g., in a test environment without hpcopy/7z),
//! `build_dmg_report()` does **not** return `None`. Instead it falls through to binary-only
//! scanning with an empty package list, emitting a warning in the progress output. This ensures
//! a report is always returned for DMG inputs, even when extraction is impossible.

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

use super::detect::{detect_app_packages, detect_macos_packages};

/// Attempt Rust-native DMG extraction using dmgwiz + hpcopy.
///
/// Pipeline:
/// 1. dmgwiz parses the UDIF footer/partition table and decompresses the HFS+ partition data
///    to a raw partition image file (e.g., `dest/partition.hfs`).
/// 2. `hpcopy -r / <dest>` extracts the HFS+ filesystem tree from the raw image into `dest`.
/// 3. The temp partition file is removed after successful extraction.
///
/// Fails gracefully (returning Err) when:
/// - dmgwiz cannot parse the DMG (invalid format, encrypted, LZMA gap, etc.)
/// - No non-trivial data partition is found in the partition table
/// - `hpcopy` is not installed on the system
/// - `hpcopy` returns a non-zero exit code
///
/// Falls through to hdiutil (macOS) or 7z on error.
pub(crate) fn try_extract_dmg_native(path: &str, dest: &Path) -> anyhow::Result<()> {
    use std::io::BufWriter;
    use std::process::Command;

    // Check that hpcopy is available before doing expensive dmgwiz work.
    // `hpcopy` is provided by `hfsutils` — install with:
    //   Linux:  apt-get install hfsutils
    //   macOS:  brew install hfsutils
    let hpcopy_check = Command::new("hpcopy").arg("--version").output();
    if hpcopy_check.is_err() {
        // Also check if it's in PATH via which-style probe
        let which_check = Command::new("which").arg("hpcopy").output();
        let found = which_check
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            anyhow::bail!(
                "hpcopy not found — install hfsutils (Linux: apt-get install hfsutils, macOS: brew install hfsutils) for dmgwiz+hpcopy DMG extraction"
            );
        }
    }

    // Open the DMG and parse the UDIF partition table using dmgwiz.
    let dmg_file = fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open DMG '{}': {}", path, e))?;
    let mut wiz = dmgwiz::DmgWiz::from_reader(
        std::io::BufReader::new(dmg_file),
        dmgwiz::Verbosity::None,
    )
    .map_err(|e| anyhow::anyhow!("dmgwiz failed to parse '{}': {}", path, e))?;

    // Find the data partition: prefer partitions whose names suggest HFS+ data.
    // Common names in Apple DMGs: "Apple_HFS", "Apple_HFSX", "disk image", or the app name.
    // Skip partition map entries, free space, drivers, and EFI partitions.
    let skip_names = ["partition_map", "free_space", "driver", "efi", "apple_boot"];
    let hfs_names = ["apple_hfs", "apple_hfsx", "hfs"];

    // First try partitions with explicitly known HFS names, then fall back to any non-skip partition.
    let partition_idx = {
        let partitions = &wiz.partitions;
        // Priority 1: known HFS+ partition name
        let hfs_idx = partitions.iter().enumerate().find(|(_, p)| {
            let name_lower = p.name.to_ascii_lowercase();
            hfs_names.iter().any(|s| name_lower.contains(s))
        });
        // Priority 2: any non-skipped partition (typically the main data partition)
        let fallback_idx = partitions.iter().enumerate().find(|(_, p)| {
            let name_lower = p.name.to_ascii_lowercase();
            !skip_names.iter().any(|s| name_lower.contains(s))
        });

        match hfs_idx.or(fallback_idx) {
            Some((i, _)) => i,
            None => anyhow::bail!("dmgwiz: no suitable data partition found in '{}'", path),
        }
    };

    progress(
        "dmg.extract.dmgwiz",
        &format!(
            "partition={} name='{}'",
            partition_idx, wiz.partitions[partition_idx].name
        ),
    );

    // Write raw HFS+ partition bytes to a temp file.
    let partition_file = dest.join("partition.hfs");
    {
        let out_file = fs::File::create(&partition_file)
            .map_err(|e| anyhow::anyhow!("failed to create partition file: {}", e))?;
        let writer = BufWriter::new(out_file);
        wiz.extract_partition(writer, partition_idx)
            .map_err(|e| anyhow::anyhow!("dmgwiz extraction failed: {}", e))?;
    }

    // Shell out to hpcopy to extract the HFS+ filesystem tree.
    // hpcopy syntax: hpcopy -r <src_hfs_path> <local_dest>
    // The `:` prefix means the HFS+ root volume.
    let hcopy_dest = dest.join("contents");
    fs::create_dir_all(&hcopy_dest)
        .map_err(|e| anyhow::anyhow!("failed to create hcopy dest dir: {}", e))?;

    // hpcopy needs the HFS volume mounted. Use `hmount` first, then `hcopy`.
    // hmount <image> — mounts the HFS partition image
    // hcopy -r : <dest_dir> — copies all files from volume root recursively
    let hmount_status = Command::new("hmount")
        .arg(&partition_file)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run hmount: {} — is hfsutils installed?", e))?;

    if !hmount_status.success() {
        // Clean up partition file before bailing
        let _ = fs::remove_file(&partition_file);
        anyhow::bail!(
            "hmount failed on '{}' — partition may not be HFS+ format",
            partition_file.display()
        );
    }

    // Copy all files from the HFS+ volume to dest
    let hcopy_status = Command::new("hcopy")
        .args(["-r", ":", &hcopy_dest.to_string_lossy()])
        .status();

    // Always unmount before returning
    let _ = Command::new("humount").status();

    // Clean up partition file
    let _ = fs::remove_file(&partition_file);

    match hcopy_status {
        Ok(s) if s.success() => {
            progress("dmg.extract.hpcopy.done", &hcopy_dest.to_string_lossy());
            Ok(())
        }
        Ok(s) => anyhow::bail!(
            "hcopy failed with exit code {} — HFS+ filesystem tree extraction failed",
            s.code().unwrap_or(-1)
        ),
        Err(e) => anyhow::bail!(
            "hcopy not found: {} — install hfsutils (apt-get install hfsutils)",
            e
        ),
    }
}

/// Extract a DMG file to a temporary directory.
/// Tries dmgwiz (Rust-native, currently no-op) first, then hdiutil (macOS), then 7z.
pub fn extract_dmg(path: &str, dest: &Path) -> anyhow::Result<()> {
    use std::process::Command;

    // Try Rust-native extraction first (cross-platform, no external tools required).
    // Currently a no-op bail — falls through to hdiutil/7z which are the production paths.
    match try_extract_dmg_native(path, dest) {
        Ok(()) => return Ok(()),
        Err(e) => {
            // Log and fall through to external tools
            progress("dmg.extract.native_skip", &format!("{}", e));
        }
    }

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
            "DMG extraction requires hdiutil (macOS) or 7z (apt: p7zip-full). Neither was found. Install p7zip-full on Linux or use macOS for DMG scanning."
        ),
    }
}

/// Build a report for a DMG disk image.
pub fn build_dmg_report(path: &str, mode: ScanMode, nvd_api_key: Option<String>) -> Option<Report> {
    let started = std::time::Instant::now();
    progress("dmg.extract.start", path);

    let tmp = tempdir().ok()?;
    let extraction_succeeded = match extract_dmg(path, tmp.path()) {
        Ok(()) => true,
        Err(e) => {
            // Per CONTEXT.md: "On extraction failure after all fallbacks: emit warning,
            // skip to binary-only scanning" — do NOT return None, continue with empty packages.
            progress(
                "dmg.extract.warning",
                &format!(
                    "extraction failed: {} — falling through to binary-only scan",
                    e
                ),
            );
            false
        }
    };
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

    // Only detect packages if extraction succeeded (otherwise the temp dir is empty)
    let packages = if extraction_succeeded {
        let mut pkgs = detect_app_packages(scan_root);
        // Also detect macOS-native packages (.app bundles and .pkg installers)
        let macos_pkgs = detect_macos_packages(scan_root);
        for p in macos_pkgs {
            if !pkgs
                .iter()
                .any(|e| e.name == p.name && e.version == p.version && e.ecosystem == p.ecosystem)
            {
                pkgs.push(p);
            }
        }
        pkgs
    } else {
        Vec::new()
    };

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
