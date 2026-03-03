//! Archive scanning: ZIP extraction, classification, report building, embedded binary scanning.

use crate::report::{
    compute_summary, ConfidenceTier, EvidenceSource, InventoryStatus, Report,
    ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::{progress, progress_timing};
use crate::vuln::{
    enrich_findings_with_nvd, epss_enrich_findings, kev_enrich_findings,
    map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use std::fs;
use std::io::Read;
use std::path::Path;
use tempfile::tempdir;
use walkdir::WalkDir;

use super::detect::{
    detect_android_metadata, detect_app_packages, detect_java_manifest,
    detect_nuspec, detect_wheel_metadata,
};

/// Maximum decompressed size per ZIP entry (2 GB) -- guards against zip bombs.
const MAX_ZIP_ENTRY_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Archive type detected from contents/extension.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ArchiveKind {
    AndroidApk,
    AndroidAab,
    JavaJar,
    JavaWar,
    JavaEar,
    PythonWheel,
    NuGet,
    Ipa,
    BrowserExtension,
    GenericZip,
}

impl ArchiveKind {
    fn label(&self) -> &'static str {
        match self {
            Self::AndroidApk => "android-apk",
            Self::AndroidAab => "android-aab",
            Self::JavaJar => "java-jar",
            Self::JavaWar => "java-war",
            Self::JavaEar => "java-ear",
            Self::PythonWheel => "python-wheel",
            Self::NuGet => "nuget",
            Self::Ipa => "ios-ipa",
            Self::BrowserExtension => "browser-extension",
            Self::GenericZip => "zip",
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a vulnerability report for a ZIP-based archive.
pub fn build_archive_report(
    path: &str,
    mode: ScanMode,
    nvd_api_key: Option<String>,
) -> Option<Report> {
    let started = std::time::Instant::now();
    progress("archive.extract.start", path);

    let tmp = tempdir().ok()?;
    if let Err(e) = extract_zip(path, tmp.path()) {
        progress("archive.extract.error", &format!("{}", e));
        return None;
    }
    progress_timing("archive.extract", started);
    progress("archive.extract.done", path);

    let kind = classify_archive(path, tmp.path());
    progress("archive.type", kind.label());

    // Detect packages from manifests inside the archive
    let pkg_started = std::time::Instant::now();
    progress("archive.packages.detect.start", "");
    let mut packages = detect_app_packages(tmp.path());

    // For Android archives, add the archive itself as an inventory item
    if matches!(kind, ArchiveKind::AndroidApk | ArchiveKind::AndroidAab) {
        detect_android_metadata(tmp.path(), &kind, &mut packages);
    }

    // For Java archives, parse META-INF/MANIFEST.MF
    if matches!(
        kind,
        ArchiveKind::JavaJar | ArchiveKind::JavaWar | ArchiveKind::JavaEar
    ) {
        detect_java_manifest(tmp.path(), &mut packages);
    }

    // For Python wheels, parse METADATA
    if kind == ArchiveKind::PythonWheel {
        detect_wheel_metadata(tmp.path(), &mut packages);
    }

    // For NuGet, parse .nuspec
    if kind == ArchiveKind::NuGet {
        detect_nuspec(tmp.path(), &mut packages);
    }

    // Scan embedded native binaries (.so, .dll, .dylib) via binary module
    let binary_findings = scan_embedded_binaries(tmp.path(), &mode, &nvd_api_key);

    progress_timing("archive.packages.detect", pkg_started);
    progress(
        "archive.packages.detect.done",
        &format!("packages={}", packages.len()),
    );

    // Enrichment pipeline -- same as container/sbom scans
    progress(
        "archive.osv.query.start",
        &format!("packages={}", packages.len()),
    );
    let osv_started = std::time::Instant::now();
    let osv_results = osv_batch_query(&packages);
    progress_timing("archive.osv.query", osv_started);
    progress("archive.osv.query.done", "ok");

    let mut findings = map_osv_results_to_findings(&packages, &osv_results);

    let osv_enrich_started = std::time::Instant::now();
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    osv_enrich_findings(&mut findings, &mut pg);
    progress_timing("archive.enrich.osv", osv_enrich_started);

    // NVD enrichment
    let nvd_started = std::time::Instant::now();
    progress(
        "archive.enrich.nvd.start",
        &format!("findings={}", findings.len()),
    );
    enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);
    progress_timing("archive.enrich.nvd", nvd_started);

    // EPSS + KEV
    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    epss_enrich_findings(&mut findings, cache_dir.as_deref());
    kev_enrich_findings(&mut findings, cache_dir.as_deref());

    // Merge binary findings
    findings.extend(binary_findings);

    let summary = compute_summary(&findings);
    progress(
        "archive.scan.done",
        &format!("findings={}", summary.total_findings),
    );
    progress_timing("archive.scan", started);

    Some(Report {
        scanner: ScannerInfo {
            name: "scanrook",
            version: env!("CARGO_PKG_VERSION"),
        },
        target: TargetInfo {
            target_type: format!("archive/{}", kind.label()),
            source: path.to_string(),
            id: None,
        },
        scan_status: ScanStatus::Complete,
        inventory_status: if packages.is_empty() {
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

// ---------------------------------------------------------------------------
// ZIP extraction with Zip Slip protection
// ---------------------------------------------------------------------------

fn extract_zip(path: &str, dest: &Path) -> anyhow::Result<()> {
    let file = fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        // Zip Slip protection: reject entries with path traversal
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            progress("archive.extract.skip", &format!("path_traversal: {}", name));
            continue;
        }

        let out_path = dest.join(&name);

        // Verify the resolved path is still under dest
        let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
        if let Ok(canonical_out) = out_path.canonicalize() {
            if !canonical_out.starts_with(&canonical_dest) {
                progress("archive.extract.skip", &format!("escape: {}", name));
                continue;
            }
        }

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
        } else {
            // Guard against zip bombs
            if entry.size() > MAX_ZIP_ENTRY_SIZE {
                progress(
                    "archive.extract.skip",
                    &format!("too_large: {} ({}B)", name, entry.size()),
                );
                continue;
            }

            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut out_file = fs::File::create(&out_path)?;
            let mut limited = entry.take(MAX_ZIP_ENTRY_SIZE);
            std::io::copy(&mut limited, &mut out_file)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive classification
// ---------------------------------------------------------------------------

pub(super) fn classify_archive(path: &str, extracted: &Path) -> ArchiveKind {
    let lower = path.to_lowercase();

    // Extension-based hints
    if lower.ends_with(".apk") && !lower.ends_with(".nupkg") {
        // Android APK (not Alpine APK which is a tar)
        if extracted.join("AndroidManifest.xml").exists() || extracted.join("classes.dex").exists()
        {
            return ArchiveKind::AndroidApk;
        }
    }
    if lower.ends_with(".aab") {
        return ArchiveKind::AndroidAab;
    }
    if lower.ends_with(".war") {
        return ArchiveKind::JavaWar;
    }
    if lower.ends_with(".ear") {
        return ArchiveKind::JavaEar;
    }
    if lower.ends_with(".jar") {
        return ArchiveKind::JavaJar;
    }
    if lower.ends_with(".whl") {
        return ArchiveKind::PythonWheel;
    }
    if lower.ends_with(".nupkg") {
        return ArchiveKind::NuGet;
    }
    if lower.ends_with(".ipa") {
        return ArchiveKind::Ipa;
    }
    if lower.ends_with(".xpi") || lower.ends_with(".crx") || lower.ends_with(".vsix") {
        return ArchiveKind::BrowserExtension;
    }

    // Content-based detection
    if extracted.join("AndroidManifest.xml").exists() || extracted.join("classes.dex").exists() {
        return ArchiveKind::AndroidApk;
    }
    if extracted.join("BundleConfig.pb").exists()
        || extracted.join("base/manifest/AndroidManifest.xml").exists()
    {
        return ArchiveKind::AndroidAab;
    }
    if extracted.join("META-INF/MANIFEST.MF").exists() {
        return ArchiveKind::JavaJar;
    }
    // Check for manifest.json with manifest_version (browser extension)
    if let Ok(text) = fs::read_to_string(extracted.join("manifest.json")) {
        if text.contains("manifest_version") {
            return ArchiveKind::BrowserExtension;
        }
    }

    ArchiveKind::GenericZip
}

// ---------------------------------------------------------------------------
// Embedded binary scanning
// ---------------------------------------------------------------------------

fn scan_embedded_binaries(
    root: &Path,
    _mode: &ScanMode,
    nvd_api_key: &Option<String>,
) -> Vec<crate::report::Finding> {
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
                    // Tag as heuristic since these are embedded
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
