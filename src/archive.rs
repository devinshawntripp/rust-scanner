//! ZIP-based archive scanning: APK, AAB, JAR, WAR, EAR, wheel, NuGet, IPA, extensions, etc.
//!
//! Also provides `detect_app_packages()` for application-level manifest detection,
//! shared between archive scans and container scans.

use crate::container::PackageCoordinate;
use crate::report::{
    compute_summary, ConfidenceTier, EvidenceItem, EvidenceSource, InventoryStatus, Report,
    ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::{progress, progress_timing};
use crate::vuln::{
    enrich_findings_with_nvd, epss_enrich_findings, kev_enrich_findings,
    map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use walkdir::WalkDir;

/// Maximum decompressed size per ZIP entry (2 GB) — guards against zip bombs.
const MAX_ZIP_ENTRY_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Archive type detected from contents/extension.
#[derive(Debug, Clone, PartialEq)]
enum ArchiveKind {
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

    // Enrichment pipeline — same as container/sbom scans
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
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        // Zip Slip protection: reject entries with path traversal
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            progress(
                "archive.extract.skip",
                &format!("path_traversal: {}", name),
            );
            continue;
        }

        let out_path = dest.join(&name);

        // Verify the resolved path is still under dest
        let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
        if let Ok(canonical_out) = out_path.canonicalize() {
            if !canonical_out.starts_with(&canonical_dest) {
                progress(
                    "archive.extract.skip",
                    &format!("escape: {}", name),
                );
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

fn classify_archive(path: &str, extracted: &Path) -> ArchiveKind {
    let lower = path.to_lowercase();

    // Extension-based hints
    if lower.ends_with(".apk") && !lower.ends_with(".nupkg") {
        // Android APK (not Alpine APK which is a tar)
        if extracted.join("AndroidManifest.xml").exists()
            || extracted.join("classes.dex").exists()
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
// Application-level package manifest detection (shared with container.rs)
// ---------------------------------------------------------------------------

/// Walk an extracted filesystem tree and detect application-level packages
/// from lock files and manifests. Usable from both archive and container scans.
pub fn detect_app_packages(root: &Path) -> Vec<PackageCoordinate> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Walk the tree, skip very deep paths and common junk
    for entry in WalkDir::new(root)
        .max_depth(12)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        match name {
            // npm / Node.js
            "package-lock.json" => parse_npm_lockfile(path, &mut packages, &mut seen),
            "yarn.lock" => parse_yarn_lock(path, &mut packages, &mut seen),
            "pnpm-lock.yaml" => parse_pnpm_lock(path, &mut packages, &mut seen),

            // Python
            "requirements.txt" => parse_requirements_txt(path, &mut packages, &mut seen),
            "Pipfile.lock" => parse_pipfile_lock(path, &mut packages, &mut seen),
            "poetry.lock" => parse_poetry_lock(path, &mut packages, &mut seen),
            "METADATA" => {
                if path_contains_dist_info(path) {
                    parse_dist_info_metadata(path, &mut packages, &mut seen);
                }
            }

            // Ruby
            "Gemfile.lock" => parse_gemfile_lock(path, &mut packages, &mut seen),

            // Go
            "go.sum" => parse_go_sum(path, &mut packages, &mut seen),
            "go.mod" => parse_go_mod(path, &mut packages, &mut seen),

            // Rust
            "Cargo.lock" => parse_cargo_lock(path, &mut packages, &mut seen),

            // Java / Maven / Gradle
            "pom.xml" => parse_pom_xml(path, &mut packages, &mut seen),
            "gradle.lockfile" => parse_gradle_lockfile(path, &mut packages, &mut seen),

            // NuGet / .NET
            "packages.config" => parse_nuget_packages_config(path, &mut packages, &mut seen),

            // PHP
            "composer.lock" => parse_composer_lock(path, &mut packages, &mut seen),

            // Dart / Flutter
            "pubspec.lock" => parse_pubspec_lock(path, &mut packages, &mut seen),

            // Swift
            "Package.resolved" => parse_swift_resolved(path, &mut packages, &mut seen),

            // CocoaPods
            "Podfile.lock" => parse_podfile_lock(path, &mut packages, &mut seen),

            // Elixir
            "mix.lock" => parse_mix_lock(path, &mut packages, &mut seen),

            _ => {
                // .csproj files with PackageReference
                if name.ends_with(".csproj") {
                    parse_csproj(path, &mut packages, &mut seen);
                }
            }
        }
    }

    packages
}

// ---------------------------------------------------------------------------
// Helper: dedup key
// ---------------------------------------------------------------------------

fn pkg_key(eco: &str, name: &str, version: &str) -> String {
    format!("{}:{}:{}", eco, name, version)
}

fn push_if_new(
    packages: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
    ecosystem: &str,
    name: &str,
    version: &str,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    let key = pkg_key(ecosystem, name, version);
    if seen.insert(key) {
        packages.push(PackageCoordinate {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// npm parsers
// ---------------------------------------------------------------------------

fn parse_npm_lockfile(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return,
    };

    // lockfileVersion 2/3 uses "packages" map
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            if key.is_empty() {
                continue; // root package
            }
            let name = key
                .strip_prefix("node_modules/")
                .unwrap_or(key)
                .to_string();
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            push_if_new(pkgs, seen, "npm", &name, &version);
        }
    }
    // lockfileVersion 1 uses "dependencies" map
    else if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        parse_npm_v1_deps(deps, pkgs, seen);
    }
}

fn parse_npm_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    for (name, val) in deps {
        let version = val
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        push_if_new(pkgs, seen, "npm", name, version);
        // Nested deps
        if let Some(sub) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_deps(sub, pkgs, seen);
        }
    }
}

fn parse_yarn_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // yarn.lock format: "name@version:" header followed by "  version \"x.y.z\""
    let mut current_name = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // Header line like: "lodash@^4.17.0, lodash@^4.17.21:"
            // Extract the package name from the first entry
            if let Some(at) = trimmed.find('@') {
                // Handle scoped packages (@scope/name@version)
                let rest = &trimmed[..trimmed.len().saturating_sub(1)]; // remove trailing ':'
                let name = if rest.starts_with('"') {
                    let unquoted = rest.trim_matches('"');
                    // Find the last @ that separates name from version spec
                    if let Some(last_at) = unquoted.rfind('@') {
                        if last_at > 0 {
                            &unquoted[..last_at]
                        } else {
                            unquoted
                        }
                    } else {
                        unquoted
                    }
                } else if let Some(comma) = rest.find(',') {
                    let first = &rest[..comma];
                    if let Some(last_at) = first.rfind('@') {
                        &first[..last_at]
                    } else {
                        first
                    }
                } else if let Some(last_at) = rest.rfind('@') {
                    &rest[..last_at]
                } else {
                    rest
                };
                current_name = name.trim_matches('"').to_string();
            }
        } else if trimmed.starts_with("version ") {
            let version = trimmed
                .strip_prefix("version ")
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            if !current_name.is_empty() {
                push_if_new(pkgs, seen, "npm", &current_name, version);
            }
        }
    }
}

fn parse_pnpm_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Simple pnpm-lock.yaml parser: look for lines like /package-name@version: or /package-name/version:
    for line in text.lines() {
        let trimmed = line.trim().trim_start_matches('\'').trim_end_matches('\'');
        // pnpm v9+ format: 'package-name@version':
        if let Some(rest) = trimmed.strip_prefix('/') {
            // /name/version: or /name@version:
            let entry = rest.trim_end_matches(':');
            if let Some((name, version)) = entry.rsplit_once('@') {
                let version = version.split('(').next().unwrap_or(version); // strip peer deps
                push_if_new(pkgs, seen, "npm", name, version);
            } else if let Some((name, version)) = entry.rsplit_once('/') {
                if !version.is_empty()
                    && version.chars().next().map_or(false, |c| c.is_ascii_digit())
                {
                    push_if_new(pkgs, seen, "npm", name, version);
                }
            }
        }
        // pnpm v9 uses package-name@version: (without leading /)
        if !trimmed.starts_with('/') && !trimmed.starts_with('#') && !trimmed.starts_with(' ') {
            let entry = trimmed.trim_end_matches(':');
            if let Some((name, version)) = entry.rsplit_once('@') {
                if !name.is_empty()
                    && !version.is_empty()
                    && version.chars().next().map_or(false, |c| c.is_ascii_digit())
                {
                    let version = version.split('(').next().unwrap_or(version);
                    push_if_new(pkgs, seen, "npm", name, version);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Python parsers
// ---------------------------------------------------------------------------

fn parse_requirements_txt(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        // name==version or name>=version or name~=version
        if let Some(idx) = trimmed.find("==") {
            let name = trimmed[..idx].trim();
            let version = trimmed[idx + 2..].trim().split(';').next().unwrap_or("").trim();
            push_if_new(pkgs, seen, "PyPI", name, version);
        }
    }
}

fn parse_pipfile_lock(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return,
    };
    for section in &["default", "develop"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (name, val) in deps {
                let version = val
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .strip_prefix("==")
                    .unwrap_or("");
                push_if_new(pkgs, seen, "PyPI", name, version);
            }
        }
    }
}

fn parse_poetry_lock(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Simple TOML-like parser for [[package]] blocks
    let mut current_name = String::new();
    let mut current_version = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if !current_name.is_empty() && !current_version.is_empty() {
                push_if_new(pkgs, seen, "PyPI", &current_name, &current_version);
            }
            current_name.clear();
            current_version.clear();
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = rest.trim_matches('"').to_string();
        }
    }
    if !current_name.is_empty() && !current_version.is_empty() {
        push_if_new(pkgs, seen, "PyPI", &current_name, &current_version);
    }
}

fn path_contains_dist_info(path: &Path) -> bool {
    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map_or(false, |n| n.ends_with(".dist-info"))
}

fn parse_dist_info_metadata(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut name = String::new();
    let mut version = String::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with(' ') {
            // End of headers
            if !line.starts_with(' ') {
                break;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("Name: ") {
            name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Version: ") {
            version = rest.trim().to_string();
        }
    }
    push_if_new(pkgs, seen, "PyPI", &name, &version);
}

// ---------------------------------------------------------------------------
// Ruby parser
// ---------------------------------------------------------------------------

fn parse_gemfile_lock(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut in_specs = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if in_specs {
            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_specs = false;
                continue;
            }
            // Lines like "    actionpack (7.1.2)"
            let parts = trimmed.trim();
            if let Some(paren) = parts.find('(') {
                let name = parts[..paren].trim();
                let version = parts[paren + 1..]
                    .trim_end_matches(')')
                    .trim();
                if !name.contains(' ') {
                    push_if_new(pkgs, seen, "RubyGems", name, version);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Go parsers
// ---------------------------------------------------------------------------

fn parse_go_sum(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let module = parts[0];
            let version_with_v = parts[1].strip_suffix("/go.mod").unwrap_or(parts[1]);
            push_if_new(pkgs, seen, "Go", module, version_with_v);
        }
    }
}

fn parse_go_mod(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut in_require = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" {
            in_require = false;
            continue;
        }
        if in_require {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && !parts[0].starts_with("//") {
                push_if_new(pkgs, seen, "Go", parts[0], parts[1]);
            }
        }
        // Single-line require
        if let Some(rest) = trimmed.strip_prefix("require ") {
            if !rest.starts_with('(') {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    push_if_new(pkgs, seen, "Go", parts[0], parts[1]);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rust parser
// ---------------------------------------------------------------------------

fn parse_cargo_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut current_name = String::new();
    let mut current_version = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if !current_name.is_empty() && !current_version.is_empty() {
                push_if_new(pkgs, seen, "crates.io", &current_name, &current_version);
            }
            current_name.clear();
            current_version.clear();
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = rest.trim_matches('"').to_string();
        }
    }
    if !current_name.is_empty() && !current_version.is_empty() {
        push_if_new(pkgs, seen, "crates.io", &current_name, &current_version);
    }
}

// ---------------------------------------------------------------------------
// Java / Maven / Gradle parsers
// ---------------------------------------------------------------------------

fn parse_pom_xml(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Simple regex-based extraction of <dependency> blocks
    let re = regex::Regex::new(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?"
    ).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let group = cap.get(1).map_or("", |m| m.as_str());
            let artifact = cap.get(2).map_or("", |m| m.as_str());
            let version = cap.get(3).map_or("", |m| m.as_str());
            let name = format!("{}:{}", group, artifact);
            push_if_new(pkgs, seen, "Maven", &name, version);
        }
    }
}

fn parse_gradle_lockfile(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Format: group:artifact:version=configuration
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let entry = trimmed.split('=').next().unwrap_or(trimmed);
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() >= 3 {
            let name = format!("{}:{}", parts[0], parts[1]);
            push_if_new(pkgs, seen, "Maven", &name, parts[2]);
        }
    }
}

// ---------------------------------------------------------------------------
// NuGet / .NET parsers
// ---------------------------------------------------------------------------

fn parse_nuget_packages_config(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // <package id="Newtonsoft.Json" version="13.0.1" ... />
    let re = regex::Regex::new(r#"<package\s+id="([^"]+)"\s+version="([^"]+)""#).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());
            push_if_new(pkgs, seen, "NuGet", name, version);
        }
    }
}

fn parse_csproj(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    let re =
        regex::Regex::new(r#"<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)""#).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());
            push_if_new(pkgs, seen, "NuGet", name, version);
        }
    }
}

// ---------------------------------------------------------------------------
// PHP parser
// ---------------------------------------------------------------------------

fn parse_composer_lock(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return,
    };
    for section in &["packages", "packages-dev"] {
        if let Some(arr) = json.get(section).and_then(|p| p.as_array()) {
            for pkg in arr {
                let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim_start_matches('v');
                push_if_new(pkgs, seen, "Packagist", name, version);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dart / Flutter parser
// ---------------------------------------------------------------------------

fn parse_pubspec_lock(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // pubspec.lock YAML format:
    //   packages:
    //     package_name:
    //       dependency: ...
    //       version: "1.2.3"
    let mut in_packages = false;
    let mut current_name = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        if in_packages {
            // Top-level package names are indented 2 spaces
            if line.starts_with("  ") && !line.starts_with("    ") {
                current_name = trimmed.trim_end_matches(':').to_string();
            }
            // Version is indented 4 spaces
            if line.starts_with("      version:") || line.starts_with("    version:") {
                if let Some(rest) = trimmed.strip_prefix("version:") {
                    let version = rest.trim().trim_matches('"');
                    if !current_name.is_empty() {
                        push_if_new(pkgs, seen, "Pub", &current_name, version);
                    }
                }
            }
            // Exit packages section
            if !line.starts_with(' ') && !trimmed.is_empty() && trimmed != "packages:" {
                in_packages = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Swift Package Manager parser
// ---------------------------------------------------------------------------

fn parse_swift_resolved(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return,
    };
    // v2 format: { "pins": [ { "identity": "...", "state": { "version": "..." } } ] }
    // v1 format: { "object": { "pins": [...] } }
    let pins = json
        .get("pins")
        .or_else(|| json.get("object").and_then(|o| o.get("pins")));
    if let Some(pins) = pins.and_then(|p| p.as_array()) {
        for pin in pins {
            let name = pin
                .get("identity")
                .or_else(|| pin.get("package"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let version = pin
                .get("state")
                .and_then(|s| s.get("version").or_else(|| s.get("checkoutState").and_then(|c| c.get("version"))))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            push_if_new(pkgs, seen, "SwiftURL", name, version);
        }
    }
}

// ---------------------------------------------------------------------------
// CocoaPods parser
// ---------------------------------------------------------------------------

fn parse_podfile_lock(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut in_pods = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "PODS:" {
            in_pods = true;
            continue;
        }
        if in_pods {
            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_pods = false;
                continue;
            }
            // "  - AFNetworking (4.0.1):" or "  - AFNetworking (4.0.1)"
            if let Some(rest) = trimmed.strip_prefix("- ") {
                if let Some(paren) = rest.find('(') {
                    let name = rest[..paren].trim();
                    let version = rest[paren + 1..]
                        .split(')')
                        .next()
                        .unwrap_or("")
                        .trim();
                    push_if_new(pkgs, seen, "CocoaPods", name, version);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Elixir parser
// ---------------------------------------------------------------------------

fn parse_mix_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Format: %{"dep_name": {:hex, :dep_name, "version", ...}}
    let re = regex::Regex::new(r#""([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)""#).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());
            push_if_new(pkgs, seen, "Hex", name, version);
        }
    }
}

// ---------------------------------------------------------------------------
// NuGet .nuspec parser (for .nupkg archives)
// ---------------------------------------------------------------------------

fn detect_nuspec(root: &Path, pkgs: &mut Vec<PackageCoordinate>) {
    let mut seen = HashSet::new();
    for entry in WalkDir::new(root)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map_or(false, |e| e == "nuspec")
        {
            if let Ok(text) = fs::read_to_string(path) {
                // <id>PackageName</id> <version>1.0.0</version>
                let id_re = regex::Regex::new(r"<id>([^<]+)</id>").ok();
                let ver_re = regex::Regex::new(r"<version>([^<]+)</version>").ok();
                if let (Some(id_re), Some(ver_re)) = (id_re, ver_re) {
                    let id = id_re
                        .captures(&text)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str())
                        .unwrap_or("");
                    let version = ver_re
                        .captures(&text)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str())
                        .unwrap_or("");
                    push_if_new(pkgs, &mut seen, "NuGet", id, version);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Android-specific detectors
// ---------------------------------------------------------------------------

fn detect_android_metadata(
    root: &Path,
    kind: &ArchiveKind,
    pkgs: &mut Vec<PackageCoordinate>,
) {
    let mut seen = HashSet::new();

    // Detect Flutter apps
    let is_flutter = match kind {
        ArchiveKind::AndroidApk => {
            // APK: lib/*/libflutter.so
            WalkDir::new(root.join("lib"))
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
                .any(|e| {
                    e.file_name()
                        .to_str()
                        .map_or(false, |n| n == "libflutter.so")
                })
        }
        ArchiveKind::AndroidAab => {
            // AAB: base/lib/*/libflutter.so
            WalkDir::new(root.join("base/lib"))
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
                .any(|e| {
                    e.file_name()
                        .to_str()
                        .map_or(false, |n| n == "libflutter.so")
                })
        }
        _ => false,
    };

    if is_flutter {
        progress("archive.android.flutter", "detected");
    }

    // Look for gradle.lockfile or build metadata
    for entry in WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let name = entry.file_name().to_str().unwrap_or("");
        if name == "gradle.lockfile" {
            parse_gradle_lockfile(entry.path(), pkgs, &mut seen);
        }
        if name == "pubspec.lock" {
            parse_pubspec_lock(entry.path(), pkgs, &mut seen);
        }
    }
}

// ---------------------------------------------------------------------------
// Java manifest parser (META-INF/MANIFEST.MF)
// ---------------------------------------------------------------------------

fn detect_java_manifest(root: &Path, pkgs: &mut Vec<PackageCoordinate>) {
    let mut seen = HashSet::new();
    let manifest = root.join("META-INF/MANIFEST.MF");
    if let Ok(text) = fs::read_to_string(&manifest) {
        let mut bundle_name = String::new();
        let mut bundle_version = String::new();
        let mut impl_title = String::new();
        let mut impl_version = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Bundle-SymbolicName: ") {
                bundle_name = rest.split(';').next().unwrap_or("").trim().to_string();
            } else if let Some(rest) = line.strip_prefix("Bundle-Version: ") {
                bundle_version = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("Implementation-Title: ") {
                impl_title = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("Implementation-Version: ") {
                impl_version = rest.trim().to_string();
            }
        }
        let name = if !bundle_name.is_empty() {
            &bundle_name
        } else {
            &impl_title
        };
        let version = if !bundle_version.is_empty() {
            &bundle_version
        } else {
            &impl_version
        };
        push_if_new(pkgs, &mut seen, "Maven", name, version);
    }

    // Also scan for embedded JARs (WAR/EAR lib directories)
    let lib_dirs = ["WEB-INF/lib", "lib", "BOOT-INF/lib"];
    for lib_dir in &lib_dirs {
        let dir = root.join(lib_dir);
        if dir.is_dir() {
            for entry in WalkDir::new(&dir)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".jar") {
                        // Extract groupId:artifactId-version from JAR filename
                        if let Some((artifact, version)) = parse_jar_filename(name) {
                            push_if_new(pkgs, &mut seen, "Maven", &artifact, &version);
                        }
                    }
                }
            }
        }
    }
}

fn parse_jar_filename(filename: &str) -> Option<(String, String)> {
    let name = filename.strip_suffix(".jar")?;
    // Try to split at the last hyphen followed by a digit: artifact-1.2.3
    let mut split_idx = None;
    for (i, _) in name.match_indices('-') {
        if name[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            split_idx = Some(i);
        }
    }
    if let Some(idx) = split_idx {
        Some((name[..idx].to_string(), name[idx + 1..].to_string()))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Python wheel METADATA parser
// ---------------------------------------------------------------------------

fn detect_wheel_metadata(root: &Path, pkgs: &mut Vec<PackageCoordinate>) {
    let mut seen = HashSet::new();
    for entry in WalkDir::new(root)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some("METADATA") {
            if path_contains_dist_info(path) {
                parse_dist_info_metadata(path, pkgs, &mut seen);
            }
        }
    }
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
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

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

// ---------------------------------------------------------------------------
// DMG extraction (macOS)
// ---------------------------------------------------------------------------

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
                    .args(["-R", &format!("{}/.", mount_point.to_string_lossy()), &copy_dest.to_string_lossy()])
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
pub fn build_dmg_report(
    path: &str,
    mode: ScanMode,
    nvd_api_key: Option<String>,
) -> Option<Report> {
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
    let binary_findings = scan_embedded_binaries(scan_root, &mode, &nvd_api_key);
    progress_timing("dmg.packages.detect", pkg_started);
    progress(
        "dmg.packages.detect.done",
        &format!("packages={}", packages.len()),
    );

    // Enrichment pipeline
    let osv_started = std::time::Instant::now();
    let osv_results = osv_batch_query(&packages);
    progress_timing("dmg.osv.query", osv_started);

    let mut findings = map_osv_results_to_findings(&packages, &osv_results);

    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    osv_enrich_findings(&mut findings, &mut pg);
    enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    epss_enrich_findings(&mut findings, cache_dir.as_deref());
    kev_enrich_findings(&mut findings, cache_dir.as_deref());

    findings.extend(binary_findings);

    let summary = compute_summary(&findings);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_if_new_deduplicates() {
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        push_if_new(&mut pkgs, &mut seen, "npm", "lodash", "4.17.21");
        push_if_new(&mut pkgs, &mut seen, "npm", "lodash", "4.17.21");
        push_if_new(&mut pkgs, &mut seen, "npm", "lodash", "4.17.20");
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn test_push_if_new_skips_empty() {
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        push_if_new(&mut pkgs, &mut seen, "npm", "", "1.0.0");
        push_if_new(&mut pkgs, &mut seen, "npm", "foo", "");
        assert_eq!(pkgs.len(), 0);
    }

    #[test]
    fn test_parse_requirements_txt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "flask==2.3.0\nrequests==2.31.0\n# comment\npytest>=7.0\n",
        )
        .unwrap();
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        parse_requirements_txt(&path, &mut pkgs, &mut seen);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "flask");
        assert_eq!(pkgs[0].version, "2.3.0");
        assert_eq!(pkgs[0].ecosystem, "PyPI");
    }

    #[test]
    fn test_parse_cargo_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("Cargo.lock");
        fs::write(
            &path,
            r#"[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "tokio"
version = "1.38.0"
"#,
        )
        .unwrap();
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        parse_cargo_lock(&path, &mut pkgs, &mut seen);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "crates.io");
        assert_eq!(pkgs[0].name, "serde");
    }

    #[test]
    fn test_parse_gemfile_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("Gemfile.lock");
        fs::write(
            &path,
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.1.2)\n    rails (7.1.2)\n\nPLATFORMS\n  ruby\n",
        )
        .unwrap();
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        parse_gemfile_lock(&path, &mut pkgs, &mut seen);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "RubyGems");
    }

    #[test]
    fn test_parse_go_mod() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("go.mod");
        fs::write(
            &path,
            "module example.com/mymod\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/text v0.14.0\n)\n",
        )
        .unwrap();
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        parse_go_mod(&path, &mut pkgs, &mut seen);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "Go");
    }

    #[test]
    fn test_parse_pubspec_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pubspec.lock");
        fs::write(
            &path,
            "packages:\n  cupertino_icons:\n    dependency: direct main\n    version: \"1.0.6\"\n  flutter:\n    dependency: direct main\n    version: \"0.0.0\"\n",
        )
        .unwrap();
        let mut pkgs = Vec::new();
        let mut seen = HashSet::new();
        parse_pubspec_lock(&path, &mut pkgs, &mut seen);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "Pub");
        assert_eq!(pkgs[0].name, "cupertino_icons");
    }

    #[test]
    fn test_parse_jar_filename() {
        assert_eq!(
            parse_jar_filename("spring-core-6.1.0.jar"),
            Some(("spring-core".to_string(), "6.1.0".to_string()))
        );
        assert_eq!(
            parse_jar_filename("jackson-databind-2.15.3.jar"),
            Some(("jackson-databind".to_string(), "2.15.3".to_string()))
        );
        assert_eq!(parse_jar_filename("noversion.jar"), None);
    }

    #[test]
    fn test_classify_archive_by_extension() {
        let dir = tempdir().unwrap();
        assert_eq!(
            classify_archive("test.whl", dir.path()),
            ArchiveKind::PythonWheel
        );
        assert_eq!(
            classify_archive("test.aab", dir.path()),
            ArchiveKind::AndroidAab
        );
        assert_eq!(
            classify_archive("test.nupkg", dir.path()),
            ArchiveKind::NuGet
        );
        assert_eq!(
            classify_archive("test.jar", dir.path()),
            ArchiveKind::JavaJar
        );
    }

    #[test]
    fn test_detect_app_packages_walks_tree() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("app");
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            sub.join("requirements.txt"),
            "flask==2.3.0\nrequests==2.31.0\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .unwrap();
        let pkgs = detect_app_packages(dir.path());
        assert_eq!(pkgs.len(), 3); // flask, requests, serde
    }
}
