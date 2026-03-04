//! Application-level package manifest detection (shared with container scans).

use crate::container::PackageCoordinate;
use super::parsers::*;
use super::push_if_new;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

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
// Android-specific detectors
// ---------------------------------------------------------------------------

pub(super) fn detect_android_metadata(root: &Path, kind: &super::scan::ArchiveKind, pkgs: &mut Vec<PackageCoordinate>) {
    let mut seen = HashSet::new();

    // Detect Flutter apps
    let is_flutter = match kind {
        super::scan::ArchiveKind::AndroidApk => {
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
        super::scan::ArchiveKind::AndroidAab => {
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
        crate::utils::progress("archive.android.flutter", "detected");
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

pub(super) fn detect_java_manifest(root: &Path, pkgs: &mut Vec<PackageCoordinate>) {
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

pub(super) fn parse_jar_filename(filename: &str) -> Option<(String, String)> {
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

pub(super) fn detect_wheel_metadata(root: &Path, pkgs: &mut Vec<PackageCoordinate>) {
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
// NuGet .nuspec parser (for .nupkg archives)
// ---------------------------------------------------------------------------

pub(super) fn detect_nuspec(root: &Path, pkgs: &mut Vec<PackageCoordinate>) {
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
// macOS .app bundle and .pkg installer detection
// ---------------------------------------------------------------------------

/// Walk an extracted filesystem tree and detect macOS-native packages:
/// - `.app` bundles via `Contents/Info.plist` (CFBundleIdentifier + version)
/// - Embedded `.framework` bundles inside `.app/Contents/Frameworks/`
/// - `.pkg` flat-package installers via apple-flat-package crate (PackageInfo XML)
pub fn detect_macos_packages(root: &Path) -> Vec<PackageCoordinate> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Detect .app bundles via Info.plist
    for entry in WalkDir::new(root)
        .max_depth(8)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("app") && path.is_dir() {
            let plist_path = path.join("Contents/Info.plist");
            if plist_path.exists() {
                if let Some((name, version)) = parse_app_info_plist(&plist_path) {
                    push_if_new(&mut packages, &mut seen, "mac-app", &name, &version);
                }
                // Scan embedded frameworks
                let frameworks_dir = path.join("Contents/Frameworks");
                if frameworks_dir.is_dir() {
                    detect_embedded_frameworks(&frameworks_dir, &mut packages, &mut seen);
                }
            }
        }
    }

    // Detect .pkg flat-package installers
    detect_pkg_installers(root, &mut packages, &mut seen);

    packages
}

/// Parse an Info.plist file and return (bundle_identifier_or_name, version).
/// Uses CFBundleIdentifier (preferred) or CFBundleName for the name.
/// Uses CFBundleShortVersionString (preferred) or CFBundleVersion for version.
/// Returns None if neither a name nor a version can be extracted.
fn parse_app_info_plist(plist_path: &Path) -> Option<(String, String)> {
    use plist::Value;
    let val = Value::from_file(plist_path).ok()?;
    let dict = val.as_dictionary()?;
    let name = dict
        .get("CFBundleIdentifier")
        .or_else(|| dict.get("CFBundleName"))
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())?;
    // Use CFBundleShortVersionString (human version), fall back to CFBundleVersion (build number)
    let version = dict
        .get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Some((name, version))
}

/// Scan a Frameworks directory for embedded .framework bundles and emit mac-framework packages.
fn detect_embedded_frameworks(
    frameworks_dir: &Path,
    packages: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    for entry in WalkDir::new(frameworks_dir)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("framework") && path.is_dir() {
            // Framework Info.plist is at Framework.framework/Resources/Info.plist
            // or Framework.framework/Versions/Current/Resources/Info.plist
            let candidates = [
                path.join("Resources/Info.plist"),
                path.join("Versions/Current/Resources/Info.plist"),
            ];
            for plist_path in &candidates {
                if plist_path.exists() {
                    if let Some((name, version)) = parse_app_info_plist(plist_path) {
                        push_if_new(packages, seen, "mac-framework", &name, &version);
                    }
                    break;
                }
            }
        }
    }
}

/// Scan for Apple flat-package (.pkg) installers and emit mac-pkg packages.
/// Uses the apple-flat-package crate to parse PackageInfo XML for identifier + version.
fn detect_pkg_installers(
    root: &Path,
    packages: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    use apple_flat_package::reader::PkgReader;
    use std::fs::File;

    for entry in WalkDir::new(root)
        .max_depth(8)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("pkg") && path.is_file() {
            let file = match File::open(path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut reader = match PkgReader::new(file) {
                Ok(r) => r,
                Err(e) => {
                    // Not a valid flat package (could be old .pkg format) — skip silently
                    crate::utils::progress(
                        "dmg.pkg.skip",
                        &format!("{}: {}", path.display(), e),
                    );
                    continue;
                }
            };
            // Try root component first (component packages like those built with pkgbuild)
            if let Ok(Some(comp)) = reader.root_component() {
                if let Some(info) = comp.package_info() {
                    let name = &info.identifier;
                    let version = &info.version;
                    if !name.is_empty() && !version.is_empty() {
                        push_if_new(packages, seen, "mac-pkg", name, version);
                    }
                }
            }
            // Also try component packages within product packages (built with productbuild)
            if let Ok(components) = reader.component_packages() {
                for comp in components {
                    if let Some(info) = comp.package_info() {
                        let name = &info.identifier;
                        let version = &info.version;
                        if !name.is_empty() && !version.is_empty() {
                            push_if_new(packages, seen, "mac-pkg", name, version);
                        }
                    }
                }
            }
        }
    }
}
