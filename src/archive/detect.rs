//! Application-level package manifest detection (shared with container scans).

use crate::container::PackageCoordinate;
use super::parsers::*;
use super::push_if_new;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use serde_json;

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
            // Individual package.json inside node_modules directories (bundled apps, Electron, etc.)
            "package.json" => {
                if is_inside_node_modules(path) {
                    parse_node_package_json(path, &mut packages, &mut seen);
                }
            }

            // Python
            "requirements.txt" => parse_requirements_txt(path, &mut packages, &mut seen),
            "Pipfile.lock" => parse_pipfile_lock(path, &mut packages, &mut seen),
            "poetry.lock" => parse_poetry_lock(path, &mut packages, &mut seen),
            "METADATA" => {
                if path_contains_dist_info(path) {
                    parse_dist_info_metadata(path, &mut packages, &mut seen);
                    // Also check for LICENSE file in the same .dist-info directory
                    if let Some(dist_dir) = path.parent() {
                        for license_name in &["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"] {
                            let license_path = dist_dir.join(license_name);
                            if license_path.exists() {
                                if let Some(license) = detect_license_from_file(&license_path) {
                                    if let Some(last) = packages.last_mut() {
                                        if last.license.is_none() {
                                            last.license = Some(license);
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
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

    // Deep license scan: check LICENSE/COPYING files for packages missing license info
    scan_license_files(root, &mut packages, &mut seen);

    packages
}

// ---------------------------------------------------------------------------
// node_modules package.json scanner (for bundled apps, Electron apps, etc.)
// ---------------------------------------------------------------------------

/// Returns true if the given path is inside a node_modules directory.
fn is_inside_node_modules(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str() == "node_modules"
    })
}

/// Parse a package.json file inside node_modules and extract name + version.
/// Only parses direct package entries (not nested node_modules), skipping workspace
/// roots and packages without a version field.
fn parse_node_package_json(
    path: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
) {
    // The `seen` HashSet deduplicates by name+version, so we scan all
    // node_modules depths including nested ones.

    if let Ok(text) = fs::read_to_string(path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("").trim();
            let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("").trim();
            if !name.is_empty() && !version.is_empty() {
                let license = extract_npm_license(&val);
                super::push_if_new_with_license(pkgs, seen, "npm", name, version, license);
            }
        }
    }
}

/// Extract license from a package.json value. Handles both string and object forms.
fn extract_npm_license(pkg_json: &serde_json::Value) -> Option<String> {
    match pkg_json.get("license") {
        Some(serde_json::Value::String(s)) => {
            if s.is_empty() { None } else { Some(s.clone()) }
        }
        Some(serde_json::Value::Object(obj)) => {
            obj.get("type")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        }
        _ => None,
    }
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

// ---------------------------------------------------------------------------
// Deep license file scanning
// ---------------------------------------------------------------------------

/// Scan for LICENSE, COPYING, NOTICE files and try to identify the license.
/// This catches packages that don't declare their license in metadata.
fn scan_license_files(
    root: &Path,
    pkgs: &mut Vec<PackageCoordinate>,
    _seen: &mut HashSet<String>,
) {
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
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_uppercase(),
            None => continue,
        };

        // Only process license text files
        if !matches!(
            fname.as_str(),
            "LICENSE"
                | "LICENSE.TXT"
                | "LICENSE.MD"
                | "LICENCE"
                | "LICENCE.TXT"
                | "LICENCE.MD"
                | "COPYING"
                | "COPYING.TXT"
                | "NOTICE"
                | "NOTICE.TXT"
        ) {
            continue;
        }

        // Try to determine which package this belongs to
        if let Some(parent) = path.parent() {
            // If inside node_modules/foo/LICENSE, the package is "foo"
            if let Some(pkg_name) = get_node_modules_package_name(parent) {
                if let Some(license) = detect_license_from_file(path) {
                    // Update existing package's license if unknown
                    for pkg in pkgs.iter_mut() {
                        if pkg.ecosystem == "npm" && pkg.name == pkg_name && pkg.license.is_none() {
                            pkg.license = Some(license.clone());
                        }
                    }
                }
            }
        }
    }
}

/// Given a directory path, extract the package name if it's inside node_modules.
/// Handles scoped packages like @scope/name.
fn get_node_modules_package_name(dir: &Path) -> Option<String> {
    let components: Vec<_> = dir.components().collect();
    // Find the last node_modules segment and get the next component
    for (i, c) in components.iter().enumerate() {
        if c.as_os_str() == "node_modules" && i + 1 < components.len() {
            let pkg = components[i + 1].as_os_str().to_string_lossy().to_string();
            // Handle scoped packages: node_modules/@scope/name
            if pkg.starts_with('@') && i + 2 < components.len() {
                let scope_name = components[i + 2].as_os_str().to_string_lossy().to_string();
                return Some(format!("{}/{}", pkg, scope_name));
            }
            return Some(pkg);
        }
    }
    None
}

/// Detect the license from a LICENSE/COPYING/NOTICE file by reading its content.
fn detect_license_from_file(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    // Try Debian copyright format first (handles DEP-5 and common patterns)
    crate::container::parse_debian_copyright_license(&content)
        .or_else(|| detect_license_from_text(&content))
}

/// Heuristic license detection from raw license text.
fn detect_license_from_text(text: &str) -> Option<String> {
    let upper = text.to_uppercase();
    let first_500 = &upper[..upper.len().min(500)];

    // SPDX identifier in header
    if let Some(pos) = upper.find("SPDX-LICENSE-IDENTIFIER:") {
        let rest = &upper[pos + 24..];
        let end = rest.find('\n').unwrap_or(rest.len());
        let id = rest[..end].trim();
        if !id.is_empty() {
            return Some(id.to_string());
        }
    }

    // Common license text patterns
    if first_500.contains("MIT LICENSE")
        || first_500.contains("PERMISSION IS HEREBY GRANTED, FREE OF CHARGE")
    {
        return Some("MIT".to_string());
    }
    if first_500.contains("APACHE LICENSE") && first_500.contains("VERSION 2.0") {
        return Some("Apache-2.0".to_string());
    }
    if first_500.contains("ISC LICENSE")
        || (first_500.contains("ISC") && first_500.contains("PERMISSION TO USE"))
    {
        return Some("ISC".to_string());
    }
    if first_500.contains("BSD 2-CLAUSE") || first_500.contains("SIMPLIFIED BSD") {
        return Some("BSD-2-Clause".to_string());
    }
    if first_500.contains("BSD 3-CLAUSE")
        || first_500.contains("NEW BSD")
        || first_500.contains("MODIFIED BSD")
    {
        return Some("BSD-3-Clause".to_string());
    }
    if upper.contains("GNU GENERAL PUBLIC LICENSE") {
        if upper.contains("VERSION 3") {
            return Some("GPL-3.0".to_string());
        }
        if upper.contains("VERSION 2") {
            return Some("GPL-2.0".to_string());
        }
        return Some("GPL".to_string());
    }
    if upper.contains("GNU LESSER GENERAL PUBLIC") {
        return Some("LGPL".to_string());
    }
    if upper.contains("MOZILLA PUBLIC LICENSE") && upper.contains("2.0") {
        return Some("MPL-2.0".to_string());
    }
    if first_500.contains("UNLICENSE")
        || first_500.contains("THIS IS FREE AND UNENCUMBERED")
    {
        return Some("Unlicense".to_string());
    }
    if first_500.contains("CC0") || first_500.contains("CREATIVE COMMONS ZERO") {
        return Some("CC0-1.0".to_string());
    }
    if first_500.contains("0BSD") || first_500.contains("ZERO-CLAUSE BSD") {
        return Some("0BSD".to_string());
    }

    None
}
