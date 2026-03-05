use super::*;
use super::detect::parse_jar_filename;
use super::scan::ArchiveKind;
use super::parsers::*;
use std::collections::HashSet;
use std::fs;
use tempfile::tempdir;

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
        "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.38.0\"\n",
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
        super::scan::classify_archive("test.whl", dir.path()),
        ArchiveKind::PythonWheel
    );
    assert_eq!(
        super::scan::classify_archive("test.aab", dir.path()),
        ArchiveKind::AndroidAab
    );
    assert_eq!(
        super::scan::classify_archive("test.nupkg", dir.path()),
        ArchiveKind::NuGet
    );
    assert_eq!(
        super::scan::classify_archive("test.jar", dir.path()),
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
    let pkgs = detect::detect_app_packages(dir.path());
    assert_eq!(pkgs.len(), 3); // flask, requests, serde
}

// ---------------------------------------------------------------------------
// macOS .app bundle and .pkg installer detection tests
// ---------------------------------------------------------------------------

use super::detect::detect_macos_packages;

#[test]
fn test_detect_macos_empty_dir() {
    let dir = tempdir().unwrap();
    let pkgs = detect_macos_packages(dir.path());
    assert!(pkgs.is_empty(), "empty dir should yield no packages");
}

#[test]
fn test_detect_macos_app_bundle() {
    let dir = tempdir().unwrap();
    // Create TestApp.app/Contents/Info.plist
    let app_dir = dir.path().join("TestApp.app/Contents");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(
        app_dir.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1.0</string>
</dict>
</plist>"#,
    )
    .unwrap();
    let pkgs = detect_macos_packages(dir.path());
    assert_eq!(pkgs.len(), 1, "expected 1 package from .app bundle");
    assert_eq!(pkgs[0].ecosystem, "mac-app");
    assert_eq!(pkgs[0].name, "com.test.app");
    assert_eq!(pkgs[0].version, "2.1.0");
}

#[test]
fn test_detect_macos_app_bundle_fallback_version() {
    // Only CFBundleVersion present (no CFBundleShortVersionString)
    let dir = tempdir().unwrap();
    let app_dir = dir.path().join("MyApp.app/Contents");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(
        app_dir.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.fallback</string>
    <key>CFBundleVersion</key>
    <string>42</string>
</dict>
</plist>"#,
    )
    .unwrap();
    let pkgs = detect_macos_packages(dir.path());
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0].ecosystem, "mac-app");
    assert_eq!(pkgs[0].name, "com.test.fallback");
    assert_eq!(pkgs[0].version, "42");
}

#[test]
fn test_detect_macos_app_bundle_with_framework() {
    let dir = tempdir().unwrap();

    // Create TestApp.app with Contents/Info.plist
    let app_dir = dir.path().join("TestApp.app/Contents");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(
        app_dir.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.mainapp</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
</dict>
</plist>"#,
    )
    .unwrap();

    // Create embedded framework at Contents/Frameworks/MyFramework.framework/Resources/Info.plist
    let fw_dir = dir.path().join("TestApp.app/Contents/Frameworks/MyFramework.framework/Resources");
    fs::create_dir_all(&fw_dir).unwrap();
    fs::write(
        fw_dir.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.framework</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
</dict>
</plist>"#,
    )
    .unwrap();

    let pkgs = detect_macos_packages(dir.path());
    assert_eq!(pkgs.len(), 2, "expected app + framework = 2 packages");
    let ecosystems: Vec<&str> = pkgs.iter().map(|p| p.ecosystem.as_str()).collect();
    assert!(ecosystems.contains(&"mac-app"), "should contain mac-app");
    assert!(ecosystems.contains(&"mac-framework"), "should contain mac-framework");
}

#[test]
fn test_detect_macos_no_version_gets_unknown() {
    // App with identifier but no version keys — returns "unknown" version
    let dir = tempdir().unwrap();
    let app_dir = dir.path().join("NoVersion.app/Contents");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(
        app_dir.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.noversion</string>
</dict>
</plist>"#,
    )
    .unwrap();
    let pkgs = detect_macos_packages(dir.path());
    // push_if_new skips entries where version is empty, but "unknown" is not empty.
    // The parse_app_info_plist function returns "unknown" when no version key is present.
    assert_eq!(pkgs.len(), 1, "should return 1 package with 'unknown' version");
    assert_eq!(pkgs[0].version, "unknown");
}

// ---------------------------------------------------------------------------
// DMG extraction fallback chain tests
// ---------------------------------------------------------------------------

#[test]
fn test_dmg_native_extraction_always_bails() {
    // try_extract_dmg_native() requires dmgwiz (UDIF parsing) + hpcopy (HFS+ extraction).
    // In test/CI environments without hpcopy installed, it bails at the hpcopy check.
    // In environments with hpcopy but a non-existent file, it bails at dmgwiz parsing.
    // Either way, it MUST return Err so the fallback chain (hdiutil -> 7z) is reached.
    let dir = tempdir().unwrap();
    let result = super::dmg::try_extract_dmg_native("fake.dmg", dir.path());
    assert!(result.is_err(), "native extraction must always bail on missing/invalid input");
    let err_msg = format!("{}", result.unwrap_err());
    // Error message should describe the failure (hpcopy not installed, or dmgwiz parse error)
    assert!(
        err_msg.contains("hpcopy") || err_msg.contains("dmgwiz") || err_msg.contains("hfsutils")
            || err_msg.contains("failed to open") || err_msg.contains("partition"),
        "error message should describe the native extraction failure, got: {err_msg}"
    );
}

#[test]
fn test_dmg_extract_nonexistent_file_returns_error() {
    // extract_dmg() on a non-existent file should always return a structured
    // Err — never panic. On CI (with 7z) this will be a 7z error; on dev machines
    // without 7z it will be the "Neither was found" error. Both are acceptable.
    let dir = tempdir().unwrap();
    let result = super::dmg::extract_dmg("/nonexistent/path/file.dmg", dir.path());
    assert!(result.is_err(), "extract_dmg on missing file must return Err");
}

#[test]
fn test_dmg_build_report_extraction_failure_returns_some() {
    // build_dmg_report MUST return Some even when extraction fails.
    // Per the graceful degradation design: extraction failure falls through to
    // binary-only scanning with empty packages. The result is a valid (but empty)
    // report, not None.
    let dir = tempdir().unwrap();
    let garbage_file = dir.path().join("garbage.dmg");
    fs::write(&garbage_file, b"not a real dmg file - just garbage bytes for testing").unwrap();

    let result = super::dmg::build_dmg_report(
        &garbage_file.to_string_lossy(),
        crate::ScanMode::Light,
        None,
    );

    assert!(
        result.is_some(),
        "build_dmg_report must return Some even on extraction failure"
    );
    let report = result.unwrap();
    assert_eq!(
        report.scan_status,
        crate::report::ScanStatus::Complete,
        "scan_status must be Complete (extraction failure is graceful, not a scan error)"
    );
    assert_eq!(
        report.inventory_status,
        crate::report::InventoryStatus::Missing,
        "inventory_status must be Missing (no packages in garbage input)"
    );
}

#[test]
fn test_dmg_build_report_target_type() {
    // Verify the DMG pipeline sets target.target_type = "dmg" so the report
    // is correctly identified as a DMG scan in downstream consumers.
    let dir = tempdir().unwrap();
    let garbage_file = dir.path().join("test.dmg");
    fs::write(&garbage_file, b"garbage dmg content").unwrap();

    let result = super::dmg::build_dmg_report(
        &garbage_file.to_string_lossy(),
        crate::ScanMode::Light,
        None,
    );

    let report = result.expect("build_dmg_report must return Some");
    assert_eq!(
        report.target.target_type, "dmg",
        "target.target_type must be 'dmg' for DMG pipeline"
    );
}

// ---------------------------------------------------------------------------
// Synthetic DMG test: .app bundle with embedded npm packages
// ---------------------------------------------------------------------------

#[test]
fn test_detect_macos_app_with_embedded_packages() {
    let dir = tempdir().unwrap();

    // Create Firefox.app/Contents/Info.plist
    let app_contents = dir.path().join("Firefox.app/Contents");
    fs::create_dir_all(&app_contents).unwrap();
    fs::write(
        app_contents.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>org.mozilla.firefox</string>
    <key>CFBundleShortVersionString</key>
    <string>123.0</string>
</dict>
</plist>"#,
    )
    .unwrap();

    // Create embedded npm package inside the app bundle
    let node_modules = app_contents.join("Resources/node_modules/express");
    fs::create_dir_all(&node_modules).unwrap();
    fs::write(
        node_modules.join("package.json"),
        r#"{"name":"express","version":"4.18.0"}"#,
    )
    .unwrap();

    // detect_macos_packages finds the .app bundle
    let macos_pkgs = detect_macos_packages(dir.path());
    assert_eq!(macos_pkgs.len(), 1, "detect_macos_packages should find 1 mac-app package");
    assert_eq!(macos_pkgs[0].ecosystem, "mac-app");
    assert_eq!(macos_pkgs[0].name, "org.mozilla.firefox");
    assert_eq!(macos_pkgs[0].version, "123.0");

    // detect_app_packages finds the embedded npm package
    let app_pkgs = detect::detect_app_packages(dir.path());
    let express_pkg = app_pkgs.iter().find(|p| p.name == "express");
    assert!(express_pkg.is_some(), "detect_app_packages should find the embedded express npm package");
    assert_eq!(express_pkg.unwrap().ecosystem, "npm");
    assert_eq!(express_pkg.unwrap().version, "4.18.0");
}
