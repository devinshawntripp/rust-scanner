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
