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
