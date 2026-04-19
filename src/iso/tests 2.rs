use super::extract::normalize_path_like;
use super::inventory::{dedupe_packages, parse_rpm_filename};
use super::repodata::{parse_primary_packages, parse_repodata_primary_href};
use super::extract::find_entry;
use crate::container::PackageCoordinate;

#[test]
fn test_parse_rpm_filename() {
    let parsed = parse_rpm_filename("bash-5.1.8-6.el9.x86_64.rpm");
    assert_eq!(
        parsed,
        Some(("bash".to_string(), "5.1.8-6.el9".to_string()))
    );
    assert_eq!(parse_rpm_filename("not-an-rpm.txt"), None);
}

#[test]
fn test_parse_repodata_primary_href() {
    let xml = r#"
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/abc-primary.xml.gz"/>
  </data>
</repomd>
"#;
    assert_eq!(
        parse_repodata_primary_href(xml.as_bytes()),
        Some("repodata/abc-primary.xml.gz".to_string())
    );
}

#[test]
fn test_parse_primary_packages() {
    let xml = r#"
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
  <package type="rpm">
    <name>openssl</name>
    <version epoch="1" ver="3.0.7" rel="20.el9"/>
  </package>
</metadata>
"#;
    let pkgs = parse_primary_packages(xml.as_bytes());
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0].name, "openssl");
    assert_eq!(pkgs[0].version, "1:3.0.7-20.el9");
}

#[test]
fn test_dedupe_packages() {
    let input = vec![
        PackageCoordinate {
            ecosystem: "redhat".into(),
            name: "bash".into(),
            version: "5.1-1".into(),
            source_name: None,
        },
        PackageCoordinate {
            ecosystem: "redhat".into(),
            name: "bash".into(),
            version: "5.1-1".into(),
            source_name: None,
        },
    ];
    let out = dedupe_packages(input);
    assert_eq!(out.len(), 1);
}

#[test]
fn test_find_entry_normalized() {
    let entries = vec!["./repodata/repomd.xml".to_string()];
    assert_eq!(
        find_entry(&entries, "repodata/repomd.xml"),
        Some("./repodata/repomd.xml")
    );
}
