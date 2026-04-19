//! Alpine/Chainguard/Wolfi APK installed database parsing.

use crate::container::PackageCoordinate;

pub(super) fn parse_apk_installed(contents: &str, out: &mut Vec<PackageCoordinate>) {
    parse_apk_installed_with_ecosystem(contents, "apk", out);
}

pub(super) fn parse_apk_installed_with_ecosystem(
    contents: &str,
    ecosystem: &str,
    out: &mut Vec<PackageCoordinate>,
) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut license: Option<String> = None;
    for line in contents.lines() {
        if line.starts_with("P:") {
            name = Some(line[2..].trim().to_string());
        } else if line.starts_with("V:") {
            version = Some(line[2..].trim().to_string());
        } else if line.starts_with("o:") {
            // Origin package name — OSV Alpine indexes by origin, not binary subpackage.
            origin = Some(line[2..].trim().to_string());
        } else if line.starts_with("L:") {
            license = Some(line[2..].trim().to_string());
        } else if line.is_empty() {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                let src = origin.take();
                let source_name = src.and_then(|o| if o == n { None } else { Some(o) });
                out.push(PackageCoordinate {
                    ecosystem: ecosystem.into(),
                    name: n,
                    version: v,
                    source_name,
                    license: license.take(),
                });
            } else {
                origin.take();
                license.take();
            }
        }
    }
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        let src = origin.take();
        let source_name = src.and_then(|o| if o == n { None } else { Some(o) });
        out.push(PackageCoordinate {
            ecosystem: ecosystem.into(),
            name: n,
            version: v,
            source_name,
            license: license.take(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apk_basic() {
        let db = "P:busybox\nV:1.36.1-r2\n\n";
        let mut out = Vec::new();
        parse_apk_installed(db, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "busybox");
        assert_eq!(out[0].version, "1.36.1-r2");
        assert_eq!(out[0].source_name, None);
    }

    #[test]
    fn test_parse_apk_origin_field() {
        // When origin differs from package name, it should be set as source_name
        let db = "P:busybox-binsh\nV:1.36.1-r2\no:busybox\n\n";
        let mut out = Vec::new();
        parse_apk_installed(db, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "busybox-binsh");
        assert_eq!(out[0].source_name, Some("busybox".into()));
    }

    #[test]
    fn test_parse_apk_origin_same_as_name() {
        let db = "P:busybox\nV:1.36.1-r2\no:busybox\n\n";
        let mut out = Vec::new();
        parse_apk_installed(db, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source_name, None); // same as name
    }

    #[test]
    fn test_parse_apk_multiple_packages() {
        let db = "P:alpine-baselayout\nV:3.4.0-r0\n\nP:busybox\nV:1.36.1-r2\n\n";
        let mut out = Vec::new();
        parse_apk_installed(db, &mut out);
        assert_eq!(out.len(), 2);
    }
}
