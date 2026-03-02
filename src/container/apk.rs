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
    for line in contents.lines() {
        if line.starts_with("P:") {
            name = Some(line[2..].trim().to_string());
        } else if line.starts_with("V:") {
            version = Some(line[2..].trim().to_string());
        } else if line.starts_with("o:") {
            // Origin package name — OSV Alpine indexes by origin, not binary subpackage.
            origin = Some(line[2..].trim().to_string());
        } else if line.is_empty() {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                let src = origin.take();
                let source_name = src.and_then(|o| if o == n { None } else { Some(o) });
                out.push(PackageCoordinate {
                    ecosystem: ecosystem.into(),
                    name: n,
                    version: v,
                    source_name,
                });
            } else {
                origin.take();
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
        });
    }
}
