//! Debian/Ubuntu dpkg status file parsing.

use crate::container::PackageCoordinate;

pub(super) fn parse_dpkg_status_with_ecosystem(
    contents: &str,
    ecosystem: &str,
    out: &mut Vec<PackageCoordinate>,
) {
    parse_dpkg_status_inner(contents, ecosystem, out);
}

pub(super) fn parse_dpkg_status(contents: &str, out: &mut Vec<PackageCoordinate>) {
    parse_dpkg_status_inner(contents, "deb", out);
}

fn parse_dpkg_status_inner(contents: &str, ecosystem: &str, out: &mut Vec<PackageCoordinate>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;
    let mut installed_ok: bool = false;

    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>,
                 installed_ok: bool,
                 out: &mut Vec<PackageCoordinate>| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            let src = source.take();
            if installed_ok {
                // OSV's Debian ecosystem indexes by source package name. The dpkg
                // `Source:` field gives us the source name when it differs from the
                // binary package name (format: "srcname" or "srcname (version)").
                let source_name = src
                    .map(|s| {
                        let trimmed = s.split_whitespace().next().unwrap_or(&s).to_string();
                        if trimmed == n {
                            None
                        } else {
                            Some(trimmed)
                        }
                    })
                    .flatten();
                out.push(PackageCoordinate {
                    ecosystem: ecosystem.into(),
                    name: n,
                    version: v,
                    source_name,
                });
            }
        } else {
            source.take();
        }
    };

    for line in contents.lines() {
        if line.starts_with("Package:") {
            flush(&mut name, &mut version, &mut source, installed_ok, out);
            name = Some(line[8..].trim().to_string());
            version = None;
            source = None;
            installed_ok = false;
        } else if line.starts_with("Version:") {
            version = Some(line[8..].trim().to_string());
        } else if line.starts_with("Source:") {
            source = Some(line[7..].trim().to_string());
        } else if line.starts_with("Status:") {
            installed_ok = line.contains("install ok installed");
        } else if line.is_empty() {
            flush(&mut name, &mut version, &mut source, installed_ok, out);
            installed_ok = false;
        }
    }
    // Flush final package
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        let src = source.take();
        if installed_ok {
            let source_name = src
                .map(|s| {
                    let trimmed = s.split_whitespace().next().unwrap_or(&s).to_string();
                    if trimmed == n {
                        None
                    } else {
                        Some(trimmed)
                    }
                })
                .flatten();
            out.push(PackageCoordinate {
                ecosystem: ecosystem.into(),
                name: n,
                version: v,
                source_name,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpkg_status_basic() {
        let status = "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\nPackage: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n";
        let mut out = Vec::new();
        parse_dpkg_status(status, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "libc6");
        assert_eq!(out[0].version, "2.36-9");
    }
}
