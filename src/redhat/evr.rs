use std::cmp::Ordering;
use std::collections::HashMap;

use crate::container::PackageCoordinate;

/// Returns true for RPM-based ecosystems.
pub fn is_rpm_ecosystem(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "redhat" | "rpm" | "rocky" | "almalinux" | "suse" | "opensuse" | "centos" | "fedora"
    )
}

pub fn compare_evr(a: &str, b: &str) -> Ordering {
    let (epoch_a, version_a, release_a) = split_evr(a);
    let (epoch_b, version_b, release_b) = split_evr(b);
    match epoch_a.cmp(&epoch_b) {
        Ordering::Equal => {}
        ord => return ord,
    }
    match rpmvercmp(version_a, version_b) {
        Ordering::Equal => rpmvercmp(release_a, release_b),
        ord => ord,
    }
}

fn split_evr(evr: &str) -> (i64, &str, &str) {
    let trimmed = evr.trim();
    let (epoch, rest) = match trimmed.split_once(':') {
        Some((lhs, rhs)) if lhs.chars().all(|c| c.is_ascii_digit()) => {
            (lhs.parse::<i64>().unwrap_or(0), rhs)
        }
        _ => (0, trimmed),
    };
    match rest.rsplit_once('-') {
        Some((version, release)) => (epoch, version, release),
        None => (epoch, rest, ""),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    End,
    Tilde,
    Numeric,
    Alpha,
}

fn rpmvercmp(a: &str, b: &str) -> Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut ia = 0usize;
    let mut ib = 0usize;

    loop {
        let (ka, sa) = next_token(ab, &mut ia);
        let (kb, sb) = next_token(bb, &mut ib);

        match (ka, kb) {
            (TokenKind::End, TokenKind::End) => return Ordering::Equal,
            (TokenKind::Tilde, TokenKind::Tilde) => continue,
            (TokenKind::Tilde, _) => return Ordering::Less,
            (_, TokenKind::Tilde) => return Ordering::Greater,
            (TokenKind::End, _) => return Ordering::Less,
            (_, TokenKind::End) => return Ordering::Greater,
            (TokenKind::Numeric, TokenKind::Numeric) => {
                let ord = compare_numeric_segments(sa, sb);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (TokenKind::Alpha, TokenKind::Alpha) => {
                let ord = sa.cmp(sb);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (TokenKind::Numeric, TokenKind::Alpha) => return Ordering::Greater,
            (TokenKind::Alpha, TokenKind::Numeric) => return Ordering::Less,
        }
    }
}

fn next_token<'a>(bytes: &'a [u8], idx: &mut usize) -> (TokenKind, &'a [u8]) {
    while *idx < bytes.len() && !bytes[*idx].is_ascii_alphanumeric() && bytes[*idx] != b'~' {
        *idx += 1;
    }
    if *idx >= bytes.len() {
        return (TokenKind::End, &[]);
    }
    if bytes[*idx] == b'~' {
        *idx += 1;
        return (TokenKind::Tilde, &[]);
    }

    let start = *idx;
    if bytes[*idx].is_ascii_digit() {
        while *idx < bytes.len() && bytes[*idx].is_ascii_digit() {
            *idx += 1;
        }
        return (TokenKind::Numeric, &bytes[start..*idx]);
    }

    while *idx < bytes.len() && bytes[*idx].is_ascii_alphabetic() {
        *idx += 1;
    }
    (TokenKind::Alpha, &bytes[start..*idx])
}

fn compare_numeric_segments(a: &[u8], b: &[u8]) -> Ordering {
    let a_trim = trim_leading_zeroes(a);
    let b_trim = trim_leading_zeroes(b);
    match a_trim.len().cmp(&b_trim.len()) {
        Ordering::Equal => a_trim.cmp(b_trim),
        ord => ord,
    }
}

fn trim_leading_zeroes(mut v: &[u8]) -> &[u8] {
    while v.first().copied() == Some(b'0') {
        v = &v[1..];
    }
    if v.is_empty() {
        b"0"
    } else {
        v
    }
}

/// Detect the Red Hat OVAL major version from an RPM ecosystem string and/or package metadata.
pub fn detect_rhel_major_version(packages: &[PackageCoordinate]) -> Option<u32> {
    // Look at release tags in package versions: e.g. "5.1.8-6.el9" -> 9
    let re = regex::Regex::new(r"\.el(\d+)").ok()?;
    for pkg in packages {
        if let Some(caps) = re.captures(&pkg.version) {
            if let Some(m) = caps.get(1) {
                if let Ok(n) = m.as_str().parse::<u32>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Auto-download and cache Red Hat OVAL data for the given RHEL major version.
///
/// Returns the path to the cached XML file, or None if download failed.
pub fn fetch_redhat_oval(
    packages: &[PackageCoordinate],
    cache_dir: Option<&std::path::Path>,
) -> Option<String> {
    let version = detect_rhel_major_version(packages)?;
    if version < 6 || version > 10 {
        crate::utils::progress(
            "oval.auto.skip",
            &format!("unsupported RHEL version {}", version),
        );
        return None;
    }

    let cache_dir = cache_dir.or_else(|| {
        std::env::var("SCANNER_CACHE")
            .ok()
            .map(|_| std::path::Path::new(""))
    });
    let cache_base = if let Some(dir) = cache_dir {
        dir.to_path_buf()
    } else if let Some(home) = std::env::var_os("HOME") {
        std::path::PathBuf::from(home)
            .join(".scanrook")
            .join("cache")
    } else {
        return None;
    };

    let oval_dir = cache_base.join("oval");
    let _ = std::fs::create_dir_all(&oval_dir);
    let oval_xml_path = oval_dir.join(format!("rhel-{}.oval.xml", version));

    // Check cache freshness (7 days)
    if oval_xml_path.exists() {
        if let Ok(meta) = std::fs::metadata(&oval_xml_path) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                if age < std::time::Duration::from_secs(7 * 24 * 3600) {
                    crate::utils::progress("oval.auto.cache_hit", &oval_xml_path.to_string_lossy());
                    return Some(oval_xml_path.to_string_lossy().to_string());
                }
            }
        }
    }

    let url = format!(
        "https://www.redhat.com/security/data/oval/v2/RHEL{}/rhel-{}.oval.xml.bz2",
        version, version
    );
    crate::utils::progress("oval.auto.download", &url);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .ok()?;
    let resp = match client.get(&url).send() {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            crate::utils::progress("oval.auto.download.error", &format!("HTTP {}", r.status()));
            return None;
        }
        Err(e) => {
            crate::utils::progress("oval.auto.download.error", &format!("{}", e));
            return None;
        }
    };

    let bz2_bytes = match resp.bytes() {
        Ok(b) => b,
        Err(e) => {
            crate::utils::progress("oval.auto.download.error", &format!("{}", e));
            return None;
        }
    };

    // Decompress bzip2
    let mut decoder = bzip2::read::BzDecoder::new(bz2_bytes.as_ref());
    let mut xml_data = Vec::new();
    if let Err(e) = std::io::Read::read_to_end(&mut decoder, &mut xml_data) {
        crate::utils::progress("oval.auto.decompress.error", &format!("{}", e));
        return None;
    }

    if let Err(e) = std::fs::write(&oval_xml_path, &xml_data) {
        crate::utils::progress("oval.auto.write.error", &format!("{}", e));
        return None;
    }

    crate::utils::progress(
        "oval.auto.done",
        &format!(
            "version={} size={}KB path={}",
            version,
            xml_data.len() / 1024,
            oval_xml_path.display()
        ),
    );
    Some(oval_xml_path.to_string_lossy().to_string())
}

/// Build a map of RPM package names to installed versions.
pub(super) fn build_rpm_package_map(packages: &[PackageCoordinate]) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for pkg in packages {
        if !is_rpm_ecosystem(&pkg.ecosystem) {
            continue;
        }
        out.entry(pkg.name.clone())
            .or_default()
            .push(pkg.version.clone());
    }
    out
}

/// Returns true for OS version-gating packages that should not generate findings.
pub(super) fn is_release_gating_package(name: &str) -> bool {
    name.ends_with("-release")
        || name.ends_with("-release-server")
        || name == "redhat-release-workstation"
        || name == "oraclelinux-release"
        || name.starts_with("centos-linux-release")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_evr_epoch_and_release() {
        assert_eq!(compare_evr("1:1.0-1", "0:9.9-9"), Ordering::Greater);
        assert_eq!(compare_evr("0:1.2.3-4", "0:1.2.4-1"), Ordering::Less);
        assert_eq!(compare_evr("1.0-10", "1.0-2"), Ordering::Greater);
    }

    #[test]
    fn test_rpmvercmp_tilde_ordering() {
        assert_eq!(rpmvercmp("1.0~beta", "1.0"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0", "1.0~beta"), Ordering::Greater);
    }

    #[test]
    fn test_compare_evr_no_epoch() {
        // No epoch prefix — epoch defaults to 0
        assert_eq!(compare_evr("1.2.3-1.el9", "1.2.3-1.el9"), Ordering::Equal);
        assert_eq!(compare_evr("1.2.4-1.el9", "1.2.3-1.el9"), Ordering::Greater);
    }

    #[test]
    fn test_compare_evr_epoch_beats_version() {
        // Higher epoch always wins regardless of version
        assert_eq!(compare_evr("2:1.0-1", "1:99.99-99"), Ordering::Greater);
    }

    #[test]
    fn test_compare_evr_release_tiebreaker() {
        // Same version, different release
        assert_eq!(compare_evr("1.0-10.el9", "1.0-2.el9"), Ordering::Greater);
    }

    #[test]
    fn test_compare_evr_tilde_pre_release() {
        // Tilde sorts lower (pre-release)
        assert_eq!(compare_evr("1.0~alpha", "1.0"), Ordering::Less);
        assert_eq!(compare_evr("2.0.0", "2.0.0~rc1"), Ordering::Greater);
        assert_eq!(compare_evr("1.0~beta2", "1.0~beta1"), Ordering::Greater);
    }

    #[test]
    fn test_detect_rhel_major_version_from_packages() {
        let pkgs = vec![
            PackageCoordinate { ecosystem: "rocky".into(), name: "bash".into(), version: "5.1.8-6.el9".into(), source_name: None, license: None },
        ];
        assert_eq!(detect_rhel_major_version(&pkgs), Some(9));

        let pkgs8 = vec![
            PackageCoordinate { ecosystem: "redhat".into(), name: "openssl".into(), version: "1:1.1.1k-9.el8_8".into(), source_name: None, license: None },
        ];
        assert_eq!(detect_rhel_major_version(&pkgs8), Some(8));
    }

    #[test]
    fn test_is_rpm_ecosystem() {
        assert!(is_rpm_ecosystem("rocky"));
        assert!(is_rpm_ecosystem("redhat"));
        assert!(is_rpm_ecosystem("centos"));
        assert!(is_rpm_ecosystem("fedora"));
        assert!(!is_rpm_ecosystem("deb"));
        assert!(!is_rpm_ecosystem("apk"));
    }
}
