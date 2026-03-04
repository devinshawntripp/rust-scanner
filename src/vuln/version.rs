fn tokenize_version(v: &str) -> Vec<i64> {
    v.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<i64>().unwrap_or(-1))
        .collect()
}

pub(crate) fn cmp_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let ta = tokenize_version(a);
    let tb = tokenize_version(b);
    let len = ta.len().max(tb.len());
    for i in 0..len {
        let va = *ta.get(i).unwrap_or(&0);
        let vb = *tb.get(i).unwrap_or(&0);
        if va < vb {
            return Ordering::Less;
        }
        if va > vb {
            return Ordering::Greater;
        }
    }
    Ordering::Equal
}

pub(super) fn is_version_in_range(
    target: &str,
    start_inc: Option<&str>,
    start_exc: Option<&str>,
    end_inc: Option<&str>,
    end_exc: Option<&str>,
) -> bool {
    if let Some(s) = start_inc {
        if cmp_versions(target, s) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(s) = start_exc {
        if cmp_versions(target, s) != std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(e) = end_inc {
        if cmp_versions(target, e) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(e) = end_exc {
        if cmp_versions(target, e) != std::cmp::Ordering::Less {
            return false;
        }
    }
    true
}

pub(super) fn cpe_parts(criteria: &str) -> Option<(String, String, Option<String>)> {
    // cpe:2.3:a:vendor:product:version:...
    let parts: Vec<&str> = criteria.split(':').collect();
    if parts.len() >= 5 {
        Some((
            parts[3].to_string(),
            parts[4].to_string(),
            parts.get(5).map(|s| s.to_string()),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    // QUAL-02: Version comparison tests

    #[test]
    fn test_cmp_versions_equal() {
        assert_eq!(cmp_versions("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn test_cmp_versions_major_diff() {
        assert_eq!(cmp_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(cmp_versions("1.0.0", "2.0.0"), Ordering::Less);
    }

    #[test]
    fn test_cmp_versions_minor_diff() {
        assert_eq!(cmp_versions("1.2.0", "1.1.0"), Ordering::Greater);
    }

    #[test]
    fn test_cmp_versions_patch_diff() {
        assert_eq!(cmp_versions("1.2.4", "1.2.3"), Ordering::Greater);
    }

    #[test]
    fn test_cmp_versions_different_lengths() {
        // Missing segments treated as 0
        assert_eq!(cmp_versions("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(cmp_versions("1.2", "1.2.1"), Ordering::Less);
    }

    #[test]
    fn test_cmp_versions_alpha_tokens() {
        // Alphabetic tokens get -1 (non-parseable to i64)
        // "1.0.0-beta" tokenizes as [1, 0, 0, -1], "1.0.0" as [1, 0, 0]
        assert_eq!(cmp_versions("1.0.0-beta", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn test_cmp_versions_large_numbers() {
        assert_eq!(cmp_versions("10.20.30", "10.20.29"), Ordering::Greater);
        assert_eq!(cmp_versions("100.0.0", "99.99.99"), Ordering::Greater);
    }

    #[test]
    fn test_is_version_in_range_basic() {
        assert!(is_version_in_range("1.5.0", Some("1.0.0"), None, Some("2.0.0"), None));
        assert!(!is_version_in_range("0.9.0", Some("1.0.0"), None, Some("2.0.0"), None));
        assert!(!is_version_in_range("2.1.0", Some("1.0.0"), None, Some("2.0.0"), None));
    }

    #[test]
    fn test_is_version_in_range_exclusive() {
        // Start exclusive: target must be strictly greater
        assert!(!is_version_in_range("1.0.0", None, Some("1.0.0"), None, None));
        assert!(is_version_in_range("1.0.1", None, Some("1.0.0"), None, None));
        // End exclusive: target must be strictly less
        assert!(!is_version_in_range("2.0.0", None, None, None, Some("2.0.0")));
        assert!(is_version_in_range("1.9.9", None, None, None, Some("2.0.0")));
    }

    #[test]
    fn test_is_version_in_range_no_bounds() {
        // No constraints = always in range
        assert!(is_version_in_range("999.0.0", None, None, None, None));
    }

    // QUAL-03: CPE matching tests

    #[test]
    fn test_cpe_parts_standard() {
        let result = cpe_parts("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*");
        let (vendor, product, version) = result.unwrap();
        assert_eq!(vendor, "apache");
        assert_eq!(product, "http_server");
        assert_eq!(version, Some("2.4.51".to_string()));
    }

    #[test]
    fn test_cpe_parts_wildcard_version() {
        let result = cpe_parts("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*");
        let (_, _, version) = result.unwrap();
        assert_eq!(version, Some("*".to_string()));
    }

    #[test]
    fn test_cpe_parts_too_short() {
        // Less than 5 parts — should return None
        assert!(cpe_parts("cpe:2.3:a:vendor").is_none());
    }

    #[test]
    fn test_cpe_parts_minimal() {
        // Exactly 5 parts (indices 0-4) — should work, version is None
        let result = cpe_parts("cpe:2.3:a:vendor:product");
        assert!(result.is_some());
        let (vendor, product, version) = result.unwrap();
        assert_eq!(vendor, "vendor");
        assert_eq!(product, "product");
        assert_eq!(version, None);
    }

    #[test]
    fn test_cpe_parts_with_version() {
        // 6 parts — version present
        let result = cpe_parts("cpe:2.3:a:vendor:product:version");
        assert!(result.is_some());
        let (_, _, version) = result.unwrap();
        assert_eq!(version, Some("version".to_string()));
    }
}
