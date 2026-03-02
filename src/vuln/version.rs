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
            Some(parts[5].to_string()),
        ))
    } else {
        None
    }
}
