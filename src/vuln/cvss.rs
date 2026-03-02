pub(super) fn parse_cvss_score(score_raw: &str) -> Option<(f32, String)> {
    let s = score_raw.trim();
    if s.is_empty() {
        return None;
    }

    // 1) Plain numeric score (e.g. "7.5")
    if let Ok(n) = s.parse::<f32>() {
        return Some((n, s.to_string()));
    }

    // 2) Legacy "X.Y/..." format
    let head = s.split('/').next().unwrap_or(s);
    if let Ok(n) = head.parse::<f32>() {
        return Some((n, s.to_string()));
    }

    // 3) CVSS vector format (e.g. "CVSS:3.1/AV:L/...")
    if s.starts_with("CVSS:") {
        if let Ok(v) = s.parse::<cvss::Cvss>() {
            return Some((v.score() as f32, s.to_string()));
        }
    }

    None
}

pub(super) fn normalize_redhat_severity(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    if up.is_empty() {
        return None;
    }
    let mapped = match up.as_str() {
        "IMPORTANT" => "HIGH",
        "MODERATE" => "MEDIUM",
        "LOW" => "LOW",
        "MEDIUM" => "MEDIUM",
        "HIGH" => "HIGH",
        "CRITICAL" => "CRITICAL",
        _ => up.as_str(),
    };
    Some(mapped.to_string())
}
