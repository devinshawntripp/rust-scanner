use serde_json::Value;

/// Render a scan report Value as human-readable text.
pub fn render_text_report(report: &Value) -> String {
    let mut out = String::new();

    // Header
    if let Some(target) = report.get("target").and_then(|v| v.as_str()) {
        out.push_str(&format!("Target: {}\n", target));
    }
    if let Some(tt) = report.get("target_type").and_then(|v| v.as_str()) {
        out.push_str(&format!("Type:   {}\n", tt));
    }
    if let Some(status) = report.get("scan_status").and_then(|v| v.as_str()) {
        out.push_str(&format!("Status: {}\n", status));
    }
    out.push('\n');

    // Summary
    if let Some(summary) = report.get("summary") {
        out.push_str("Summary\n");
        out.push_str("-------\n");
        if let Some(pkgs) = summary.get("total_packages").and_then(|v| v.as_u64()) {
            out.push_str(&format!("  Packages: {}\n", pkgs));
        }
        if let Some(total) = summary.get("total_findings").and_then(|v| v.as_u64()) {
            out.push_str(&format!("  Findings: {}\n", total));
        }
        for sev in &["critical", "high", "medium", "low"] {
            if let Some(n) = summary.get(*sev).and_then(|v| v.as_u64()) {
                if n > 0 {
                    out.push_str(&format!("    {}: {}\n", sev.to_uppercase(), n));
                }
            }
        }
        out.push('\n');
    }

    // Findings
    if let Some(findings) = report.get("findings").and_then(|v| v.as_array()) {
        if !findings.is_empty() {
            out.push_str("Findings\n");
            out.push_str("--------\n");
            for (i, f) in findings.iter().enumerate() {
                let cve = f.get("cve_id").and_then(|v| v.as_str()).unwrap_or("N/A");
                let pkg = f.get("package").and_then(|v| v.as_str()).unwrap_or("unknown");
                let ver = f.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
                let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");

                out.push_str(&format!(
                    "  {}. [{}] {} {} @ {}\n",
                    i + 1, sev, cve, pkg, ver
                ));
                if !desc.is_empty() {
                    out.push_str(&format!("     {}\n", desc));
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_basic_report() {
        let report = json!({
            "target": "/tmp/test.tar",
            "target_type": "container",
            "scan_status": "Complete",
            "summary": {
                "total_packages": 42,
                "total_findings": 3,
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 0
            },
            "findings": [
                {
                    "cve_id": "CVE-2024-1234",
                    "package": "openssl",
                    "version": "1.1.1",
                    "severity": "CRITICAL",
                    "description": "Buffer overflow"
                }
            ]
        });

        let text = render_text_report(&report);
        assert!(text.contains("test.tar"), "should show target");
        assert!(text.contains("42"), "should show package count");
        assert!(text.contains("CVE-2024-1234"), "should show CVE ID");
        assert!(text.contains("openssl"), "should show package name");
        assert!(text.contains("CRITICAL"), "should show severity");
        assert!(!text.starts_with('{'), "should not be JSON");
    }

    #[test]
    fn renders_empty_report() {
        let report = json!({});
        let text = render_text_report(&report);
        assert!(!text.starts_with('{'), "should not be JSON even for empty report");
    }
}
