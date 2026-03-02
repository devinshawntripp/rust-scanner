use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
pub struct ParsedIds {
    pub tool: String,
    pub ids: BTreeSet<String>,
    pub id_packages: BTreeMap<String, BTreeSet<String>>,
}

pub fn parse_report_ids(path: &str) -> anyhow::Result<ParsedIds> {
    let text = std::fs::read_to_string(path)?;
    let v: Value = serde_json::from_str(&text)?;
    let mut out = ParsedIds::default();

    if let Some(arr) = v.get("findings").and_then(|x| x.as_array()) {
        out.tool = "scanrook".to_string();
        for f in arr {
            if let Some(id) = f.get("id").and_then(|x| x.as_str()) {
                if id.starts_with("CVE-") {
                    out.ids.insert(id.to_string());
                    if let Some(pkg) = f
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|x| x.as_str())
                    {
                        out.id_packages
                            .entry(id.to_string())
                            .or_default()
                            .insert(pkg.to_string());
                    }
                }
            }
        }
        return Ok(out);
    }

    if let Some(results) = v.get("Results").and_then(|x| x.as_array()) {
        out.tool = "trivy".to_string();
        for r in results {
            if let Some(vulns) = r.get("Vulnerabilities").and_then(|x| x.as_array()) {
                for vuln in vulns {
                    if let Some(id) = vuln.get("VulnerabilityID").and_then(|x| x.as_str()) {
                        if id.starts_with("CVE-") {
                            out.ids.insert(id.to_string());
                            if let Some(pkg) = vuln.get("PkgName").and_then(|x| x.as_str()) {
                                out.id_packages
                                    .entry(id.to_string())
                                    .or_default()
                                    .insert(pkg.to_string());
                            }
                        }
                    }
                }
            }
        }
        return Ok(out);
    }

    if let Some(matches) = v.get("matches").and_then(|x| x.as_array()) {
        out.tool = "grype".to_string();
        for m in matches {
            if let Some(id) = m
                .get("vulnerability")
                .and_then(|vv| vv.get("id"))
                .and_then(|x| x.as_str())
            {
                if id.starts_with("CVE-") {
                    out.ids.insert(id.to_string());
                    if let Some(pkg) = m
                        .get("artifact")
                        .and_then(|a| a.get("name"))
                        .and_then(|x| x.as_str())
                    {
                        out.id_packages
                            .entry(id.to_string())
                            .or_default()
                            .insert(pkg.to_string());
                    }
                }
            }
        }
        return Ok(out);
    }

    Err(anyhow::anyhow!("unsupported report schema: {}", path))
}

pub fn run_diff(ours: &str, against: &str, out: Option<&str>) -> anyhow::Result<()> {
    let ours_ids = parse_report_ids(ours)?;
    let other_ids = parse_report_ids(against)?;

    let missing: Vec<String> = other_ids.ids.difference(&ours_ids.ids).cloned().collect();
    let extra: Vec<String> = ours_ids.ids.difference(&other_ids.ids).cloned().collect();

    println!(
        "ours_tool={} ours_cves={} against_tool={} against_cves={}",
        ours_ids.tool,
        ours_ids.ids.len(),
        other_ids.tool,
        other_ids.ids.len()
    );
    println!("missing_vs_against={}", missing.len());
    println!("extra_vs_against={}", extra.len());

    println!("missing_sample:");
    for cve in missing.iter().take(25) {
        println!("  {}", cve);
    }
    println!("extra_sample:");
    for cve in extra.iter().take(25) {
        println!("  {}", cve);
    }

    let mut miss_pkg_freq: BTreeMap<String, usize> = BTreeMap::new();
    for cve in &missing {
        if let Some(pkgs) = other_ids.id_packages.get(cve) {
            for p in pkgs {
                *miss_pkg_freq.entry(p.clone()).or_insert(0) += 1;
            }
        }
    }
    if !miss_pkg_freq.is_empty() {
        println!("missing_package_frequency:");
        let mut ranked: Vec<(String, usize)> = miss_pkg_freq.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (pkg, n) in ranked.into_iter().take(15) {
            println!("  {} {}", pkg, n);
        }
    }

    if let Some(path) = out {
        let payload = serde_json::json!({
            "ours_tool": ours_ids.tool,
            "against_tool": other_ids.tool,
            "ours_count": ours_ids.ids.len(),
            "against_count": other_ids.ids.len(),
            "missing_vs_against": missing,
            "extra_vs_against": extra,
        });
        std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
    }
    Ok(())
}
