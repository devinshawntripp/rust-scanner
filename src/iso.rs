use crate::container::PackageCoordinate;
use crate::redhat::filter_findings_with_redhat_oval;
use crate::report::{compute_summary, Report, ScannerInfo, TargetInfo};
use crate::utils::progress;
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use anyhow::{anyhow, Context};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::collections::HashSet;
use std::io::Read;
use std::process::Command;
use xmltree::{Element, XMLNode};

pub fn build_iso_report(
    path: &str,
    _mode: ScanMode,
    _yara_rules: Option<String>,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Report> {
    progress("iso.detect.start", path);
    let entries = match list_iso_entries(path) {
        Ok(v) => v,
        Err(e) => {
            progress("iso.detect.error", &format!("{}", e));
            return None;
        }
    };
    progress("iso.detect.done", &format!("entries={}", entries.len()));

    let mut packages = packages_from_rpm_entries(&entries);
    progress(
        "iso.packages.filenames",
        &format!("packages={}", packages.len()),
    );

    match packages_from_repodata(path, &entries) {
        Ok(mut from_repodata) => {
            if !from_repodata.is_empty() {
                progress(
                    "iso.repodata.done",
                    &format!("packages={}", from_repodata.len()),
                );
                packages.append(&mut from_repodata);
            } else {
                progress("iso.repodata.skip", "no-primary-packages");
            }
        }
        Err(e) => {
            progress("iso.repodata.error", &format!("{}", e));
        }
    }

    packages = dedupe_packages(packages);
    progress(
        "iso.packages.detect.done",
        &format!("packages={}", packages.len()),
    );
    if packages.is_empty() {
        progress("iso.packages.detect.skip", "no-rpm-package-metadata");
        return None;
    }

    progress(
        "iso.osv.query.start",
        &format!("packages={}", packages.len()),
    );
    let osv_results = osv_batch_query(&packages);
    progress("iso.osv.query.done", "ok");

    let mut findings_norm = map_osv_results_to_findings(&packages, &osv_results);
    progress(
        "iso.enrich.osv.start",
        &format!("findings_pre_enrich={}", findings_norm.len()),
    );

    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    osv_enrich_findings(&mut findings_norm, &mut pg);
    progress(
        "iso.enrich.osv.done",
        &format!("findings={}", findings_norm.len()),
    );

    let nvd_enrich_enabled = std::env::var("SCANNER_NVD_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if nvd_enrich_enabled {
        let unique_cves = findings_norm
            .iter()
            .filter(|f| f.id.starts_with("CVE-"))
            .map(|f| f.id.clone())
            .collect::<HashSet<_>>();
        progress(
            "iso.enrich.nvd.start",
            &format!("cves={}", unique_cves.len()),
        );
        enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
        progress("iso.enrich.nvd.done", "ok");
    } else {
        progress("iso.enrich.nvd.skip", "disabled by SCANNER_NVD_ENRICH");
    }

    let oval_redhat = oval_redhat
        .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
        .filter(|v| !v.trim().is_empty());
    if let Some(oval_path) = oval_redhat.as_deref() {
        progress("iso.enrich.redhat.start", oval_path);
        match filter_findings_with_redhat_oval(&mut findings_norm, &packages, oval_path) {
            Ok(stats) => {
                progress(
                    "iso.enrich.redhat.done",
                    &format!(
                        "defs={}/{} cves={}/{} findings={}->{} filtered={}",
                        stats.definitions_evaluable,
                        stats.definitions_total,
                        stats.vulnerable_cves,
                        stats.covered_cves,
                        stats.findings_before,
                        stats.findings_after,
                        stats.findings_filtered
                    ),
                );
            }
            Err(e) => {
                progress("iso.enrich.redhat.error", &format!("{}", e));
            }
        }
    }

    let scanner = ScannerInfo {
        name: "scanner",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "iso".into(),
        source: path.to_string(),
        id: None,
    };
    let mut report = Report {
        scanner,
        target,
        sbom: None,
        findings: findings_norm,
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);
    Some(report)
}

fn list_iso_entries(path: &str) -> anyhow::Result<Vec<String>> {
    progress("iso.entries.list.start", path);
    let output = Command::new("bsdtar")
        .arg("-tf")
        .arg(path)
        .output()
        .with_context(|| "failed to invoke bsdtar; install libarchive-tools in runtime image")?;
    if !output.status.success() {
        return Err(anyhow!(
            "bsdtar failed to list ISO entries: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let entries = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    progress(
        "iso.entries.list.done",
        &format!("entries={}", entries.len()),
    );
    Ok(entries)
}

fn packages_from_rpm_entries(entries: &[String]) -> Vec<PackageCoordinate> {
    let mut out = Vec::new();
    for entry in entries {
        let lower = entry.to_ascii_lowercase();
        if !lower.ends_with(".rpm") {
            continue;
        }
        let file_name = entry.rsplit('/').next().unwrap_or(entry.as_str());
        if let Some((name, version)) = parse_rpm_filename(file_name) {
            out.push(PackageCoordinate {
                ecosystem: "redhat".into(),
                name,
                version,
            });
        }
    }
    out
}

fn parse_rpm_filename(file_name: &str) -> Option<(String, String)> {
    let stem = file_name.strip_suffix(".rpm")?;
    let (nvr, _arch) = stem.rsplit_once('.')?;
    let mut parts = nvr.rsplitn(3, '-');
    let release = parts.next()?;
    let version = parts.next()?;
    let name = parts.next()?;
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    Some((name.to_string(), format!("{}-{}", version, release)))
}

fn packages_from_repodata(
    path: &str,
    entries: &[String],
) -> anyhow::Result<Vec<PackageCoordinate>> {
    progress("iso.repodata.start", "repomd.xml");
    let Some(repomd_path) = find_entry(entries, "repodata/repomd.xml") else {
        return Ok(Vec::new());
    };
    let repomd_raw = read_iso_entry(path, repomd_path)?;
    let Some(primary_href) = parse_repodata_primary_href(&repomd_raw) else {
        return Ok(Vec::new());
    };
    let Some(primary_entry) = find_entry(entries, &primary_href) else {
        return Err(anyhow!(
            "repodata primary metadata not found in ISO entries: {}",
            primary_href
        ));
    };
    let primary_raw = read_iso_entry(path, primary_entry)?;
    let primary_xml = decompress_if_needed(primary_entry, primary_raw)?;
    Ok(parse_primary_packages(&primary_xml))
}

fn read_iso_entry(path: &str, entry: &str) -> anyhow::Result<Vec<u8>> {
    let output = Command::new("bsdtar")
        .arg("-xOf")
        .arg(path)
        .arg(entry)
        .output()
        .with_context(|| format!("failed extracting {} from ISO", entry))?;
    if !output.status.success() {
        return Err(anyhow!(
            "bsdtar failed extracting {}: {}",
            entry,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn decompress_if_needed(entry: &str, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let lower = entry.to_ascii_lowercase();
    if lower.ends_with(".gz") {
        let mut out = Vec::new();
        let mut dec = GzDecoder::new(payload.as_slice());
        dec.read_to_end(&mut out)?;
        return Ok(out);
    }
    if lower.ends_with(".bz2") {
        let mut out = Vec::new();
        let mut dec = BzDecoder::new(payload.as_slice());
        dec.read_to_end(&mut out)?;
        return Ok(out);
    }
    Ok(payload)
}

fn parse_repodata_primary_href(repomd_xml: &[u8]) -> Option<String> {
    let root = Element::parse(repomd_xml).ok()?;
    let mut data_nodes = Vec::new();
    collect_descendants_by_local(&root, "data", &mut data_nodes);
    for data in data_nodes {
        let Some(data_type) = attr_value(data, "type") else {
            continue;
        };
        if data_type != "primary" {
            continue;
        }
        let mut location_nodes = Vec::new();
        collect_descendants_by_local(data, "location", &mut location_nodes);
        for loc in location_nodes {
            if let Some(href) = attr_value(loc, "href") {
                let v = href.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn parse_primary_packages(primary_xml: &[u8]) -> Vec<PackageCoordinate> {
    let root = match Element::parse(primary_xml) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut packages = Vec::new();
    let mut package_nodes = Vec::new();
    collect_descendants_by_local(&root, "package", &mut package_nodes);
    for pkg in package_nodes {
        let Some(name) = child_text_by_local(pkg, "name") else {
            continue;
        };
        let Some(version_el) = child_by_local(pkg, "version") else {
            continue;
        };
        let ver = attr_value(version_el, "ver").unwrap_or("").trim();
        if ver.is_empty() {
            continue;
        }
        let rel = attr_value(version_el, "rel").unwrap_or("").trim();
        let epoch = attr_value(version_el, "epoch").unwrap_or("").trim();

        let mut full_ver = String::new();
        if !epoch.is_empty() && epoch != "0" {
            full_ver.push_str(epoch);
            full_ver.push(':');
        }
        full_ver.push_str(ver);
        if !rel.is_empty() {
            full_ver.push('-');
            full_ver.push_str(rel);
        }
        packages.push(PackageCoordinate {
            ecosystem: "redhat".into(),
            name,
            version: full_ver,
        });
    }
    packages
}

fn find_entry<'a>(entries: &'a [String], wanted: &str) -> Option<&'a str> {
    let wanted_norm = normalize_path_like(wanted);
    entries
        .iter()
        .find(|e| normalize_path_like(e) == wanted_norm)
        .map(String::as_str)
}

fn normalize_path_like(s: &str) -> String {
    s.trim()
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn dedupe_packages(input: Vec<PackageCoordinate>) -> Vec<PackageCoordinate> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for pkg in input {
        let key = format!("{}|{}", pkg.name, pkg.version);
        if seen.insert(key) {
            out.push(pkg);
        }
    }
    out.sort_by(|a, b| {
        let ka = (&a.name, &a.version);
        let kb = (&b.name, &b.version);
        ka.cmp(&kb)
    });
    out
}

fn child_by_local<'a>(el: &'a Element, target: &str) -> Option<&'a Element> {
    el.children.iter().find_map(|node| {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                return Some(child);
            }
        }
        None
    })
}

fn child_text_by_local(el: &Element, target: &str) -> Option<String> {
    child_by_local(el, target).map(element_text)
}

fn attr_value<'a>(el: &'a Element, key: &str) -> Option<&'a str> {
    if let Some(v) = el.attributes.get(key) {
        return Some(v);
    }
    for (k, v) in &el.attributes {
        if local_name(k).eq_ignore_ascii_case(key) {
            return Some(v);
        }
    }
    None
}

fn collect_descendants_by_local<'a>(el: &'a Element, target: &str, out: &mut Vec<&'a Element>) {
    for node in &el.children {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                out.push(child);
            }
            collect_descendants_by_local(child, target, out);
        }
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn element_text(el: &Element) -> String {
    let mut out = String::new();
    append_text(el, &mut out);
    out.trim().to_string()
}

fn append_text(el: &Element, out: &mut String) {
    for node in &el.children {
        match node {
            XMLNode::Element(child) => append_text(child, out),
            XMLNode::Text(text) | XMLNode::CData(text) => {
                let t = text.trim();
                if t.is_empty() {
                    continue;
                }
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(t);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            },
            PackageCoordinate {
                ecosystem: "redhat".into(),
                name: "bash".into(),
                version: "5.1-1".into(),
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
}
