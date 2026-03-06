//! Repodata XML parsing and XML helper utilities for ISO scanning.

use crate::container::PackageCoordinate;
use crate::utils::progress;
use super::comps::{parse_comps_xml, CompsData};
use super::extract::*;
use anyhow::anyhow;
use std::collections::HashSet;
use xmltree::{Element, XMLNode};

pub(super) fn packages_from_repodata(
    path: &str,
    entries: &[String],
) -> anyhow::Result<Vec<PackageCoordinate>> {
    progress("iso.repodata.start", "repomd.xml");
    let repos = find_repomd_entries(entries);
    if repos.is_empty() {
        return Ok(Vec::new());
    }
    let mut all_packages = Vec::new();
    for (prefix, repomd_entry) in &repos {
        let repomd_raw = read_iso_entry(path, repomd_entry)?;
        let Some(primary_href) = parse_repodata_primary_href(&repomd_raw) else {
            continue;
        };
        let resolved = resolve_href(prefix, &primary_href);
        let Some(primary_entry) = find_entry(entries, &resolved) else {
            progress(
                "iso.repodata.primary.missing",
                &format!("not found: {}", resolved),
            );
            continue;
        };
        let primary_raw = read_iso_entry(path, primary_entry)?;
        let primary_xml = decompress_if_needed(primary_entry, primary_raw)?;
        let pkgs = parse_primary_packages(&primary_xml);
        progress(
            "iso.repodata.repo",
            &format!("prefix={} packages={}", if prefix.is_empty() { "(root)" } else { prefix }, pkgs.len()),
        );
        all_packages.extend(pkgs);
    }
    Ok(all_packages)
}

/// Find all repomd.xml entries in the ISO, returning (prefix, entry_path) pairs.
/// Checks root `repodata/repomd.xml` and subdirectory patterns like `BaseOS/repodata/repomd.xml`.
fn find_repomd_entries<'a>(entries: &'a [String]) -> Vec<(String, &'a str)> {
    let suffix = "repodata/repomd.xml";
    let mut results = Vec::new();
    for entry in entries {
        let norm = normalize_path_like(entry);
        if norm == suffix {
            results.push(("".to_string(), entry.as_str()));
        } else if norm.ends_with(&format!("/{}", suffix)) {
            let prefix = &norm[..norm.len() - suffix.len()];
            results.push((prefix.to_string(), entry.as_str()));
        }
    }
    results
}

/// Resolve a relative href from repomd.xml against the repo prefix directory.
/// e.g., prefix="BaseOS/", href="repodata/hash-primary.xml.gz" → "BaseOS/repodata/hash-primary.xml.gz"
fn resolve_href(prefix: &str, href: &str) -> String {
    if prefix.is_empty() {
        href.to_string()
    } else {
        format!("{}{}", prefix, href)
    }
}

pub(super) fn parse_repodata_primary_href(repomd_xml: &[u8]) -> Option<String> {
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

pub(super) fn parse_repodata_comps_href(repomd_xml: &[u8]) -> Option<String> {
    let root = Element::parse(repomd_xml).ok()?;
    let mut data_nodes = Vec::new();
    collect_descendants_by_local(&root, "data", &mut data_nodes);
    for data in data_nodes {
        let Some(data_type) = attr_value(data, "type") else {
            continue;
        };
        if data_type != "group" {
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

/// Load comps.xml from repodata and return the default-install package names.
/// Returns (environment_name, package_names, full_comps_data).
/// Searches all repos (BaseOS/, AppStream/, root) and uses the first with a
/// valid comps.xml containing installation environments.
pub(super) fn comps_package_names_from_repodata(
    path: &str,
    entries: &[String],
) -> anyhow::Result<Option<(String, HashSet<String>, CompsData)>> {
    let repos = find_repomd_entries(entries);
    if repos.is_empty() {
        return Ok(None);
    }
    for (prefix, repomd_entry) in &repos {
        let repomd_raw = read_iso_entry(path, repomd_entry)?;
        let Some(comps_href) = parse_repodata_comps_href(&repomd_raw) else {
            continue;
        };
        let resolved = resolve_href(prefix, &comps_href);
        let Some(comps_entry) = find_entry(entries, &resolved) else {
            progress(
                "iso.comps.entry.missing",
                &format!("not found: {}", resolved),
            );
            continue;
        };
        let comps_raw = read_iso_entry(path, comps_entry)?;
        let comps_xml = decompress_if_needed(comps_entry, comps_raw)?;
        let comps_data = parse_comps_xml(&comps_xml)?;
        let (env_name, package_names) = comps_data.default_install_packages();
        if let Some(name) = env_name {
            progress(
                "iso.comps.found",
                &format!("prefix={} environment={}", if prefix.is_empty() { "(root)" } else { prefix }, name),
            );
            return Ok(Some((name, package_names, comps_data)));
        }
    }
    Ok(None)
}

pub(super) fn parse_primary_packages(primary_xml: &[u8]) -> Vec<PackageCoordinate> {
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
            source_name: None,
        });
    }
    packages
}

// --- XML helpers ---

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
    fn test_find_repomd_entries_root() {
        let entries = vec![
            "repodata/repomd.xml".to_string(),
            "repodata/abc-primary.xml.gz".to_string(),
            "Packages/foo.rpm".to_string(),
        ];
        let found = find_repomd_entries(&entries);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "");
        assert_eq!(found[0].1, "repodata/repomd.xml");
    }

    #[test]
    fn test_find_repomd_entries_subdirs() {
        let entries = vec![
            "BaseOS/repodata/repomd.xml".to_string(),
            "BaseOS/repodata/abc-primary.xml.gz".to_string(),
            "AppStream/repodata/repomd.xml".to_string(),
            "AppStream/repodata/def-primary.xml.gz".to_string(),
            "Packages/foo.rpm".to_string(),
        ];
        let found = find_repomd_entries(&entries);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, "BaseOS/");
        assert_eq!(found[1].0, "AppStream/");
    }

    #[test]
    fn test_find_repomd_entries_leading_dot_slash() {
        let entries = vec![
            "./BaseOS/repodata/repomd.xml".to_string(),
        ];
        let found = find_repomd_entries(&entries);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "BaseOS/");
    }

    #[test]
    fn test_resolve_href_with_prefix() {
        assert_eq!(
            resolve_href("BaseOS/", "repodata/abc-primary.xml.gz"),
            "BaseOS/repodata/abc-primary.xml.gz"
        );
    }

    #[test]
    fn test_resolve_href_root() {
        assert_eq!(
            resolve_href("", "repodata/abc-primary.xml.gz"),
            "repodata/abc-primary.xml.gz"
        );
    }

    #[test]
    fn test_parse_repodata_primary_href_rhel10() {
        let repomd = br#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/579c0ab-primary.xml.gz"/>
  </data>
  <data type="group">
    <location href="repodata/efbe7f7-comps-BaseOS.x86_64.xml"/>
  </data>
</repomd>"#;
        let href = parse_repodata_primary_href(repomd).unwrap();
        assert_eq!(href, "repodata/579c0ab-primary.xml.gz");
    }

    #[test]
    fn test_parse_repodata_comps_href_rhel10() {
        let repomd = br#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/579c0ab-primary.xml.gz"/>
  </data>
  <data type="group">
    <location href="repodata/efbe7f7-comps-BaseOS.x86_64.xml"/>
  </data>
</repomd>"#;
        let href = parse_repodata_comps_href(repomd).unwrap();
        assert_eq!(href, "repodata/efbe7f7-comps-BaseOS.x86_64.xml");
    }
}
