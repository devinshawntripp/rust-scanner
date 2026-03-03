//! Repodata XML parsing and XML helper utilities for ISO scanning.

use crate::container::PackageCoordinate;
use crate::utils::progress;
use super::extract::*;
use anyhow::anyhow;
use xmltree::{Element, XMLNode};

pub(super) fn packages_from_repodata(
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
