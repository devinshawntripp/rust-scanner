use std::collections::HashSet;

use regex::Regex;
use xmltree::{Element, XMLNode};

/// Strip namespace prefix from an XML element name.
pub(super) fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Concatenate all text content from an XML element tree.
pub(super) fn element_text(el: &Element) -> String {
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

/// Get a named attribute value from an XML element (namespace-aware).
pub(super) fn attr_value<'a>(el: &'a Element, key: &str) -> Option<&'a str> {
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

/// Find the first child element matching the given local name.
pub(super) fn child_by_local<'a>(el: &'a Element, target: &str) -> Option<&'a Element> {
    el.children.iter().find_map(|node| {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                return Some(child);
            }
        }
        None
    })
}

/// Get text content of the first child element matching the given local name.
pub(super) fn child_text_by_local(el: &Element, target: &str) -> Option<String> {
    child_by_local(el, target).map(element_text)
}

/// Collect direct children matching the given local name.
pub(super) fn collect_children_by_local<'a>(
    el: &'a Element,
    target: &str,
    out: &mut Vec<&'a Element>,
) {
    for node in &el.children {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                out.push(child);
            }
        }
    }
}

/// Recursively collect all descendant elements matching the given local name.
pub(super) fn collect_descendants_by_local<'a>(
    el: &'a Element,
    target: &str,
    out: &mut Vec<&'a Element>,
) {
    for node in &el.children {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                out.push(child);
            }
            collect_descendants_by_local(child, target, out);
        }
    }
}

/// Extract all CVE IDs from an OVAL definition element's metadata.
pub(super) fn extract_cves_from_definition(
    definition: &Element,
    cve_re: &Regex,
) -> HashSet<String> {
    let mut out = HashSet::new();

    let mut references = Vec::new();
    collect_descendants_by_local(definition, "reference", &mut references);
    for reference in references {
        for value in reference.attributes.values() {
            for m in cve_re.find_iter(value) {
                out.insert(m.as_str().to_ascii_uppercase());
            }
        }
        let txt = element_text(reference);
        for m in cve_re.find_iter(&txt) {
            out.insert(m.as_str().to_ascii_uppercase());
        }
    }

    for field in ["title", "description"] {
        let mut nodes = Vec::new();
        collect_descendants_by_local(definition, field, &mut nodes);
        for node in nodes {
            let txt = element_text(node);
            for m in cve_re.find_iter(&txt) {
                out.insert(m.as_str().to_ascii_uppercase());
            }
        }
    }

    out
}

/// Parse an OVAL comparison operation string into a `CompareOp`.
pub(super) fn parse_compare_op(op: &str) -> Option<super::oval::CompareOp> {
    let norm = op.trim().to_ascii_lowercase();
    match norm.as_str() {
        "less than" => Some(super::oval::CompareOp::LessThan),
        "less than or equal" => Some(super::oval::CompareOp::LessThanOrEqual),
        "greater than" => Some(super::oval::CompareOp::GreaterThan),
        "greater than or equal" => Some(super::oval::CompareOp::GreaterThanOrEqual),
        "equal" | "equals" => Some(super::oval::CompareOp::Equal),
        _ => None,
    }
}
