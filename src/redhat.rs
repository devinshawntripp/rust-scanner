use crate::container::PackageCoordinate;
use crate::report::Finding;
use anyhow::Context;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use xmltree::{Element, XMLNode};

#[derive(Debug, Clone, Default)]
pub struct OvalFilterStats {
    pub definitions_total: usize,
    pub definitions_evaluable: usize,
    pub covered_cves: usize,
    pub vulnerable_cves: usize,
    pub findings_before: usize,
    pub findings_after: usize,
    pub findings_filtered: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriState {
    True,
    False,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum CompareOp {
    LessThan,
    LessThanOrEqual,
    Equal,
    GreaterThanOrEqual,
    GreaterThan,
}

#[derive(Debug, Clone)]
struct StateConstraint {
    op: CompareOp,
    evr: String,
}

#[derive(Debug, Clone)]
struct RpmConstraint {
    package: String,
    op: CompareOp,
    evr: String,
}

#[derive(Debug)]
struct ParsedOval {
    root: Element,
    test_constraints: HashMap<String, Vec<RpmConstraint>>,
}

#[derive(Debug, Default)]
struct OvalEval {
    definitions_total: usize,
    definitions_evaluable: usize,
    covered_cves: HashSet<String>,
    vulnerable_cves: HashSet<String>,
}

pub fn filter_findings_with_redhat_oval(
    findings: &mut Vec<Finding>,
    packages: &[PackageCoordinate],
    oval_path: &str,
) -> anyhow::Result<OvalFilterStats> {
    let parsed = parse_oval_file(oval_path)?;
    let package_map = build_rpm_package_map(packages);
    let eval = evaluate_oval_for_packages(&parsed.root, &parsed.test_constraints, &package_map);

    let findings_before = findings.len();

    for finding in findings.iter_mut() {
        if !finding.id.starts_with("CVE-") {
            continue;
        }
        let id = finding.id.to_ascii_uppercase();
        let Some(pkg) = finding.package.as_ref() else {
            continue;
        };
        if !is_rpm_ecosystem(&pkg.ecosystem) {
            continue;
        }
        if eval.covered_cves.contains(&id) && eval.vulnerable_cves.contains(&id) {
            finding.fixed = Some(false);
        }
    }

    findings.retain(|finding| {
        if !finding.id.starts_with("CVE-") {
            return true;
        }
        let Some(pkg) = finding.package.as_ref() else {
            return true;
        };
        if !is_rpm_ecosystem(&pkg.ecosystem) {
            return true;
        }
        let id = finding.id.to_ascii_uppercase();
        if eval.covered_cves.contains(&id) {
            return eval.vulnerable_cves.contains(&id);
        }
        true
    });

    let findings_after = findings.len();
    Ok(OvalFilterStats {
        definitions_total: eval.definitions_total,
        definitions_evaluable: eval.definitions_evaluable,
        covered_cves: eval.covered_cves.len(),
        vulnerable_cves: eval.vulnerable_cves.len(),
        findings_before,
        findings_after,
        findings_filtered: findings_before.saturating_sub(findings_after),
    })
}

/// Generate new findings AND filter existing ones from RHEL OVAL data in a single parse.
///
/// Returns `(generated_count, filter_stats)`. New findings are appended to `findings`
/// (deduplicated by `(cve_id, package_name)`) before the filter pass runs.
pub fn apply_redhat_oval_enrichment(
    findings: &mut Vec<Finding>,
    packages: &[PackageCoordinate],
    oval_path: &str,
) -> anyhow::Result<(usize, OvalFilterStats)> {
    let parsed = parse_oval_file(oval_path)?;
    let package_map = build_rpm_package_map(packages);

    // Step 1: generate new findings from OVAL that OSV may have missed
    let new_findings = generate_from_parsed_oval(&parsed, &package_map, packages);

    // Merge, deduplicating by (cve|package_name)
    let existing_keys: HashSet<String> = findings
        .iter()
        .map(|f| {
            format!(
                "{}|{}",
                f.id,
                f.package.as_ref().map_or("", |p| p.name.as_str())
            )
        })
        .collect();
    let mut generated_count = 0usize;
    for f in new_findings {
        let key = format!(
            "{}|{}",
            f.id,
            f.package.as_ref().map_or("", |p| p.name.as_str())
        );
        if !existing_keys.contains(&key) {
            findings.push(f);
            generated_count += 1;
        }
    }

    // Step 2: filter using OVAL (removes findings for CVEs OVAL says are patched)
    let eval = evaluate_oval_for_packages(&parsed.root, &parsed.test_constraints, &package_map);

    let findings_before = findings.len();

    for finding in findings.iter_mut() {
        if !finding.id.starts_with("CVE-") {
            continue;
        }
        let id = finding.id.to_ascii_uppercase();
        let Some(pkg) = finding.package.as_ref() else {
            continue;
        };
        if !is_rpm_ecosystem(&pkg.ecosystem) {
            continue;
        }
        if eval.covered_cves.contains(&id) && eval.vulnerable_cves.contains(&id) {
            finding.fixed = Some(false);
        }
    }

    findings.retain(|finding| {
        if !finding.id.starts_with("CVE-") {
            return true;
        }
        let Some(pkg) = finding.package.as_ref() else {
            return true;
        };
        if !is_rpm_ecosystem(&pkg.ecosystem) {
            return true;
        }
        let id = finding.id.to_ascii_uppercase();
        if eval.covered_cves.contains(&id) {
            return eval.vulnerable_cves.contains(&id);
        }
        true
    });

    let findings_after = findings.len();
    let stats = OvalFilterStats {
        definitions_total: eval.definitions_total,
        definitions_evaluable: eval.definitions_evaluable,
        covered_cves: eval.covered_cves.len(),
        vulnerable_cves: eval.vulnerable_cves.len(),
        findings_before,
        findings_after,
        findings_filtered: findings_before.saturating_sub(findings_after),
    };

    Ok((generated_count, stats))
}

/// Generate `Finding`s from a pre-parsed OVAL file by iterating per-package test constraints.
///
/// This supplements OSV lookups by directly evaluating the RHEL OVAL advisory data.
/// Package version comparisons use the same `compare_evr`/`rpmvercmp` logic as the filter.
fn generate_from_parsed_oval(
    parsed: &ParsedOval,
    package_map: &HashMap<String, Vec<String>>,
    packages: &[PackageCoordinate],
) -> Vec<Finding> {
    use crate::report::{ConfidenceTier, EvidenceSource, PackageInfo, ReferenceInfo};

    if package_map.is_empty() {
        return Vec::new();
    }

    let cve_re = Regex::new(r"CVE-\d{4}-\d+").expect("valid CVE regex");
    let mut definitions = Vec::new();
    collect_descendants_by_local(&parsed.root, "definition", &mut definitions);

    // Build ecosystem lookup: package_name → original distro ecosystem
    let name_to_ecosystem: HashMap<String, String> = packages
        .iter()
        .filter(|p| is_rpm_ecosystem(&p.ecosystem))
        .map(|p| (p.name.clone(), p.ecosystem.clone()))
        .collect();

    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new(); // keys: "cve|package_name"

    for definition in definitions {
        let cves = extract_cves_from_definition(definition, &cve_re);
        if cves.is_empty() {
            continue;
        }

        // Collect all test_refs referenced anywhere in this definition's criteria tree
        let mut test_refs: Vec<String> = Vec::new();
        collect_test_refs_from_element(definition, &mut test_refs);

        for test_ref in &test_refs {
            let Some(constraints) = parsed.test_constraints.get(test_ref) else {
                continue;
            };
            for constraint in constraints {
                // Skip OS/distro version-gating packages (e.g. redhat-release, rocky-release)
                if is_release_gating_package(&constraint.package) {
                    continue;
                }

                let Some(installed_versions) = package_map.get(&constraint.package) else {
                    continue;
                };

                // Evaluate: does the installed version satisfy the vulnerability condition?
                // Typically: LessThan means installed < fixed_evr → vulnerable.
                let is_vulnerable = installed_versions.iter().any(|installed| {
                    let ord = compare_evr(installed, &constraint.evr);
                    match constraint.op {
                        CompareOp::LessThan => ord == Ordering::Less,
                        CompareOp::LessThanOrEqual => ord != Ordering::Greater,
                        CompareOp::Equal => ord == Ordering::Equal,
                        CompareOp::GreaterThanOrEqual => ord != Ordering::Less,
                        CompareOp::GreaterThan => ord == Ordering::Greater,
                    }
                });

                if !is_vulnerable {
                    continue;
                }

                let ecosystem = name_to_ecosystem
                    .get(&constraint.package)
                    .cloned()
                    .unwrap_or_else(|| "rpm".to_string());
                let installed_version =
                    installed_versions.first().cloned().unwrap_or_default();

                for cve in &cves {
                    let key = format!("{}|{}", cve, constraint.package);
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);

                    let nvd_url = format!(
                        "https://nvd.nist.gov/vuln/detail/{}",
                        cve
                    );
                    findings.push(Finding {
                        id: cve.clone(),
                        source_ids: vec!["redhat-oval".to_string()],
                        package: Some(PackageInfo {
                            name: constraint.package.clone(),
                            ecosystem: ecosystem.clone(),
                            version: installed_version.clone(),
                        }),
                        confidence_tier: ConfidenceTier::ConfirmedInstalled,
                        evidence_source: EvidenceSource::InstalledDb,
                        accuracy_note: Some("redhat-oval".to_string()),
                        fixed: Some(false),
                        fixed_in: Some(constraint.evr.clone()),
                        recommendation: Some(format!(
                            "Update {} to {}",
                            constraint.package, constraint.evr
                        )),
                        severity: None,
                        cvss: None,
                        description: None,
                        evidence: vec![],
                        references: vec![ReferenceInfo {
                            reference_type: "WEB".to_string(),
                            url: nvd_url,
                        }],
                        confidence: None,
                        epss_score: None,
                        epss_percentile: None,
                        in_kev: None,
                    });
                }
            }
        }
    }

    findings
}

/// Collect all `test_ref` attribute values from all `criterion` elements in the subtree.
fn collect_test_refs_from_element(el: &Element, out: &mut Vec<String>) {
    for node in &el.children {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == "criterion" {
                if let Some(test_ref) = attr_value(child, "test_ref") {
                    out.push(test_ref.to_string());
                }
            }
            collect_test_refs_from_element(child, out);
        }
    }
}

/// Returns true for OS version-gating packages that should not generate findings.
fn is_release_gating_package(name: &str) -> bool {
    // e.g. redhat-release, redhat-release-server, rocky-release, centos-release, etc.
    name.ends_with("-release")
        || name.ends_with("-release-server")
        || name == "redhat-release-workstation"
        || name == "oraclelinux-release"
        || name.starts_with("centos-linux-release")
}

/// Check if a CVE exists in a Red Hat OVAL XML file
pub fn check_redhat_cve(cve: &str, oval_path: &str) {
    let parsed = match parse_oval_file(oval_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to parse OVAL file: {}", e);
            return;
        }
    };
    let cve_re = Regex::new(r"CVE-\d{4}-\d+").expect("valid CVE regex");
    let needle = cve.trim().to_ascii_uppercase();

    let mut definitions = Vec::new();
    collect_descendants_by_local(&parsed.root, "definition", &mut definitions);
    for definition in definitions {
        let cves = extract_cves_from_definition(definition, &cve_re);
        if cves.contains(&needle) {
            println!("✅ Found in Red Hat OVAL: {}", needle);
            return;
        }
    }

    println!("❌ {} not found in Red Hat OVAL definitions.", needle);
}

fn parse_oval_file(oval_path: &str) -> anyhow::Result<ParsedOval> {
    let file = File::open(oval_path)
        .with_context(|| format!("could not open OVAL file at {}", oval_path))?;
    let reader = BufReader::new(file);
    let root = Element::parse(reader)
        .with_context(|| format!("failed to parse OVAL XML at {}", oval_path))?;
    let test_constraints = build_test_constraints(&root);
    Ok(ParsedOval {
        root,
        test_constraints,
    })
}

fn evaluate_oval_for_packages(
    root: &Element,
    tests: &HashMap<String, Vec<RpmConstraint>>,
    packages: &HashMap<String, Vec<String>>,
) -> OvalEval {
    let cve_re = Regex::new(r"CVE-\d{4}-\d+").expect("valid CVE regex");
    let mut eval = OvalEval::default();
    let mut definitions = Vec::new();
    collect_descendants_by_local(root, "definition", &mut definitions);

    for definition in definitions {
        let cves = extract_cves_from_definition(definition, &cve_re);
        if cves.is_empty() {
            continue;
        }

        eval.definitions_total += 1;
        let state = evaluate_definition(definition, tests, packages);
        if state == TriState::Unknown {
            continue;
        }

        eval.definitions_evaluable += 1;
        for cve in cves {
            eval.covered_cves.insert(cve.clone());
            if state == TriState::True {
                eval.vulnerable_cves.insert(cve);
            }
        }
    }
    eval
}

fn evaluate_definition(
    definition: &Element,
    tests: &HashMap<String, Vec<RpmConstraint>>,
    packages: &HashMap<String, Vec<String>>,
) -> TriState {
    let mut criteria_nodes = Vec::new();
    collect_children_by_local(definition, "criteria", &mut criteria_nodes);
    if criteria_nodes.is_empty() {
        return TriState::Unknown;
    }

    let mut states = Vec::new();
    for criteria in criteria_nodes {
        states.push(evaluate_criteria(criteria, tests, packages));
    }
    combine_states(&states, false)
}

fn evaluate_criteria(
    criteria: &Element,
    tests: &HashMap<String, Vec<RpmConstraint>>,
    packages: &HashMap<String, Vec<String>>,
) -> TriState {
    let is_or = attr_value(criteria, "operator")
        .map(|v| v.eq_ignore_ascii_case("OR"))
        .unwrap_or(false);

    let mut states = Vec::new();
    for child in &criteria.children {
        if let XMLNode::Element(el) = child {
            let name = local_name(&el.name);
            if name == "criteria" {
                states.push(evaluate_criteria(el, tests, packages));
            } else if name == "criterion" {
                states.push(evaluate_criterion(el, tests, packages));
            } else if name == "extend_definition" {
                states.push(TriState::Unknown);
            }
        }
    }

    combine_states(&states, is_or)
}

fn evaluate_criterion(
    criterion: &Element,
    tests: &HashMap<String, Vec<RpmConstraint>>,
    packages: &HashMap<String, Vec<String>>,
) -> TriState {
    let Some(test_ref) = attr_value(criterion, "test_ref") else {
        return TriState::Unknown;
    };
    let Some(constraints) = tests.get(test_ref) else {
        return TriState::Unknown;
    };
    if constraints.is_empty() {
        return TriState::Unknown;
    }

    let mut matched = false;
    for constraint in constraints {
        if package_matches_constraint(packages, constraint) {
            matched = true;
            break;
        }
    }
    if matched {
        TriState::True
    } else {
        TriState::False
    }
}

fn combine_states(states: &[TriState], is_or: bool) -> TriState {
    if states.is_empty() {
        return TriState::Unknown;
    }
    if is_or {
        if states.iter().any(|s| *s == TriState::True) {
            return TriState::True;
        }
        if states.iter().all(|s| *s == TriState::False) {
            return TriState::False;
        }
        TriState::Unknown
    } else {
        if states.iter().any(|s| *s == TriState::False) {
            return TriState::False;
        }
        if states.iter().all(|s| *s == TriState::True) {
            return TriState::True;
        }
        TriState::Unknown
    }
}

fn build_test_constraints(root: &Element) -> HashMap<String, Vec<RpmConstraint>> {
    let object_map = build_rpm_object_map(root);
    let state_map = build_rpm_state_map(root);

    let mut out: HashMap<String, Vec<RpmConstraint>> = HashMap::new();
    let mut tests = Vec::new();
    collect_descendants_by_local(root, "rpminfo_test", &mut tests);
    for test in tests {
        let Some(test_id) = attr_value(test, "id") else {
            continue;
        };

        let mut object_ref: Option<&str> = None;
        let mut state_refs: Vec<&str> = Vec::new();
        for child in &test.children {
            if let XMLNode::Element(el) = child {
                let name = local_name(&el.name);
                if name == "object" {
                    object_ref = attr_value(el, "object_ref");
                } else if name == "state" {
                    if let Some(state_ref) = attr_value(el, "state_ref") {
                        state_refs.push(state_ref);
                    }
                }
            }
        }

        let Some(object_ref) = object_ref else {
            continue;
        };
        let Some(package_name) = object_map.get(object_ref) else {
            continue;
        };

        let mut constraints = Vec::new();
        for state_ref in state_refs {
            let Some(state) = state_map.get(state_ref) else {
                continue;
            };
            constraints.push(RpmConstraint {
                package: package_name.clone(),
                op: state.op,
                evr: state.evr.clone(),
            });
        }
        if !constraints.is_empty() {
            out.insert(test_id.to_string(), constraints);
        }
    }
    out
}

fn build_rpm_object_map(root: &Element) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut objects = Vec::new();
    collect_descendants_by_local(root, "rpminfo_object", &mut objects);
    for object in objects {
        let Some(id) = attr_value(object, "id") else {
            continue;
        };
        let Some(name) = child_text_by_local(object, "name") else {
            continue;
        };
        let pkg = name.trim();
        if pkg.is_empty() {
            continue;
        }
        out.insert(id.to_string(), pkg.to_string());
    }
    out
}

fn build_rpm_state_map(root: &Element) -> HashMap<String, StateConstraint> {
    let mut out = HashMap::new();
    let mut states = Vec::new();
    collect_descendants_by_local(root, "rpminfo_state", &mut states);
    for state in states {
        let Some(id) = attr_value(state, "id") else {
            continue;
        };
        let Some(evr_el) = child_by_local(state, "evr") else {
            continue;
        };
        let evr = element_text(evr_el).trim().to_string();
        if evr.is_empty() {
            continue;
        }
        let op = attr_value(evr_el, "operation")
            .and_then(parse_compare_op)
            .unwrap_or(CompareOp::Equal);
        out.insert(id.to_string(), StateConstraint { op, evr });
    }
    out
}

fn build_rpm_package_map(packages: &[PackageCoordinate]) -> HashMap<String, Vec<String>> {
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

pub fn is_rpm_ecosystem(ecosystem: &str) -> bool {
    matches!(
        ecosystem,
        "redhat" | "rpm" | "rocky" | "almalinux" | "suse" | "opensuse" | "centos" | "fedora"
    )
}

fn package_matches_constraint(
    packages: &HashMap<String, Vec<String>>,
    constraint: &RpmConstraint,
) -> bool {
    let Some(installed_versions) = packages.get(&constraint.package) else {
        return false;
    };

    installed_versions.iter().any(|installed| {
        let ord = compare_evr(installed, &constraint.evr);
        match constraint.op {
            CompareOp::LessThan => ord == Ordering::Less,
            CompareOp::LessThanOrEqual => ord != Ordering::Greater,
            CompareOp::Equal => ord == Ordering::Equal,
            CompareOp::GreaterThanOrEqual => ord != Ordering::Less,
            CompareOp::GreaterThan => ord == Ordering::Greater,
        }
    })
}

fn parse_compare_op(op: &str) -> Option<CompareOp> {
    let norm = op.trim().to_ascii_lowercase();
    match norm.as_str() {
        "less than" => Some(CompareOp::LessThan),
        "less than or equal" => Some(CompareOp::LessThanOrEqual),
        "greater than" => Some(CompareOp::GreaterThan),
        "greater than or equal" => Some(CompareOp::GreaterThanOrEqual),
        "equal" | "equals" => Some(CompareOp::Equal),
        _ => None,
    }
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

fn extract_cves_from_definition(definition: &Element, cve_re: &Regex) -> HashSet<String> {
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

fn collect_children_by_local<'a>(el: &'a Element, target: &str, out: &mut Vec<&'a Element>) {
    for node in &el.children {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                out.push(child);
            }
        }
    }
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

/// Detect the Red Hat OVAL major version from an RPM ecosystem string and/or package metadata.
pub fn detect_rhel_major_version(packages: &[crate::container::PackageCoordinate]) -> Option<u32> {
    // Look at release tags in package versions: e.g. "5.1.8-6.el9" → 9
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
    packages: &[crate::container::PackageCoordinate],
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
                    crate::utils::progress(
                        "oval.auto.cache_hit",
                        &oval_xml_path.to_string_lossy(),
                    );
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
            crate::utils::progress(
                "oval.auto.download.error",
                &format!("HTTP {}", r.status()),
            );
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
    fn test_oval_eval_with_rpm_constraints() {
        let xml = r#"
<oval_definitions xmlns:rpm-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:def:1" class="vulnerability">
      <metadata>
        <title>CVE-2024-1111 in bash</title>
        <reference source="CVE" ref_id="CVE-2024-1111"/>
      </metadata>
      <criteria>
        <criterion test_ref="oval:test:1"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <rpm-def:rpminfo_test id="oval:test:1">
      <rpm-def:object object_ref="oval:obj:1"/>
      <rpm-def:state state_ref="oval:state:1"/>
    </rpm-def:rpminfo_test>
  </tests>
  <objects>
    <rpm-def:rpminfo_object id="oval:obj:1">
      <rpm-def:name>bash</rpm-def:name>
    </rpm-def:rpminfo_object>
  </objects>
  <states>
    <rpm-def:rpminfo_state id="oval:state:1">
      <rpm-def:evr operation="less than">0:5.1-5.el9</rpm-def:evr>
    </rpm-def:rpminfo_state>
  </states>
</oval_definitions>
"#;
        let root = Element::parse(xml.as_bytes()).expect("xml parse");
        let tests = build_test_constraints(&root);

        let mut package_map = HashMap::new();
        package_map.insert("bash".to_string(), vec!["5.1-3.el9".to_string()]);
        let eval = evaluate_oval_for_packages(&root, &tests, &package_map);
        assert!(eval.covered_cves.contains("CVE-2024-1111"));
        assert!(eval.vulnerable_cves.contains("CVE-2024-1111"));

        package_map.insert("bash".to_string(), vec!["5.1-7.el9".to_string()]);
        let eval_fixed = evaluate_oval_for_packages(&root, &tests, &package_map);
        assert!(eval_fixed.covered_cves.contains("CVE-2024-1111"));
        assert!(!eval_fixed.vulnerable_cves.contains("CVE-2024-1111"));
    }
}
