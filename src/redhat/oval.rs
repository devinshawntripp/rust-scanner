use crate::container::PackageCoordinate;
use crate::report::Finding;
use anyhow::Context;
use postgres::Client as PgClient;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;

use xmltree::{Element, XMLNode};

use super::evr::{build_rpm_package_map, compare_evr, is_release_gating_package, is_rpm_ecosystem};
use super::xml_helpers::{
    attr_value, child_by_local, child_text_by_local, collect_children_by_local,
    collect_descendants_by_local, element_text, extract_cves_from_definition, local_name,
    parse_compare_op,
};

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) enum CompareOp {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Pre-processed definition data that can be cached to avoid re-parsing XML.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedDefinition {
    cves: Vec<String>,
    test_refs: Vec<String>,
}

/// Cached representation of all data needed from parsed OVAL XML.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedOvalData {
    test_constraints: HashMap<String, Vec<RpmConstraint>>,
    definitions: Vec<CachedDefinition>,
}

fn resolve_oval_cache_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("SCANNER_CACHE") {
        if !dir.is_empty() {
            return Some(std::path::PathBuf::from(dir));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Some(
            std::path::PathBuf::from(home)
                .join(".scanrook")
                .join("cache"),
        );
    }
    None
}

fn load_cached_oval(oval_path: &str) -> Option<CachedOvalData> {
    let file_hash = crate::utils::hash_file_stream(oval_path).ok()?;
    let cache_dir = resolve_oval_cache_dir()?;
    let cache_key = format!("oval_parsed_{}.json", &file_hash[..16]);
    let data = crate::cache::cache_get(Some(cache_dir.as_path()), &cache_key)?;
    serde_json::from_slice(&data).ok()
}

fn store_cached_oval(oval_path: &str, cached: &CachedOvalData) {
    let file_hash = match crate::utils::hash_file_stream(oval_path) {
        Ok(h) => h,
        Err(_) => return,
    };
    let cache_dir = match resolve_oval_cache_dir() {
        Some(d) => d,
        None => return,
    };
    let cache_key = format!("oval_parsed_{}.json", &file_hash[..16]);
    if let Ok(data) = serde_json::to_vec(cached) {
        crate::cache::cache_put(Some(cache_dir.as_path()), &cache_key, &data);
    }
}

fn build_cached_oval_data(
    root: &Element,
    test_constraints: HashMap<String, Vec<RpmConstraint>>,
) -> CachedOvalData {
    let cve_re = Regex::new(r"CVE-\d{4}-\d+").expect("valid CVE regex");
    let mut definitions_out = Vec::new();

    let mut raw_defs = Vec::new();
    collect_descendants_by_local(root, "definition", &mut raw_defs);

    for definition in raw_defs {
        let cves_set = extract_cves_from_definition(definition, &cve_re);
        if cves_set.is_empty() {
            continue;
        }
        let mut test_refs = Vec::new();
        collect_test_refs_from_element(definition, &mut test_refs);

        definitions_out.push(CachedDefinition {
            cves: cves_set.into_iter().collect(),
            test_refs,
        });
    }

    CachedOvalData {
        test_constraints,
        definitions: definitions_out,
    }
}

/// Query OVAL data from PostgreSQL (populated by vulndb-pg-import CronJob).
/// Returns None if no data exists for the given RHEL major version.
fn query_oval_from_pg(pg: &mut PgClient, rhel_version: u32) -> Option<CachedOvalData> {
    crate::utils::progress("oval.pg.query.start", &format!("rhel={}", rhel_version));
    let started = std::time::Instant::now();

    let def_rows = pg
        .query(
            "SELECT definition_id, cves, test_refs FROM oval_definitions_cache WHERE rhel_version = $1",
            &[&(rhel_version as i32)],
        )
        .ok()?;

    if def_rows.is_empty() {
        crate::utils::progress("oval.pg.query.empty", &format!("rhel={}", rhel_version));
        return None;
    }

    let definitions: Vec<CachedDefinition> = def_rows
        .iter()
        .map(|row| {
            let cves: Vec<String> = row.get("cves");
            let test_refs: Vec<String> = row.get("test_refs");
            CachedDefinition { cves, test_refs }
        })
        .collect();

    let tc_rows = pg
        .query(
            "SELECT test_ref, package, op, evr FROM oval_test_constraints_cache WHERE rhel_version = $1",
            &[&(rhel_version as i32)],
        )
        .ok()?;

    let mut test_constraints: HashMap<String, Vec<RpmConstraint>> = HashMap::new();
    for row in &tc_rows {
        let test_ref: String = row.get("test_ref");
        let package: String = row.get("package");
        let op_str: String = row.get("op");
        let evr: String = row.get("evr");
        let op = match op_str.as_str() {
            "LT" => CompareOp::LessThan,
            "LE" => CompareOp::LessThanOrEqual,
            "EQ" => CompareOp::Equal,
            "GE" => CompareOp::GreaterThanOrEqual,
            "GT" => CompareOp::GreaterThan,
            _ => CompareOp::LessThan,
        };
        test_constraints
            .entry(test_ref)
            .or_default()
            .push(RpmConstraint { package, op, evr });
    }

    crate::utils::progress_timing("oval.pg.query", started);
    crate::utils::progress(
        "oval.pg.query.done",
        &format!(
            "rhel={} defs={} constraints={}",
            rhel_version,
            definitions.len(),
            tc_rows.len()
        ),
    );

    Some(CachedOvalData {
        test_constraints,
        definitions,
    })
}

/// Load OVAL data for enrichment using the parsed-data cache, falling back to XML parse.
fn load_oval_data(oval_path: &str) -> anyhow::Result<CachedOvalData> {
    // Try cache first
    if let Some(cached) = load_cached_oval(oval_path) {
        crate::utils::progress("oval.cache.hit", oval_path);
        return Ok(cached);
    }

    crate::utils::progress("oval.cache.miss", oval_path);
    let parsed = parse_oval_file(oval_path)?;
    let cached = build_cached_oval_data(&parsed.root, parsed.test_constraints);

    // Store for next time (best-effort)
    store_cached_oval(oval_path, &cached);

    Ok(cached)
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
/// Returns `(generated_count, filter_stats)`. Deduplicates by `(cve_id, package_name)`.
/// Skips `evaluate_oval_for_packages` (RHEL OVAL class="patch" always evaluates Unknown).
///
/// If `pg` is provided, tries PostgreSQL lookup first (populated by vulndb-pg-import CronJob).
/// Falls back to `oval_path` XML parsing if PG has no data or is unavailable.
pub fn apply_redhat_oval_enrichment(
    findings: &mut Vec<Finding>,
    packages: &[PackageCoordinate],
    oval_path: &str,
    pg: Option<&mut PgClient>,
) -> anyhow::Result<(usize, OvalFilterStats)> {
    // Try PG first if available
    let cached = if let Some(client) = pg {
        if let Some(rhel_ver) = super::evr::detect_rhel_major_version(packages) {
            if let Some(pg_cached) = query_oval_from_pg(client, rhel_ver) {
                crate::utils::progress("oval.source", "pg");
                pg_cached
            } else {
                crate::utils::progress("oval.source", "xml-fallback");
                load_oval_data(oval_path)?
            }
        } else {
            load_oval_data(oval_path)?
        }
    } else {
        load_oval_data(oval_path)?
    };
    let package_map = build_rpm_package_map(packages);

    // Step 1: generate new findings from OVAL that OSV may have missed
    let new_findings = generate_from_cached_oval(&cached, &package_map, packages);

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

    // Step 2: Skip evaluate_oval_for_packages — RHEL OVAL class="patch" definitions
    // use extend_definition refs that resolve to Unknown, making evaluable=0 always.
    let findings_before = findings.len();
    let findings_after = findings_before;

    let stats = OvalFilterStats {
        definitions_total: cached.definitions.len(),
        definitions_evaluable: 0,
        covered_cves: 0,
        vulnerable_cves: 0,
        findings_before,
        findings_after,
        findings_filtered: 0,
    };

    Ok((generated_count, stats))
}

fn generate_from_cached_oval(
    cached: &CachedOvalData,
    package_map: &HashMap<String, Vec<String>>,
    packages: &[PackageCoordinate],
) -> Vec<Finding> {
    use crate::report::{ConfidenceTier, EvidenceSource, PackageInfo, ReferenceInfo};

    if package_map.is_empty() {
        return Vec::new();
    }

    // Build ecosystem lookup: package_name -> original distro ecosystem
    let name_to_ecosystem: HashMap<String, String> = packages
        .iter()
        .filter(|p| is_rpm_ecosystem(&p.ecosystem))
        .map(|p| (p.name.clone(), p.ecosystem.clone()))
        .collect();

    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new(); // keys: "cve|package_name"

    for def in &cached.definitions {
        if def.cves.is_empty() {
            continue;
        }

        for test_ref in &def.test_refs {
            let Some(constraints) = cached.test_constraints.get(test_ref) else {
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

                let is_vulnerable = installed_versions
                    .iter()
                    .any(|v| evr_matches_op(v, &constraint.evr, constraint.op));

                if !is_vulnerable {
                    continue;
                }

                let ecosystem = name_to_ecosystem
                    .get(&constraint.package)
                    .cloned()
                    .unwrap_or_else(|| "rpm".to_string());
                let installed_version = installed_versions.first().cloned().unwrap_or_default();

                for cve in &def.cves {
                    let key = format!("{}|{}", cve, constraint.package);
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);

                    let nvd_url = format!("https://nvd.nist.gov/vuln/detail/{}", cve);
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
            println!("Found in Red Hat OVAL: {}", needle);
            return;
        }
    }

    println!("{} not found in Red Hat OVAL definitions.", needle);
}

fn parse_oval_file(oval_path: &str) -> anyhow::Result<ParsedOval> {
    let file = File::open(oval_path)
        .with_context(|| format!("could not open OVAL file at {}", oval_path))?;

    let reader: Box<dyn std::io::Read> = if oval_path.ends_with(".bz2") {
        Box::new(bzip2::read::BzDecoder::new(file))
    } else {
        Box::new(file)
    };

    let buf = BufReader::new(reader);
    let root = Element::parse(buf)
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

/// Check if an installed version matches the given comparison operator against an EVR.
fn evr_matches_op(installed: &str, evr: &str, op: CompareOp) -> bool {
    let ord = compare_evr(installed, evr);
    match op {
        CompareOp::LessThan => ord == Ordering::Less,
        CompareOp::LessThanOrEqual => ord != Ordering::Greater,
        CompareOp::Equal => ord == Ordering::Equal,
        CompareOp::GreaterThanOrEqual => ord != Ordering::Less,
        CompareOp::GreaterThan => ord == Ordering::Greater,
    }
}

fn package_matches_constraint(
    packages: &HashMap<String, Vec<String>>,
    constraint: &RpmConstraint,
) -> bool {
    let Some(installed_versions) = packages.get(&constraint.package) else {
        return false;
    };
    installed_versions
        .iter()
        .any(|v| evr_matches_op(v, &constraint.evr, constraint.op))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_cached_oval_data_roundtrip() {
        let xml = r#"
<oval_definitions xmlns:rpm-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:def:1" class="patch">
      <metadata>
        <title>CVE-2024-1234 fix for openssl</title>
        <reference source="CVE" ref_id="CVE-2024-1234"/>
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
      <rpm-def:name>openssl</rpm-def:name>
    </rpm-def:rpminfo_object>
  </objects>
  <states>
    <rpm-def:rpminfo_state id="oval:state:1">
      <rpm-def:evr operation="less than">1:3.0.7-18.el9</rpm-def:evr>
    </rpm-def:rpminfo_state>
  </states>
</oval_definitions>
"#;
        let root = Element::parse(xml.as_bytes()).expect("xml parse");
        let test_constraints = build_test_constraints(&root);
        let cached = build_cached_oval_data(&root, test_constraints);

        // Serialize and deserialize
        let json = serde_json::to_string(&cached).expect("serialize");
        let restored: CachedOvalData = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(cached.definitions.len(), restored.definitions.len());
        assert_eq!(
            cached.test_constraints.len(),
            restored.test_constraints.len()
        );
        assert_eq!(
            restored.definitions[0].cves,
            vec!["CVE-2024-1234".to_string()]
        );
        assert_eq!(
            restored.definitions[0].test_refs,
            vec!["oval:test:1".to_string()]
        );

        let constraints = restored
            .test_constraints
            .get("oval:test:1")
            .expect("test constraint");
        assert_eq!(constraints[0].package, "openssl");
        assert_eq!(constraints[0].evr, "1:3.0.7-18.el9");
    }

    #[test]
    fn test_evaluate_oval_for_packages_vulnerable_vs_patched() {
        // Synthetic OVAL definition for CVE-2024-0001 targeting openssl with linux-def: namespace
        // Verifies the full evaluate_oval_for_packages pipeline with EVR comparison
        let oval_xml = r#"
<oval_definitions xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:com.redhat.rhsa:def:20240001" class="vulnerability">
      <metadata>
        <title>RHSA-2024:0001: openssl security update</title>
        <reference source="CVE" ref_id="CVE-2024-0001"/>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:com.redhat.rhsa:tst:20240001001" comment="openssl is earlier than 1:3.0.7-25.el9"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:rpminfo_test id="oval:com.redhat.rhsa:tst:20240001001" check="at least one">
      <linux-def:object object_ref="oval:com.redhat.rhsa:obj:20240001001"/>
      <linux-def:state state_ref="oval:com.redhat.rhsa:ste:20240001001"/>
    </linux-def:rpminfo_test>
  </tests>
  <objects>
    <linux-def:rpminfo_object id="oval:com.redhat.rhsa:obj:20240001001">
      <linux-def:name>openssl</linux-def:name>
    </linux-def:rpminfo_object>
  </objects>
  <states>
    <linux-def:rpminfo_state id="oval:com.redhat.rhsa:ste:20240001001">
      <linux-def:evr datatype="evr_string" operation="less than">1:3.0.7-25.el9</linux-def:evr>
    </linux-def:rpminfo_state>
  </states>
</oval_definitions>"#;

        let root = Element::parse(oval_xml.as_bytes()).expect("xml parse");
        let tests = build_test_constraints(&root);

        // Vulnerable: openssl 1:3.0.7-24.el9 is older than fixed 1:3.0.7-25.el9
        let mut package_map = HashMap::new();
        package_map.insert("openssl".to_string(), vec!["1:3.0.7-24.el9".to_string()]);
        let eval = evaluate_oval_for_packages(&root, &tests, &package_map);
        assert!(eval.covered_cves.contains("CVE-2024-0001"), "CVE should be covered");
        assert!(eval.vulnerable_cves.contains("CVE-2024-0001"), "older version should be vulnerable");

        // Patched: openssl 1:3.0.7-25.el9 is exactly at the fixed version (not less than)
        package_map.insert("openssl".to_string(), vec!["1:3.0.7-25.el9".to_string()]);
        let eval_patched = evaluate_oval_for_packages(&root, &tests, &package_map);
        assert!(eval_patched.covered_cves.contains("CVE-2024-0001"), "CVE should still be covered");
        assert!(!eval_patched.vulnerable_cves.contains("CVE-2024-0001"), "patched version should NOT be vulnerable");
    }

    #[test]
    fn test_cached_oval_from_pg_maps_correctly() {
        // Verify that CachedOvalData built from PG-style data works with generate_from_cached_oval
        let cached = CachedOvalData {
            test_constraints: {
                let mut m = HashMap::new();
                m.insert(
                    "oval:test:1".to_string(),
                    vec![RpmConstraint {
                        package: "openssl".to_string(),
                        op: CompareOp::LessThan,
                        evr: "1:1.0.2k-26.el7_9".to_string(),
                    }],
                );
                m
            },
            definitions: vec![CachedDefinition {
                cves: vec!["CVE-2023-0286".to_string()],
                test_refs: vec!["oval:test:1".to_string()],
            }],
        };
        assert_eq!(cached.definitions.len(), 1);
        assert_eq!(cached.test_constraints.len(), 1);
        assert_eq!(cached.definitions[0].cves[0], "CVE-2023-0286");

        // Verify it can generate findings for a vulnerable package
        let mut package_map = HashMap::new();
        package_map.insert(
            "openssl".to_string(),
            vec!["1:1.0.2k-25.el7_9".to_string()],
        );
        let pkgs = vec![PackageCoordinate {
            ecosystem: "Rocky Linux:9".to_string(),
            name: "openssl".to_string(),
            version: "1:1.0.2k-25.el7_9".to_string(),
            source_name: None,
        }];
        let findings = generate_from_cached_oval(&cached, &package_map, &pkgs);
        assert_eq!(findings.len(), 1, "should generate 1 finding for vulnerable openssl");
        assert_eq!(findings[0].id, "CVE-2023-0286");
        assert_eq!(
            findings[0].package.as_ref().unwrap().name,
            "openssl"
        );
    }

    #[test]
    fn parse_oval_file_handles_bz2() {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions/>
  <tests/>
  <objects/>
  <states/>
</oval_definitions>"#;

        let dir = tempfile::tempdir().unwrap();
        let bz2_path = dir.path().join("test.oval.xml.bz2");

        {
            let f = std::fs::File::create(&bz2_path).unwrap();
            let mut encoder = BzEncoder::new(f, Compression::default());
            encoder.write_all(xml.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }

        let result = parse_oval_file(bz2_path.to_str().unwrap());
        assert!(result.is_ok(), "parse_oval_file should handle .bz2: {:?}", result.err());
    }
}
