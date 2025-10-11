use std::fs::File;
use goblin::Object;
use memmap2::Mmap;
use crate::utils::{hash_file_stream, progress};
use crate::report::{Report, ScannerInfo, TargetInfo, compute_summary, Finding, EvidenceItem};
use crate::{ScanMode};
#[cfg(feature = "yara")]
use yara::Compiler;
use crate::vuln::{nvd_cpe_findings, nvd_findings_by_product_version, nvd_keyword_findings};
use regex::Regex;
use std::collections::HashSet;
use goblin::mach::Mach;
use goblin::pe::PE;

/// Detect file format via goblin and print streaming SHA-256
pub fn scan_binary(path: &str) {
    let hash = match hash_file_stream(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hashing file {}: {}", path, e);
            return;
        }
    };

    match File::open(path) {
        Ok(file) => {
            let mmap = unsafe { Mmap::map(&file) };
            match mmap {
                Ok(bytes) => {
                    let kind = match Object::parse(&bytes) {
                        Ok(Object::Elf(_)) => "ELF",
                        Ok(Object::PE(_)) => "PE",
                        Ok(Object::Mach(_)) => "Mach-O",
                        Ok(_) => "Unknown",
                        Err(_) => "Unknown",
                    };
                    println!("Type: {}", kind);
                    println!("SHA256: {}", hash);
                }
                Err(e) => {
                    eprintln!("Failed to mmap file {}: {}", path, e);
                }
            }
        }
        Err(e) => eprintln!("Failed to open {}: {}", path, e),
    }
}

/// Return (file_type, sha256) for JSON report; prints errors and returns None on failure
pub fn scan_binary_report(path: &str) -> Option<(String, String)> {
    let sha256 = match hash_file_stream(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hashing file {}: {}", path, e);
            return None;
        }
    };

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {}: {}", path, e);
            return None;
        }
    };

    let mmap = unsafe { Mmap::map(&file) };
    let file_type = match mmap {
        Ok(bytes) => match Object::parse(&bytes) {
            Ok(Object::Elf(_)) => "ELF".to_string(),
            Ok(Object::PE(_)) => "PE".to_string(),
            Ok(Object::Mach(_)) => "Mach-O".to_string(),
            Ok(_) => "Unknown".to_string(),
            Err(_) => "Unknown".to_string(),
        },
        Err(e) => {
            eprintln!("Failed to mmap file {}: {}", path, e);
            return None;
        }
    };

    Some((file_type, sha256))
}

/// Build canonical JSON report for a single binary (no package vulnerabilities yet)
pub fn build_binary_report(path: &str, mode: ScanMode, yara_rules: Option<String>, nvd_api_key: Option<String>) -> Option<Report> {
    let (file_type, sha256) = scan_binary_report(path)?;
    let scanner = ScannerInfo { name: "scanner", version: env!("CARGO_PKG_VERSION") };
    let target = TargetInfo { target_type: "binary".into(), source: path.to_string(), id: Some(sha256) };
    let mut findings: Vec<Finding> = Vec::new();

    progress("binary.parse.start", path);
    // Generic metadata extraction and NVD lookup (no hardcoded products)
    if let Ok(file) = File::open(path) {
        if let Ok(bytes) = unsafe { Mmap::map(&file) } {
            let mut seen_pairs: HashSet<(String, String)> = HashSet::new();

            match Object::parse(&bytes) {
                Ok(Object::Elf(elf)) => {
                    // Use DT_NEEDED entries to infer components and possible versions from soname suffix
                    for lib in elf.libraries.iter() {
                        if let Some((name, ver)) = infer_component_from_libname(lib) {
                            seen_pairs.insert((name, ver));
                        } else if let Some(name) = infer_name_from_lib_without_version(lib) {
                            // No explicit version in the .so name, try to find a version in strings
                            if let Some(ver) = find_version_in_bytes(&bytes) {
                                seen_pairs.insert((name, ver));
                            }
                        }
                    }
                    // Go version embedded
                    if let Some(go_ver) = find_go_version(&bytes) {
                        seen_pairs.insert(("go".into(), go_ver));
                    }
                }
                Ok(Object::Mach(_)) => {
                    // Simplified: rely on generic string extraction for Mach-O for now
                    for (name, ver) in find_name_version_pairs(&bytes) {
                        seen_pairs.insert((name, ver));
                    }
                }
                Ok(Object::PE(_)) => {
                    if let Ok(pe) = PE::parse(&bytes) {
                        for imp in pe.imports.iter() {
                            let dll = imp.dll.to_string().to_lowercase();
                            if let Some(name) = infer_name_from_lib_without_version(&dll) {
                                if let Some(ver) = find_version_in_bytes(&bytes) {
                                    seen_pairs.insert((name, ver));
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Fallback: generic pattern in printable strings: <name>[ _/-]v?<version>
                    for (name, ver) in find_name_version_pairs(&bytes) {
                        seen_pairs.insert((name, ver));
                    }
                }
            }

            for (product, version) in seen_pairs {
                progress("binary.nvd.lookup", &format!("{} {}", product, version));
                // Try product/vendor heuristic: vendor=product
                let mut extra = nvd_findings_by_product_version(&product, &product, &version, nvd_api_key.as_deref(), Some(path));
                if extra.is_empty() { extra = nvd_cpe_findings(&product, &version, nvd_api_key.as_deref(), Some(path)); }
                if extra.is_empty() { extra = nvd_keyword_findings(&product, &version, nvd_api_key.as_deref(), Some(path)); }
                findings.extend(extra);
            }
        }
    }
    progress("binary.parse.done", path);

    // Optional YARA in deep mode
    if let ScanMode::Deep = mode {
        #[cfg(feature = "yara")]
        if let Some(rule_path) = yara_rules.as_deref() {
            if let Ok(mut compiler) = Compiler::new() {
                let _ = compiler.add_rules_file(rule_path);
                if let Ok(rules) = compiler.compile_rules() {
                    if let Ok(scan) = rules.scan_file(path, 5) {
                        for m in scan.matches {
                            findings.push(Finding {
                                id: format!("YARA:{}", m.identifier),
                                source_ids: Vec::new(),
                                package: None,
                                fixed: None,
                                severity: None,
                                cvss: None,
                                description: None,
                                evidence: vec![EvidenceItem { evidence_type: "yara".into(), path: Some(path.to_string()), detail: Some(m.identifier.to_string()) }],
                                references: Vec::new(),
                                confidence: Some("MEDIUM".into()),
                            });
                        }
                    }
                }
            }
        }
    }

    // Enrich with NVD using Postgres cache (single connection per binary report)
    let mut findings = findings;
    {
        let mut pg = crate::vuln::pg_connect();
        if let Some(c) = pg.as_mut() { crate::vuln::pg_init_schema(c); }
        crate::vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);
    }

    let mut report = Report { scanner, target, sbom: None, findings, summary: Default::default() };
    report.summary = compute_summary(&report.findings);
    Some(report)
}

fn infer_component_from_libname(lib: &str) -> Option<(String, String)> {
    // Examples: libssl.so.1.1 -> (ssl, 1.1) ; libz.so.1 -> (z, 1)
    let mut name = lib.to_string();
    if let Some(pos) = name.rfind('/') { name = name[pos + 1..].to_string(); }
    if name.contains(".so") {
        if let Some((base, rest)) = name.split_once(".so") {
            let mut comp = base.to_string();
            if comp.starts_with("lib") { comp = comp.trim_start_matches("lib").to_string(); }
            let ver = rest.trim_matches('.').to_string();
            if !ver.is_empty() { return Some((comp, ver)); }
        }
    } else if name.ends_with(".dylib") {
        // Mach-O: version not in filename commonly; return none to allow other heuristics
        let mut comp = name.trim_end_matches(".dylib").to_string();
        if comp.starts_with("lib") { comp = comp.trim_start_matches("lib").to_string(); }
        return None;
    }
    None
}

fn infer_name_from_lib_without_version(lib: &str) -> Option<String> {
    let mut name = lib.to_string();
    if let Some(pos) = name.rfind("/") { name = name[pos+1..].to_string(); }
    if name.starts_with("lib") { name = name.trim_start_matches("lib").to_string(); }
    if let Some(pos) = name.find('.') { name.truncate(pos); }
    if name.is_empty() { None } else { Some(name) }
}

fn find_version_in_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    Regex::new(r"\bv?(\d+\.\d+(?:\.\d+)?[a-z0-9-]*)\b").ok()
        .and_then(|re| re.captures(&text).map(|cap| cap.get(1).unwrap().as_str().to_string()))
}

fn find_name_version_pairs(bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(bytes);
    let re = match Regex::new(r"\b([A-Za-z][A-Za-z0-9_+\.-]{1,40})[ _/-]v?(\d+\.\d+(?:\.\d+)?[a-z0-9-]*)\b") { Ok(r) => r, Err(_) => return Vec::new() };
    let mut out = Vec::new();
    for cap in re.captures_iter(&text) {
        let name = cap.get(1).unwrap().as_str().to_lowercase();
        let ver = cap.get(2).unwrap().as_str().to_string();
        out.push((name, ver));
    }
    out
}

fn find_go_version(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    Regex::new(r"\bgo1\.(\d+)(?:\.(\d+))?\b").ok()
        .and_then(|re| re.captures(&text).map(|cap| cap.get(0).unwrap().as_str().to_string()))
}

fn format_version_macho(raw: u32) -> String {
    // Mach-O version as x.y.z in 16.16.16 fixed point
    let major = (raw >> 16) & 0xffff;
    let minor = (raw >> 8) & 0xff;
    let patch = raw & 0xff;
    format!("{}.{}.{}", major, minor, patch)
}

fn trim_lib_name(name: &str) -> String {
    let mut n = name.to_string();
    if let Some(pos) = n.rfind('/') { n = n[pos+1..].to_string(); }
    if n.starts_with("lib") { n = n.trim_start_matches("lib").to_string(); }
    if let Some(pos) = n.find('.') { n.truncate(pos); }
    n
}
