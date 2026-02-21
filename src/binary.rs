#[cfg(feature = "yara")]
use crate::report::EvidenceItem;
use crate::report::{compute_summary, Finding, Report, ScannerInfo, TargetInfo};
use crate::utils::{hash_file_stream, progress};
use crate::vuln::{
    map_osv_results_to_findings, nvd_cpe_findings, nvd_findings_by_product_version,
    nvd_keyword_findings, osv_batch_query,
};
use crate::container::PackageCoordinate;
use crate::ScanMode;
use goblin::pe::PE;
use goblin::Object;
use regex::Regex;
use std::cmp::{max, min};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "yara")]
use yara::Compiler;

const DEFAULT_BINARY_FULL_SCAN_MAX_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_BINARY_SAMPLE_BYTES: usize = 12 * 1024 * 1024;
const DEFAULT_BINARY_HEAD_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_BINARY_TEXT_SCAN_BYTES: usize = 8 * 1024 * 1024;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn short_hash(hash: &str) -> &str {
    let end = min(12, hash.len());
    &hash[..end]
}

fn detect_file_type(bytes: &[u8]) -> String {
    match Object::parse(bytes) {
        Ok(Object::Elf(_)) => "ELF".to_string(),
        Ok(Object::PE(_)) => "PE".to_string(),
        Ok(Object::Mach(_)) => "Mach-O".to_string(),
        Ok(_) => "Unknown".to_string(),
        Err(_) => "Unknown".to_string(),
    }
}

fn read_head_bytes(path: &str, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; max_bytes];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn read_range(file: &mut File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn read_sampled_bytes(path: &str, total_size: u64, budget: usize) -> std::io::Result<Vec<u8>> {
    if total_size == 0 {
        return Ok(Vec::new());
    }

    let budget = max(64 * 1024, budget);
    if total_size <= budget as u64 {
        return std::fs::read(path);
    }

    let mut file = File::open(path)?;
    let chunk = max(64 * 1024, budget / 3);
    let mut offsets = vec![0_u64];

    if total_size > chunk as u64 {
        let mid = (total_size / 2).saturating_sub((chunk as u64) / 2);
        offsets.push(mid);
        offsets.push(total_size.saturating_sub(chunk as u64));
    }

    offsets.sort_unstable();
    offsets.dedup();

    let mut out = Vec::with_capacity(chunk * offsets.len());
    for off in offsets {
        let mut part = read_range(&mut file, off, chunk)?;
        out.append(&mut part);
    }
    Ok(out)
}

/// Detect file format via goblin and print streaming SHA-256
pub fn scan_binary(path: &str) {
    let hash = match hash_file_stream(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hashing file {}: {}", path, e);
            return;
        }
    };

    let head_bytes = match read_head_bytes(
        path,
        env_usize("SCANNER_BINARY_HEAD_BYTES", DEFAULT_BINARY_HEAD_BYTES),
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {}: {}", path, e);
            return;
        }
    };

    let kind = detect_file_type(&head_bytes);
    println!("Type: {}", kind);
    println!("SHA256: {}", hash);
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

    let head_bytes = match read_head_bytes(
        path,
        env_usize("SCANNER_BINARY_HEAD_BYTES", DEFAULT_BINARY_HEAD_BYTES),
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {}: {}", path, e);
            return None;
        }
    };

    let file_type = detect_file_type(&head_bytes);
    Some((file_type, sha256))
}

/// Build canonical JSON report for a single binary
pub fn build_binary_report(
    path: &str,
    mode: ScanMode,
    yara_rules: Option<String>,
    nvd_api_key: Option<String>,
) -> Option<Report> {
    progress("binary.hash.start", path);
    let (file_type, sha256) = scan_binary_report(path)?;
    progress(
        "binary.hash.ready",
        &format!("type={} sha256={}", file_type, short_hash(&sha256)),
    );

    let scanner = ScannerInfo {
        name: "scanner",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "binary".into(),
        source: path.to_string(),
        id: Some(sha256),
    };
    let mut findings: Vec<Finding> = Vec::new();

    progress("binary.parse.start", path);
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    progress(
        "binary.file.info",
        &format!("size={}B type={}", file_size, file_type),
    );

    let full_limit = env_u64(
        "SCANNER_BINARY_FULL_SCAN_MAX_BYTES",
        DEFAULT_BINARY_FULL_SCAN_MAX_BYTES,
    );
    let sample_budget = env_usize("SCANNER_BINARY_SAMPLE_BYTES", DEFAULT_BINARY_SAMPLE_BYTES);
    let mut bytes: Vec<u8> = Vec::new();

    if file_size > full_limit {
        progress(
            "binary.parse.mode",
            &format!("sampled size={}B budget={}B", file_size, sample_budget),
        );
        match read_sampled_bytes(path, file_size, sample_budget) {
            Ok(b) => {
                bytes = b;
                progress(
                    "binary.parse.sampled",
                    &format!("loaded_bytes={}", bytes.len()),
                );
            }
            Err(e) => {
                progress("binary.parse.error", &format!("sampled_read: {}", e));
            }
        }
    } else {
        progress("binary.parse.mode", &format!("full size={}B", file_size));
        match std::fs::read(path) {
            Ok(b) => {
                bytes = b;
                progress(
                    "binary.parse.loaded",
                    &format!("loaded_bytes={}", bytes.len()),
                );
            }
            Err(e) => {
                progress("binary.parse.error", &format!("read: {}", e));
            }
        }
    }

    if !bytes.is_empty() {
        let mut seen_pairs: HashSet<(String, String)> = HashSet::new();
        let text_budget = if file_size > full_limit {
            bytes.len()
        } else {
            env_usize(
                "SCANNER_BINARY_TEXT_SCAN_BYTES",
                DEFAULT_BINARY_TEXT_SCAN_BYTES,
            )
            .min(bytes.len())
        };

        match Object::parse(&bytes) {
            Ok(Object::Elf(elf)) => {
                for lib in elf.libraries.iter() {
                    if let Some((name, ver)) = infer_component_from_libname(lib) {
                        seen_pairs.insert((name, ver));
                    } else if let Some(name) = infer_name_from_lib_without_version(lib) {
                        if let Some(ver) = find_version_in_bytes(&bytes, text_budget) {
                            seen_pairs.insert((name, ver));
                        }
                    }
                }
                if let Some(go_ver) = find_go_version(&bytes, text_budget) {
                    seen_pairs.insert(("go".into(), go_ver));
                }
            }
            Ok(Object::Mach(_)) => {
                for (name, ver) in find_name_version_pairs(&bytes, text_budget) {
                    seen_pairs.insert((name, ver));
                }
            }
            Ok(Object::PE(_)) => {
                if let Ok(pe) = PE::parse(&bytes) {
                    for imp in pe.imports.iter() {
                        let dll = imp.dll.to_string().to_lowercase();
                        if let Some(name) = infer_name_from_lib_without_version(&dll) {
                            if let Some(ver) = find_version_in_bytes(&bytes, text_budget) {
                                seen_pairs.insert((name, ver));
                            }
                        }
                    }
                }
            }
            _ => {
                for (name, ver) in find_name_version_pairs(&bytes, text_budget) {
                    seen_pairs.insert((name, ver));
                }
            }
        }

        let mut pairs: Vec<(String, String)> = seen_pairs.into_iter().collect();
        pairs.sort_unstable();
        let total = pairs.len();
        progress("binary.components.detected", &format!("count={}", total));

        if total == 0 {
            progress("binary.nvd.lookup.skip", "no-candidate-components");
        }

        for (idx, (product, version)) in pairs.iter().enumerate() {
            let step = format!("{}/{} {} {}", idx + 1, total, product, version);
            progress("binary.nvd.lookup.start", &step);

            let mut extra = nvd_findings_by_product_version(
                product,
                product,
                version,
                nvd_api_key.as_deref(),
                Some(path),
            );
            if extra.is_empty() {
                extra = nvd_cpe_findings(product, version, nvd_api_key.as_deref(), Some(path));
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings(product, version, nvd_api_key.as_deref(), Some(path));
            }

            let found = extra.len();
            progress(
                "binary.nvd.lookup.done",
                &format!(
                    "{}/{} {} {} findings={}",
                    idx + 1,
                    total,
                    product,
                    version,
                    found
                ),
            );
            findings.extend(extra);
        }
    }

    // Go module OSV lookup via embedded buildinfo
    {
        let go_modules = parse_go_buildinfo(&bytes);
        if !go_modules.is_empty() {
            progress("binary.go.buildinfo.found", &format!("modules={}", go_modules.len()));
            let coords: Vec<PackageCoordinate> = go_modules
                .iter()
                .map(|(path, ver)| PackageCoordinate {
                    ecosystem: "Go".into(),
                    name: path.clone(),
                    version: ver.clone(),
                })
                .collect();
            let osv_results = osv_batch_query(&coords);
            let go_findings = map_osv_results_to_findings(&coords, &osv_results);
            progress("binary.go.osv.done", &format!("findings={}", go_findings.len()));
            findings.extend(go_findings);
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
                                fixed_in: None,
                                recommendation: None,
                                severity: None,
                                cvss: None,
                                description: None,
                                evidence: vec![EvidenceItem {
                                    evidence_type: "yara".into(),
                                    path: Some(path.to_string()),
                                    detail: Some(m.identifier.to_string()),
                                }],
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
    {
        let mut pg = crate::vuln::pg_connect();
        if let Some(c) = pg.as_mut() {
            crate::vuln::pg_init_schema(c);
        }
        crate::vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);
    }

    let mut report = Report {
        scanner,
        target,
        sbom: None,
        findings,
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);
    Some(report)
}

fn infer_component_from_libname(lib: &str) -> Option<(String, String)> {
    // Examples: libssl.so.1.1 -> (ssl, 1.1) ; libz.so.1 -> (z, 1)
    let mut name = lib.to_string();
    if let Some(pos) = name.rfind('/') {
        name = name[pos + 1..].to_string();
    }
    if name.contains(".so") {
        if let Some((base, rest)) = name.split_once(".so") {
            let mut comp = base.to_string();
            if comp.starts_with("lib") {
                comp = comp.trim_start_matches("lib").to_string();
            }
            let ver = rest.trim_matches('.').to_string();
            if !ver.is_empty() {
                return Some((comp, ver));
            }
        }
    } else if name.ends_with(".dylib") {
        return None;
    }
    None
}

fn infer_name_from_lib_without_version(lib: &str) -> Option<String> {
    let mut name = lib.to_string();
    if let Some(pos) = name.rfind("/") {
        name = name[pos + 1..].to_string();
    }
    if name.starts_with("lib") {
        name = name.trim_start_matches("lib").to_string();
    }
    if let Some(pos) = name.find('.') {
        name.truncate(pos);
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn find_version_in_bytes(bytes: &[u8], scan_limit: usize) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let end = bytes.len().min(max(1, scan_limit));
    let text = String::from_utf8_lossy(&bytes[..end]);
    Regex::new(r"\bv?(\d+\.\d+(?:\.\d+)?[a-z0-9-]*)\b")
        .ok()
        .and_then(|re| {
            re.captures(&text)
                .map(|cap| cap.get(1).unwrap().as_str().to_string())
        })
}

fn find_name_version_pairs(bytes: &[u8], scan_limit: usize) -> Vec<(String, String)> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let end = bytes.len().min(max(1, scan_limit));
    let text = String::from_utf8_lossy(&bytes[..end]);
    let re = match Regex::new(
        r"\b([A-Za-z][A-Za-z0-9_+\.-]{1,40})[ _/-]v?(\d+\.\d+(?:\.\d+)?[a-z0-9-]*)\b",
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for cap in re.captures_iter(&text) {
        let name = cap.get(1).unwrap().as_str().to_lowercase();
        let ver = cap.get(2).unwrap().as_str().to_string();
        out.push((name, ver));
    }
    out
}

fn find_go_version(bytes: &[u8], scan_limit: usize) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let end = bytes.len().min(max(1, scan_limit));
    let text = String::from_utf8_lossy(&bytes[..end]);
    Regex::new(r"\bgo1\.(\d+)(?:\.(\d+))?\b")
        .ok()
        .and_then(|re| {
            re.captures(&text)
                .map(|cap| cap.get(0).unwrap().as_str().to_string())
        })
}

/// Parse Go module dependency list embedded in Go 1.12+ binaries.
/// Searches for the `\xff Go build info:` magic header and extracts
/// `dep` and `mod` records of the form `\t(dep|mod)\t<path>\t<version>`.
/// Returns (module_path, version) pairs suitable for OSV lookup.
fn parse_go_buildinfo(bytes: &[u8]) -> Vec<(String, String)> {
    const MAGIC: &[u8] = b"\xff Go build info:";
    // Find the magic header
    let start = match bytes
        .windows(MAGIC.len())
        .position(|w| w == MAGIC)
    {
        Some(pos) => pos + MAGIC.len(),
        None => return Vec::new(),
    };

    // The module info is plain ASCII text; scan forward up to 512 KiB
    let end = bytes.len().min(start + 512 * 1024);
    let text = String::from_utf8_lossy(&bytes[start..end]);

    let mut out = Vec::new();
    let re = match Regex::new(r"\t(mod|dep)\t([^\t\r\n]+)\t(v[^\t\r\n]+)") {
        Ok(r) => r,
        Err(_) => return out,
    };
    let mut seen = std::collections::HashSet::new();
    for cap in re.captures_iter(&text) {
        let path = cap.get(2).map(|m| m.as_str()).unwrap_or("").trim().to_string();
        let version = cap.get(3).map(|m| m.as_str()).unwrap_or("")
            .split('\t').next().unwrap_or("").trim().to_string();
        if path.is_empty() || version.is_empty() || !version.starts_with('v') {
            continue;
        }
        if seen.insert((path.clone(), version.clone())) {
            out.push((path, version));
        }
    }
    out
}
