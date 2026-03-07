use crate::container::PackageCoordinate;
use crate::report::{
    compute_summary, FileEntry, Finding, InventoryStatus, Report, ScanStatus, ScannerInfo,
    TargetInfo,
};
#[cfg(feature = "yara")]
use crate::report::{ConfidenceTier, EvidenceItem, EvidenceSource};
use crate::utils::{hash_file_stream, progress, progress_timing};
use crate::vuln::{
    map_osv_results_to_findings, nvd_cpe_findings, nvd_findings_by_product_version,
    nvd_keyword_findings, osv_batch_query,
};
use crate::ScanMode;
use goblin::pe::PE;
use goblin::Object;
use regex::Regex;
use std::cmp::{max, min};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(feature = "yara")]
use yara::Compiler;

/// Map extracted library short names to their NVD vendor:product pair.
/// Covers the most common C/C++ libraries found in binaries.
fn nvd_vendor_product(extracted_name: &str) -> Option<(&'static str, &'static str)> {
    let lower = extracted_name.to_lowercase();
    match lower.as_str() {
        "ssl" | "crypto" | "openssl" => Some(("openssl", "openssl")),
        "z" | "zlib" => Some(("zlib", "zlib")),
        "curl" => Some(("haxx", "curl")),
        "xml2" | "libxml2" => Some(("xmlsoft", "libxml2")),
        "xslt" | "libxslt" => Some(("xmlsoft", "libxslt")),
        "png" | "png16" => Some(("libpng", "libpng")),
        "jpeg" | "turbojpeg" => Some(("libjpeg-turbo", "libjpeg-turbo")),
        "tiff" => Some(("libtiff", "libtiff")),
        "freetype" => Some(("freetype", "freetype")),
        "pcre" | "pcre2" => Some(("pcre", "pcre")),
        "expat" => Some(("libexpat_project", "libexpat")),
        "sqlite3" | "sqlite" => Some(("sqlite", "sqlite")),
        "nghttp2" => Some(("nghttp2", "nghttp2")),
        "ssh2" | "libssh2" => Some(("libssh2", "libssh2")),
        "ssh" | "libssh" => Some(("libssh", "libssh")),
        "gnutls" => Some(("gnu", "gnutls")),
        "bz2" | "bzip2" => Some(("bzip", "bzip2")),
        "lzma" | "xz" => Some(("tukaani", "xz")),
        "zstd" => Some(("facebook", "zstandard")),
        "protobuf" | "protobuf-c" => Some(("google", "protobuf")),
        "yaml" => Some(("pyyaml", "libyaml")),
        "ffi" => Some(("sourceware", "libffi")),
        "gmp" => Some(("gmplib", "gmp")),
        "idn2" => Some(("gnu", "libidn2")),
        "nettle" => Some(("nettle_project", "nettle")),
        "hogweed" => Some(("nettle_project", "nettle")),
        "systemd" => Some(("systemd_project", "systemd")),
        "krb5" | "gssapi_krb5" | "k5crypto" => Some(("mit", "kerberos_5")),
        "ldap" => Some(("openldap", "openldap")),
        "sasl2" => Some(("cyrusimap", "cyrus-sasl")),
        "pq" => Some(("postgresql", "postgresql")),
        "mysqlclient" => Some(("oracle", "mysql")),
        "event" | "event_core" => Some(("libevent_project", "libevent")),
        "uv" => Some(("libuv_project", "libuv")),
        "cap" => Some(("kernel", "linux_kernel")),
        // Additional common libraries
        "cares" | "c-ares" => Some(("c-ares_project", "c-ares")),
        "jansson" => Some(("digip", "jansson")),
        "lz4" => Some(("lz4_project", "lz4")),
        "snappy" => Some(("google", "snappy")),
        "hiredis" => Some(("redis", "hiredis")),
        "sodium" | "nacl" => Some(("jedisct1", "libsodium")),
        "gpg" | "gpgme" | "gcrypt" => Some(("gnupg", "libgcrypt")),
        "glib" | "gobject" | "gio" => Some(("gnome", "glib")),
        "avcodec" | "avformat" | "avutil" | "swresample" | "swscale" => Some(("ffmpeg", "ffmpeg")),
        "boost" => Some(("boost", "boost")),
        "icu" | "icuuc" | "icui18n" | "icudata" => Some(("icu-project", "international_components_for_unicode")),
        "ncurses" | "ncursesw" => Some(("gnu", "ncurses")),
        "readline" => Some(("gnu", "readline")),
        "archive" => Some(("libarchive", "libarchive")),
        "microhttpd" => Some(("gnu", "libmicrohttpd")),
        "maxminddb" => Some(("maxmind", "libmaxminddb")),
        "p11-kit" | "p11kit" => Some(("p11-glue", "p11-kit")),
        "tasn1" => Some(("gnu", "libtasn1")),
        "onig" => Some(("kkos", "oniguruma")),
        "cjson" | "cJSON" => Some(("cjson_project", "cjson")),
        "leveldb" => Some(("google", "leveldb")),
        "rocksdb" => Some(("facebook", "rocksdb")),
        "mbedtls" | "mbedcrypto" | "mbedx509" => Some(("arm", "mbed_tls")),
        "wolfssl" | "wolfcrypt" => Some(("wolfssl", "wolfssl")),
        _ => None,
    }
}

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
    crate::progress::init_pipeline("binary");
    crate::progress::enter_stage("parse");
    progress("binary.hash.start", path);
    #[cfg(not(feature = "yara"))]
    let _ = &yara_rules;

    let (file_type, sha256) = scan_binary_report(path)?;
    progress(
        "binary.hash.ready",
        &format!("type={} sha256={}", file_type, short_hash(&sha256)),
    );

    let scanner = ScannerInfo {
        name: "scanrook",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "binary".into(),
        source: path.to_string(),
        id: Some(sha256),
    };
    let mut findings: Vec<Finding> = Vec::new();

    let parse_started = std::time::Instant::now();
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

    // Connect to PG early so osv_batch_query can use cluster-mode chunk cache
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }

    // Create per-scan circuit breakers (one per API source, not static/shared)
    let osv_breaker = crate::vuln::CircuitBreaker::new("osv", 5);
    let nvd_breaker = crate::vuln::CircuitBreaker::new("nvd", 5);
    let epss_breaker = crate::vuln::CircuitBreaker::new("epss", 5);
    let kev_breaker = crate::vuln::CircuitBreaker::new("kev", 5);

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
                    // Collect recognized DLL imports first so we know the count
                    let dll_names: Vec<(String, String)> = pe
                        .imports
                        .iter()
                        .filter_map(|imp| {
                            let dll = imp.dll.to_string().to_lowercase();
                            infer_name_from_lib_without_version(&dll).map(|name| (dll, name))
                        })
                        .collect();
                    let single_import = dll_names.len() == 1;

                    for (dll, name) in &dll_names {
                        // Try name-aware version search first (looks near the DLL name in bytes)
                        if let Some(ver) = find_version_near_name(&bytes, text_budget, dll)
                            .or_else(|| find_version_near_name(&bytes, text_budget, name))
                        {
                            seen_pairs.insert((name.clone(), ver));
                        } else if single_import {
                            // Only use global version search when there's a single import
                            // to avoid assigning one version to all DLLs
                            if let Some(ver) = find_version_in_bytes(&bytes, text_budget) {
                                seen_pairs.insert((name.clone(), ver));
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

        // If not a recognized binary format and no components extracted, bail
        if file_type == "Unknown" && seen_pairs.is_empty() {
            eprintln!("Unrecognized file type: {}. Not an ELF, PE, or Mach-O binary.", path);
            crate::utils::progress("scan.skip", &format!("unknown_type={}", path));
            return None;
        }

        let mut pairs: Vec<(String, String)> = seen_pairs.into_iter().collect();
        pairs.sort_unstable();
        let total = pairs.len();
        progress("binary.components.detected", &format!("count={}", total));

        if total == 0 {
            progress("binary.nvd.lookup.skip", "no-candidate-components");
        }

        crate::progress::enter_stage("nvd_lookup");
        for (idx, (product, version)) in pairs.iter().enumerate() {
            if nvd_breaker.is_open() {
                progress("binary.nvd.lookup.skip", "circuit breaker open");
                break;
            }
            // Look up correct NVD vendor/product, fall back to product=product
            let (vendor, nvd_product) = nvd_vendor_product(product)
                .map(|(v, p)| (v.to_string(), p.to_string()))
                .unwrap_or_else(|| (product.clone(), product.clone()));

            let step = format!("{}/{} {} {}", idx + 1, total, nvd_product, version);
            progress("binary.nvd.lookup.start", &step);

            let mut extra = nvd_findings_by_product_version(
                &vendor,
                &nvd_product,
                version,
                nvd_api_key.as_deref(),
                Some(path),
                &nvd_breaker,
            );
            if extra.is_empty() {
                extra = nvd_cpe_findings(&vendor, &nvd_product, version, nvd_api_key.as_deref(), Some(path), &nvd_breaker);
            }
            if extra.is_empty() && nvd_vendor_product(product).is_some() {
                // Only use keyword fallback for known-vendor components to reduce false positives
                extra = nvd_keyword_findings(&nvd_product, version, nvd_api_key.as_deref(), Some(path), &nvd_breaker);
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
    crate::progress::enter_stage("go_osv");
    {
        let go_modules = parse_go_buildinfo(&bytes);
        if !go_modules.is_empty() {
            progress(
                "binary.go.buildinfo.found",
                &format!("modules={}", go_modules.len()),
            );
            let coords: Vec<PackageCoordinate> = go_modules
                .iter()
                .map(|(path, ver)| PackageCoordinate {
                    ecosystem: "Go".into(),
                    name: path.clone(),
                    version: ver.clone(),
                    source_name: None,
                })
                .collect();
            let osv_results = osv_batch_query(&coords, &mut pg, &osv_breaker);
            let go_findings = map_osv_results_to_findings(&coords, &osv_results);
            progress(
                "binary.go.osv.done",
                &format!("findings={}", go_findings.len()),
            );
            findings.extend(go_findings);
        }
    }

    progress_timing("binary.parse", parse_started);
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
                                confidence_tier: ConfidenceTier::HeuristicUnverified,
                                evidence_source: EvidenceSource::BinaryHeuristic,
                                accuracy_note: Some(
                                    "Derived from binary pattern matching; package inventory is not available."
                                        .into(),
                                ),
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
                                epss_score: None,
                                epss_percentile: None,
                                in_kev: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // NVD enrichment
    crate::progress::enter_stage("nvd_enrich");
    {
        let nvd_started = std::time::Instant::now();
        crate::vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg, &nvd_breaker);
        progress_timing("binary.enrich.nvd", nvd_started);
    }

    crate::progress::enter_stage("epss");
    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::vuln::epss_enrich_findings(&mut findings, &mut pg, cache_dir.as_deref(), &epss_breaker);
    crate::progress::enter_stage("kev");
    crate::vuln::kev_enrich_findings(&mut findings, &mut pg, cache_dir.as_deref(), &kev_breaker);

    // Downgrade findings from components with no known NVD vendor mapping
    for f in findings.iter_mut() {
        if let Some(ref pkg) = f.package {
            if nvd_vendor_product(&pkg.name).is_none() {
                f.confidence = Some("LOW".into());
                if f.accuracy_note.is_none() {
                    f.accuracy_note = Some(
                        "Component detected via binary string heuristic with no known NVD vendor mapping. \
                         Finding may be a false positive.".into(),
                    );
                }
            }
        }
    }

    crate::progress::enter_stage("report");
    let mut report = Report {
        scanner,
        target,
        scan_status: ScanStatus::Complete,
        inventory_status: InventoryStatus::Complete,
        inventory_reason: None,
        sbom: None,
        findings,
        files: vec![FileEntry {
            path: Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(path)
                .to_string(),
            entry_type: "file".into(),
            size_bytes: std::fs::metadata(path).ok().map(|m| m.len()),
            mode: None,
            mtime: std::fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|ts| chrono::DateTime::<chrono::Utc>::from(ts).to_rfc3339()),
            sha256: hash_file_stream(path).ok(),
            parent_path: None,
        }],
        iso_profile: None,
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);

    // Collect warnings from tripped circuit breakers into report.summary.warnings
    let all_breakers: [&crate::vuln::CircuitBreaker; 4] =
        [&osv_breaker, &nvd_breaker, &epss_breaker, &kev_breaker];
    for b in &all_breakers {
        if b.is_open() {
            report.summary.warnings.push(format!(
                "{} unavailable — results may be incomplete (5 consecutive failures)",
                b.source_name()
            ));
        }
    }

    crate::progress::finish_pipeline();
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

/// Extract a version string from a small byte region.
fn extract_version_from_region(region: &[u8]) -> Option<String> {
    if region.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(region);
    Regex::new(r"\bv?(\d+\.\d+(?:\.\d+)?[a-z0-9-]*)\b")
        .ok()
        .and_then(|re| {
            re.captures(&text)
                .map(|cap| cap.get(1).unwrap().as_str().to_string())
        })
}

/// Search for a version string near occurrences of `name` in the binary content.
/// Looks within a +-512 byte window around each occurrence of the name.
fn find_version_near_name(bytes: &[u8], budget: usize, name: &str) -> Option<String> {
    if bytes.is_empty() || name.is_empty() {
        return None;
    }
    let end = bytes.len().min(max(1, budget));
    let scan = &bytes[..end];
    let name_lower = name.as_bytes();
    let window: usize = 512;

    // Slide through the scan region looking for the name (case-insensitive)
    if name_lower.len() > scan.len() {
        return None;
    }
    for i in 0..=(scan.len() - name_lower.len()) {
        let candidate = &scan[i..i + name_lower.len()];
        if candidate.eq_ignore_ascii_case(name_lower) {
            let region_start = i.saturating_sub(window);
            let region_end = (i + name_lower.len() + window).min(end);
            if let Some(ver) = extract_version_from_region(&scan[region_start..region_end]) {
                return Some(ver);
            }
        }
    }
    None
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

pub fn find_go_version(bytes: &[u8], scan_limit: usize) -> Option<String> {
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
pub fn parse_go_buildinfo(bytes: &[u8]) -> Vec<(String, String)> {
    const MAGIC: &[u8] = b"\xff Go build info:";
    // Find the magic header
    let start = match bytes.windows(MAGIC.len()).position(|w| w == MAGIC) {
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
        let path = cap
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let version = cap
            .get(3)
            .map(|m| m.as_str())
            .unwrap_or("")
            .split('\t')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if path.is_empty() || version.is_empty() || !version.starts_with('v') {
            continue;
        }
        if seen.insert((path.clone(), version.clone())) {
            out.push((path, version));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn unknown_file_type_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readme.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "This is a plain text file with no version-like strings anywhere inside it.").unwrap();
        }
        let report = build_binary_report(
            path.to_str().unwrap(),
            ScanMode::Light,
            None,
            None,
        );
        assert!(report.is_none(), "plain text file should not produce a binary report");
    }

    #[test]
    fn vendor_lookup_maps_common_libraries() {
        assert_eq!(nvd_vendor_product("ssl"), Some(("openssl", "openssl")));
        assert_eq!(nvd_vendor_product("SSL"), Some(("openssl", "openssl")));
        assert_eq!(nvd_vendor_product("z"), Some(("zlib", "zlib")));
        assert_eq!(nvd_vendor_product("curl"), Some(("haxx", "curl")));
        assert_eq!(nvd_vendor_product("pq"), Some(("postgresql", "postgresql")));
        assert_eq!(nvd_vendor_product("unknownlib"), None);
    }

    #[test]
    fn extract_version_from_region_finds_semver() {
        let region = b"some junk openssl 1.1.1k more junk";
        assert_eq!(
            extract_version_from_region(region),
            Some("1.1.1k".to_string())
        );
    }

    #[test]
    fn extract_version_from_region_finds_two_part() {
        let region = b"zlib 1.2";
        assert_eq!(
            extract_version_from_region(region),
            Some("1.2".to_string())
        );
    }

    #[test]
    fn extract_version_from_region_empty() {
        assert_eq!(extract_version_from_region(b""), None);
        assert_eq!(extract_version_from_region(b"no version here"), None);
    }

    #[test]
    fn find_version_near_name_finds_version_close_to_name() {
        // Simulate binary content where "zlib" appears near "1.2.11"
        // and "openssl" appears near "1.1.1k", separated by >1024 bytes of padding
        let mut data = Vec::new();
        data.extend_from_slice(b"openssl version 1.1.1k built on ...");
        data.extend_from_slice(&vec![0u8; 2048]); // large gap
        data.extend_from_slice(b"zlib compression library v1.2.11");

        let budget = data.len();

        // Should find 1.1.1k near "openssl"
        let ver = find_version_near_name(&data, budget, "openssl");
        assert_eq!(ver, Some("1.1.1k".to_string()));

        // Should find 1.2.11 near "zlib"
        let ver = find_version_near_name(&data, budget, "zlib");
        assert_eq!(ver, Some("1.2.11".to_string()));
    }

    #[test]
    fn find_version_near_name_case_insensitive() {
        let data = b"OPENSSL version 3.0.2 built";
        let ver = find_version_near_name(data, data.len(), "openssl");
        assert_eq!(ver, Some("3.0.2".to_string()));
    }

    #[test]
    fn find_version_near_name_returns_none_for_missing_name() {
        let data = b"zlib compression library v1.2.11";
        let ver = find_version_near_name(data, data.len(), "openssl");
        assert_eq!(ver, None);
    }

    #[test]
    fn find_version_near_name_empty_inputs() {
        assert_eq!(find_version_near_name(b"", 100, "openssl"), None);
        assert_eq!(find_version_near_name(b"openssl 1.0", 10, ""), None);
    }

    #[test]
    fn find_version_near_name_respects_budget() {
        let mut data = Vec::new();
        data.extend_from_slice(&vec![0u8; 100]);
        data.extend_from_slice(b"openssl version 1.1.1k");

        // Budget smaller than where "openssl" appears -- should not find it
        let ver = find_version_near_name(&data, 50, "openssl");
        assert_eq!(ver, None);

        // Budget large enough
        let ver = find_version_near_name(&data, data.len(), "openssl");
        assert_eq!(ver, Some("1.1.1k".to_string()));
    }

    #[test]
    fn pe_imports_get_distinct_versions() {
        // Verify that the name-aware search assigns different versions to
        // different libraries when those versions appear near the respective names
        let mut data = Vec::new();
        data.extend_from_slice(b"openssl.dll version 3.0.8 linked");
        data.extend_from_slice(&vec![0u8; 2048]);
        data.extend_from_slice(b"zlib1.dll compression 1.2.13 ok");

        let budget = data.len();

        let ver_ssl = find_version_near_name(&data, budget, "openssl.dll")
            .or_else(|| find_version_near_name(&data, budget, "openssl"));
        let ver_z = find_version_near_name(&data, budget, "zlib1.dll")
            .or_else(|| find_version_near_name(&data, budget, "zlib1"));

        assert_eq!(ver_ssl, Some("3.0.8".to_string()));
        assert_eq!(ver_z, Some("1.2.13".to_string()));
        // They must be different -- the old bug would give them the same version
        assert_ne!(ver_ssl, ver_z);
    }
}
