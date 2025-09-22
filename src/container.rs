use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;
use flate2::read::GzDecoder;
use bzip2::read::BzDecoder;
use tempfile::tempdir;
use serde::Serialize;
use crate::vuln::{osv_batch_query, map_osv_results_to_findings, enrich_findings_with_nvd, nvd_keyword_findings, nvd_cpe_findings, nvd_keyword_findings_name};
use crate::utils::parse_name_version_from_filename;
use crate::redhat::check_redhat_cve;
use crate::report::{Report, ScannerInfo, TargetInfo, SbomInfo, compute_summary};
use crate::utils::{run_syft_generate_sbom, write_output_if_needed, progress};
use crate::{OutputFormat, ScanMode};
use walkdir::WalkDir;
#[cfg(feature = "yara")]
use yara::Compiler;
use std::collections::HashSet;

/// Extracts a tar archive (optionally gzipped) to ./extracted
pub fn extract_tar(tar_path: &str, dest: &Path) -> anyhow::Result<()> {
    let file = File::open(tar_path)?;
    let mut archive: Archive<Box<dyn std::io::Read>> = if tar_path.ends_with(".gz") || tar_path.ends_with(".tgz") {
        Archive::new(Box::new(GzDecoder::new(file)))
    } else if tar_path.ends_with(".bz2") || tar_path.ends_with(".tbz") || tar_path.ends_with(".tbz2") {
        Archive::new(Box::new(BzDecoder::new(file)))
    } else {
        Archive::new(Box::new(file))
    };
    archive.unpack(dest)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct PackageCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct ContainerReport {
    pub scanner: &'static str,
    pub version: &'static str,
    pub target: String,
    pub mode: String,
    pub packages: Vec<PackageCoordinate>,
    pub findings: serde_json::Value,
}

pub fn scan_container(tar_path: &str, mode: ScanMode, format: OutputFormat, cache_dir: Option<String>, yara_rules: Option<String>, out: Option<String>, sbom: bool, nvd_api_key: Option<String>, oval_redhat: Option<String>) {
    let tmp = match tempdir() {
        Ok(td) => td,
        Err(e) => {
            eprintln!("Failed to create tempdir: {}", e);
            return;
        }
    };
    progress("container.extract.start", tar_path);

    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        eprintln!("Failed to extract {}: {}", tar_path, e);
        progress("container.extract.error", &format!("{}", e));
        return;
    }
    progress("container.extract.done", tar_path);

    // Try to merge layers if it's a docker save; if no manifest.json, treat dest as rootfs
    let manifest_path = tmp.path().join("manifest.json");
    let rootfs = if manifest_path.exists() {
        progress("container.layers.merge.start", "manifest=present");
        match merge_layers(tmp.path()) {
            Ok(p) => {
                progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                p
            }
            Err(e) => {
                eprintln!("Failed to merge layers: {}", e);
                progress("container.layers.merge.error", &format!("{}", e));
                tmp.path().to_path_buf()
            }
        }
    } else {
        progress("container.layers.merge.skip", &format!("manifest=missing; rootfs={}", tmp.path().display()));
        tmp.path().to_path_buf()
    };

    progress("container.packages.detect.start", rootfs.to_string_lossy().as_ref());
    let packages = detect_os_packages(&rootfs);
    progress("container.packages.detect.done", &format!("packages={}", packages.len()));

    // Light mode: only OSV lookups for packages; Deep mode: run YARA too
    progress("container.osv.query.start", &format!("packages={}", packages.len()));
    let osv_results = osv_batch_query(&packages);
    progress("container.osv.query.done", "ok");
    let mut findings_norm = map_osv_results_to_findings(&packages, &osv_results);

    // Enrich with OSV details first, then NVD for CVSS/refs
    progress("container.enrich.osv.start", &format!("findings_pre_enrich={}", findings_norm.len()));
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() { crate::vuln::pg_init_schema(c); }
    crate::vuln::osv_enrich_findings(&mut findings_norm, &mut pg);
    progress("container.enrich.osv.done", &format!("findings={}", findings_norm.len()));
    let unique: HashSet<String> = findings_norm
        .iter()
        .filter(|f| f.id.starts_with("CVE-"))
        .map(|f| f.id.clone())
        .collect();
    progress("container.enrich.nvd.start", &format!("cves={}", unique.len()));
    crate::vuln::enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
    progress("container.enrich.nvd.done", "ok");

    // Fallback: if no packages detected, try filename heuristic (e.g., busybox-<ver>.tar.*)
    if packages.is_empty() {
        if let Some((name, ver)) = parse_name_version_from_filename(tar_path) {
            // Try structured (vendor=product=name) CPE first, then product/version filter, then keyword
            let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
            if extra.is_empty() { extra = crate::vuln::nvd_findings_by_product_version(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
            if extra.is_empty() { extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
            if extra.is_empty() { extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path)); }
            findings_norm.append(&mut extra);
        }
        if findings_norm.is_empty() {
            if let Some((name, ver)) = detect_busybox_version_in_tree(&rootfs) {
                progress("container.filename.heuristic", &format!("{} {}", name, ver));
                let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
                if extra.is_empty() { extra = crate::vuln::nvd_findings_by_product_version(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
                if extra.is_empty() { extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
                if extra.is_empty() { extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path)); }
                findings_norm.append(&mut extra);
            }
        }
    }

    // If OVAL provided, we could cross-check CVEs to see if they are marked fixed in the distro
    if let Some(_oval_path) = oval_redhat.as_deref() {
        // Placeholder: integrate full OVAL evaluation per package versions; current redhat.rs only does presence checks.
        // For now, we keep this as a hook for future implementation.
    }

    let mut yara_hits: Vec<String> = Vec::new();
    if let ScanMode::Deep = mode {
        #[cfg(feature = "yara")]
        if let Some(rule_path) = yara_rules.as_deref() {
            if let Ok(mut compiler) = Compiler::new() {
                if let Err(e) = compiler.add_rules_file(rule_path) {
                    eprintln!("Failed to add YARA rules: {}", e);
                } else if let Ok(rules) = compiler.compile_rules() {
                    for entry in WalkDir::new(&rootfs).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            if let Ok(scan) = rules.scan_file(entry.path(), 5) {
                                for m in scan.matches {
                                    yara_hits.push(format!("{}: {}", entry.path().display(), m.identifier));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    match format {
        OutputFormat::Text => {
            println!("Merged RootFS: {}", rootfs.display());
            println!("Detected packages: {}", packages.len());
            for p in &packages {
                println!("- {}:{}@{}", p.ecosystem, p.name, p.version);
            }
            println!("Findings: {}", findings_norm.len());
            if !yara_hits.is_empty() { println!("YARA hits: {}", yara_hits.len()); }
        }
        OutputFormat::Json => {
            let scanner = ScannerInfo { name: "scanner", version: env!("CARGO_PKG_VERSION") };
            let target = TargetInfo { target_type: "container".into(), source: tar_path.to_string(), id: None };
            let mut sbom_info: Option<SbomInfo> = None;
            if sbom {
                progress("container.sbom.start", rootfs.to_string_lossy().as_ref());
                let sbom_path = tmp.path().join("sbom.cdx.json");
                if let Err(e) = run_syft_generate_sbom(rootfs.to_str().unwrap_or("."), sbom_path.to_str().unwrap_or("sbom.cdx.json")) {
                    eprintln!("Syft SBOM generation failed: {}", e);
                    progress("container.sbom.error", &format!("{}", e));
                } else {
                    sbom_info = Some(SbomInfo { format: "cyclonedx".into(), path: sbom_path.display().to_string() });
                    progress("container.sbom.done", "ok");
                }
            }
            let mut report = Report { scanner, target, sbom: sbom_info, findings: findings_norm, summary: Default::default() };
            report.summary = compute_summary(&report.findings);
            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("{}", json);
            write_output_if_needed(&out, &json);
        }
    }
}

/// Build a container report (no printing)
pub fn build_container_report(tar_path: &str, mode: ScanMode, sbom: bool, nvd_api_key: Option<String>, yara_rules: Option<String>) -> Option<Report> {
    let tmp = tempdir().ok()?;
    progress("container.extract.start", tar_path);
    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        progress("container.extract.error", &format!("{}", e));
        return None;
    }
    progress("container.extract.done", tar_path);
    let manifest_path = tmp.path().join("manifest.json");
    let rootfs = if manifest_path.exists() {
        progress("container.layers.merge.start", "manifest=present");
        match merge_layers(tmp.path()) {
            Ok(p) => { progress("container.layers.merge.done", p.to_string_lossy().as_ref()); p }
            Err(e) => { progress("container.layers.merge.error", &format!("{}", e)); tmp.path().to_path_buf() }
        }
    } else {
        progress("container.layers.merge.skip", &format!("manifest=missing; rootfs={}", tmp.path().display()));
        tmp.path().to_path_buf()
    };

    progress("container.packages.detect.start", rootfs.to_string_lossy().as_ref());
    let packages = detect_os_packages(&rootfs);
    progress("container.packages.detect.done", &format!("packages={}", packages.len()));
    progress("container.osv.query.start", &format!("packages={}", packages.len()));
    let osv_results = osv_batch_query(&packages);
    progress("container.osv.query.done", "ok");
    let mut findings_norm = map_osv_results_to_findings(&packages, &osv_results);
    progress("container.enrich.osv.start", &format!("findings_pre_enrich={}", findings_norm.len()));
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() { crate::vuln::pg_init_schema(c); }
    crate::vuln::osv_enrich_findings(&mut findings_norm, &mut pg);
    progress("container.enrich.osv.done", &format!("findings={}", findings_norm.len()));
    let unique: HashSet<String> = findings_norm
        .iter()
        .filter(|f| f.id.starts_with("CVE-"))
        .map(|f| f.id.clone())
        .collect();
    progress("container.enrich.nvd.start", &format!("cves={}", unique.len()));
    enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
    progress("container.enrich.nvd.done", "ok");

    // Optional YARA in deep mode (ignored if feature not enabled)
    if let ScanMode::Deep = mode {
        #[cfg(feature = "yara")]
        if let Some(rule_path) = yara_rules.as_deref() {
            if let Ok(mut compiler) = Compiler::new() {
                let _ = compiler.add_rules_file(rule_path);
                if let Ok(rules) = compiler.compile_rules() {
                    for entry in WalkDir::new(&rootfs).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            let _ = rules.scan_file(entry.path(), 5);
                        }
                    }
                }
            }
        }
    }

    let scanner = ScannerInfo { name: "scanner", version: env!("CARGO_PKG_VERSION") };
    let target = TargetInfo { target_type: "container".into(), source: tar_path.to_string(), id: None };
    let mut sbom_info: Option<SbomInfo> = None;
    if sbom {
        progress("container.sbom.start", rootfs.to_string_lossy().as_ref());
        let sbom_path = tmp.path().join("sbom.cdx.json");
        if run_syft_generate_sbom(rootfs.to_str().unwrap_or("."), sbom_path.to_str().unwrap_or("sbom.cdx.json")).is_ok() {
            sbom_info = Some(SbomInfo { format: "cyclonedx".into(), path: sbom_path.display().to_string() });
        }
        progress("container.sbom.done", "ok");
    }

    let mut report = Report { scanner, target, sbom: sbom_info, findings: findings_norm, summary: Default::default() };
    report.summary = compute_summary(&report.findings);
    Some(report)
}

/// Build a source tarball report (no printing)
pub fn build_source_report(tar_path: &str, nvd_api_key: Option<String>) -> Option<Report> {
    let tmp = tempdir().ok()?;
    extract_tar(tar_path, tmp.path()).ok()?;

    let mut candidates: Vec<(String,String)> = Vec::new();
    if let Some((n,v)) = parse_name_version_from_filename(tar_path) { candidates.push((n,v)); }
    if let Some((n,v)) = detect_busybox_version_in_tree(tmp.path()) { candidates.push((n,v)); }
    if let Some((n,v)) = detect_busybox_version_from_makefile(tmp.path()) { candidates.push((n,v)); }

    let mut findings = Vec::new();
    for (name, ver) in candidates {
        let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        if extra.is_empty() { extra = crate::vuln::nvd_findings_by_product_version(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
        if extra.is_empty() { extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
        if extra.is_empty() { extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path)); }
        findings.extend(extra);
    }

    let scanner = ScannerInfo { name: "scanner", version: env!("CARGO_PKG_VERSION") };
    let target = TargetInfo { target_type: "source".into(), source: tar_path.to_string(), id: None };
    // Enrich with NVD using Postgres cache
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() { crate::vuln::pg_init_schema(c); }
    crate::vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);

    let mut report = Report { scanner, target, sbom: None, findings, summary: Default::default() };
    report.summary = compute_summary(&report.findings);
    Some(report)
}
fn detect_busybox_version_in_tree(root: &Path) -> Option<(String, String)> {
    let re = regex::Regex::new(r"BusyBox v(\d+\.\d+(?:\.\d+)?)").ok()?;
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(mut f) = File::open(entry.path()) {
                let mut buf = [0u8; 4096];
                if let Ok(n) = f.read(&mut buf) {
                    let s = String::from_utf8_lossy(&buf[..n]);
                    if let Some(caps) = re.captures(&s) {
                        if let Some(ver) = caps.get(1) { return Some(("busybox".into(), ver.as_str().to_string())); }
                    }
                }
            }
        }
    }
    None
}

fn detect_busybox_version_from_makefile(root: &Path) -> Option<(String, String)> {
    let makefile = root.join("Makefile");
    if !makefile.exists() { return None; }
    let content = std::fs::read_to_string(&makefile).ok()?;
    let re_ver = regex::Regex::new(r"(?m)^\s*VERSION\s*=\s*(\d+)\s*$").ok()?;
    let re_patch = regex::Regex::new(r"(?m)^\s*PATCHLEVEL\s*=\s*(\d+)\s*$").ok()?;
    let re_sub = regex::Regex::new(r"(?m)^\s*SUBLEVEL\s*=\s*(\d+)\s*$").ok()?;
    let v = re_ver.captures(&content)?.get(1)?.as_str().to_string();
    let p = re_patch.captures(&content)?.get(1)?.as_str().to_string();
    let s = re_sub.captures(&content)?.get(1)?.as_str().to_string();
    Some(("busybox".into(), format!("{}.{}.{}", v, p, s)))
}

pub fn scan_source_tarball(tar_path: &str, format: OutputFormat, nvd_api_key: Option<String>, out: Option<String>) {
    let tmp = match tempdir() { Ok(td) => td, Err(e) => { eprintln!("Failed to create tempdir: {}", e); return; } };
    if let Err(e) = extract_tar(tar_path, tmp.path()) { eprintln!("Failed to extract {}: {}", tar_path, e); return; }

    // Try specific detections (BusyBox) and general filename/version
    let mut candidates: Vec<(String,String)> = Vec::new();
    if let Some((n,v)) = parse_name_version_from_filename(tar_path) { candidates.push((n,v)); }
    if let Some((n,v)) = detect_busybox_version_in_tree(tmp.path()) { candidates.push((n,v)); }
    if let Some((n,v)) = detect_busybox_version_from_makefile(tmp.path()) { candidates.push((n,v)); }
    // TODO: parse generic Makefile for VERSION/PKGNAME

    let mut findings = Vec::new();
    for (name, ver) in candidates {
        let mut extra = nvd_cpe_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path));
        if extra.is_empty() { extra = crate::vuln::nvd_findings_by_product_version(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
        if extra.is_empty() { extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path)); }
        if extra.is_empty() { extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path)); }
        findings.extend(extra);
    }

    match format {
        OutputFormat::Text => {
            println!("Source: {}", tar_path);
            println!("Findings: {}", findings.len());
        }
        OutputFormat::Json => {
            let scanner = ScannerInfo { name: "scanner", version: env!("CARGO_PKG_VERSION") };
            let target = TargetInfo { target_type: "source".into(), source: tar_path.to_string(), id: None };
            let mut report = Report { scanner, target, sbom: None, findings, summary: Default::default() };
            report.summary = compute_summary(&report.findings);
            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("{}", json);
            write_output_if_needed(&out, &json);
        }
    }
}

fn merge_layers(extracted: &Path) -> anyhow::Result<PathBuf> {
    // docker save layout: manifest.json + layer tarballs and config
    let manifest_path = extracted.join("manifest.json");
    let mut manifest_str = String::new();
    File::open(&manifest_path)?.read_to_string(&mut manifest_str)?;
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)?;
    let first = &manifest_json[0];
    let layers = first["Layers"].as_array().ok_or_else(|| anyhow::anyhow!("No Layers"))?;

    let rootfs_dir = extracted.join("rootfs");
    fs::create_dir_all(&rootfs_dir)?;

    for layer_rel in layers {
        let layer_rel = layer_rel.as_str().ok_or_else(|| anyhow::anyhow!("Layer not string"))?;
        let layer_path = extracted.join(layer_rel);
        apply_layer_tar(&layer_path, &rootfs_dir)?;
    }

    Ok(rootfs_dir)
}

fn apply_layer_tar(layer_tar: &Path, rootfs: &Path) -> anyhow::Result<()> {
    let file = File::open(layer_tar)?;
    // Docker save typically produces uncompressed layer.tar; handle both .tar and .tar.gz
    let is_gz = layer_tar
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".tar.gz") || n.ends_with(".tgz") || n.ends_with(".gz"))
        .unwrap_or(false);

    if is_gz {
        let gz = GzDecoder::new(file);
        let mut ar = Archive::new(gz);
        ar.unpack(rootfs)?;
    } else {
        let mut ar = Archive::new(file);
        ar.unpack(rootfs)?;
    }
    Ok(())
}

fn detect_os_packages(rootfs: &Path) -> Vec<PackageCoordinate> {
    let mut packages = Vec::new();

    // Debian/Ubuntu: /var/lib/dpkg/status
    let dpkg_status = rootfs.join("var/lib/dpkg/status");
    if dpkg_status.exists() {
        if let Ok(mut s) = fs::read_to_string(&dpkg_status) {
            parse_dpkg_status(&s, &mut packages);
        }
    }

    // Alpine: /lib/apk/db/installed
    let apk_db = rootfs.join("lib/apk/db/installed");
    if apk_db.exists() {
        if let Ok(mut s) = fs::read_to_string(&apk_db) {
            parse_apk_installed(&s, &mut packages);
        }
    }

    // RPM: try host rpm CLI as a fallback (if available)
    let rpmdb = rootfs.join("var/lib/rpm");
    if rpmdb.exists() {
        if let Ok(list) = detect_rpm_packages_cli(rootfs) {
            for (name, version) in list {
                packages.push(PackageCoordinate { ecosystem: "rpm".into(), name, version });
            }
        }
    }

    packages
}

fn parse_dpkg_status(contents: &str, out: &mut Vec<PackageCoordinate>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut installed_ok: bool = false;
    for line in contents.lines() {
        if line.starts_with("Package:") {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                if installed_ok { out.push(PackageCoordinate { ecosystem: "deb".into(), name: n, version: v }); }
            }
            name = Some(line[8..].trim().to_string());
            version = None;
            installed_ok = false;
        } else if line.starts_with("Version:") {
            version = Some(line[8..].trim().to_string());
        } else if line.starts_with("Status:") {
            // Expect: Status: install ok installed
            installed_ok = line.contains("install ok installed");
        } else if line.is_empty() {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                if installed_ok { out.push(PackageCoordinate { ecosystem: "deb".into(), name: n, version: v }); }
            }
        }
    }
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        if installed_ok { out.push(PackageCoordinate { ecosystem: "deb".into(), name: n, version: v }); }
    }
}

fn parse_apk_installed(contents: &str, out: &mut Vec<PackageCoordinate>) {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in contents.lines() {
        if line.starts_with("P:") {
            name = Some(line[2..].trim().to_string());
        } else if line.starts_with("V:") {
            version = Some(line[2..].trim().to_string());
        } else if line.is_empty() {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                out.push(PackageCoordinate { ecosystem: "apk".into(), name: n, version: v });
            }
        }
    }
    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        out.push(PackageCoordinate { ecosystem: "apk".into(), name: n, version: v });
    }
}

fn detect_rpm_packages_cli(rootfs: &Path) -> anyhow::Result<Vec<(String,String)>> {
    use std::process::Command;
    let output = Command::new("rpm")
        .arg("--root")
        .arg(rootfs)
        .arg("-qa")
        .arg("--qf")
        .arg("%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n")
        .output();
    let mut results = Vec::new();
    match output {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let mut parts = line.split_whitespace();
                if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
                    let version = ver.trim_start_matches(":").to_string();
                    results.push((name.to_string(), version));
                }
            }
            Ok(results)
        }
        Ok(out) => Err(anyhow::anyhow!("rpm exited with status {}", out.status)),
        Err(e) => Err(anyhow::anyhow!("failed to invoke rpm: {}", e)),
    }
}
