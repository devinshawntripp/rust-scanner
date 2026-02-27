use crate::container::PackageCoordinate;
use crate::redhat::filter_findings_with_redhat_oval;
use crate::report::{
    compute_summary, retag_findings, ConfidenceTier, EvidenceSource, FileEntry, InventoryStatus,
    Report, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::{progress, progress_timing};
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, osv_batch_query, osv_enrich_findings,
};
use crate::ScanMode;
use anyhow::{anyhow, Context};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;
use walkdir::WalkDir;
use xmltree::{Element, XMLNode};

const ISO_HEURISTIC_NOTE: &str =
    "Installed package inventory could not be fully determined for this ISO. Finding may be false positive.";

fn light_allow_heuristic_fallback() -> bool {
    std::env::var("SCANNER_LIGHT_ALLOW_HEURISTIC_FALLBACK")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

fn deep_require_installed_inventory() -> bool {
    std::env::var("SCANNER_DEEP_REQUIRE_INSTALLED_INVENTORY")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

fn heuristic_fallback_allowed(mode: &ScanMode) -> bool {
    match mode {
        ScanMode::Light => light_allow_heuristic_fallback(),
        ScanMode::Deep => !deep_require_installed_inventory(),
    }
}

pub fn build_iso_report(
    path: &str,
    mode: ScanMode,
    _yara_rules: Option<String>,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Report> {
    progress("iso.detect.start", path);
    let detect_started = std::time::Instant::now();
    let entries = match list_iso_entries(path) {
        Ok(v) => v,
        Err(e) => {
            progress("iso.detect.error", &format!("{}", e));
            return None;
        }
    };
    progress_timing("iso.detect", detect_started);
    progress("iso.detect.done", &format!("entries={}", entries.len()));

    let runtime_started = std::time::Instant::now();
    let mut runtime_error_reason: Option<String> = None;
    let runtime_packages = match packages_from_runtime_inventory(path, &entries) {
        Ok(pkgs) => pkgs,
        Err(e) => {
            progress("iso.inventory.runtime.error", &format!("{}", e));
            runtime_error_reason = Some("runtime_inventory_extraction_failed".into());
            Vec::new()
        }
    };
    progress_timing("iso.inventory.runtime", runtime_started);
    let inventory_complete = !runtime_packages.is_empty();
    if inventory_complete {
        progress(
            "iso.inventory.runtime.done",
            &format!("packages={}", runtime_packages.len()),
        );
    } else {
        progress(
            "iso.inventory.runtime.missing",
            "no directly extractable installed package database found",
        );
    }

    let allow_heuristic_fallback = heuristic_fallback_allowed(&mode);
    let mut fallback_source = EvidenceSource::RepoMetadata;
    let mut used_repodata = false;
    let mut packages = if inventory_complete {
        runtime_packages
    } else if !allow_heuristic_fallback {
        progress(
            "iso.packages.fallback.skip",
            "heuristic fallback disabled by strict inventory policy",
        );
        Vec::new()
    } else {
        let fallback_started = std::time::Instant::now();
        let mut p = packages_from_rpm_entries(&entries);
        progress("iso.packages.filenames", &format!("packages={}", p.len()));
        match packages_from_repodata(path, &entries) {
            Ok(mut from_repodata) => {
                if !from_repodata.is_empty() {
                    used_repodata = true;
                    progress(
                        "iso.repodata.done",
                        &format!("packages={}", from_repodata.len()),
                    );
                    p.append(&mut from_repodata);
                } else {
                    progress("iso.repodata.skip", "no-primary-packages");
                }
            }
            Err(e) => progress("iso.repodata.error", &format!("{}", e)),
        }
        progress_timing("iso.packages.fallback", fallback_started);
        p
    };
    if !used_repodata {
        fallback_source = EvidenceSource::FilenameHeuristic;
    }
    packages = dedupe_packages(packages);
    progress(
        "iso.packages.detect.done",
        &format!("packages={}", packages.len()),
    );

    let mut findings_norm = Vec::new();
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }

    if !packages.is_empty() {
        progress(
            "iso.osv.query.start",
            &format!("packages={}", packages.len()),
        );
        let osv_query_started = std::time::Instant::now();
        let osv_results = osv_batch_query(&packages);
        progress_timing("iso.osv.query", osv_query_started);
        progress("iso.osv.query.done", "ok");
        findings_norm = map_osv_results_to_findings(&packages, &osv_results);
        progress(
            "iso.enrich.osv.start",
            &format!("findings_pre_enrich={}", findings_norm.len()),
        );
        let osv_enrich_started = std::time::Instant::now();
        osv_enrich_findings(&mut findings_norm, &mut pg);
        progress_timing("iso.enrich.osv", osv_enrich_started);
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
            let nvd_enrich_started = std::time::Instant::now();
            enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg);
            progress_timing("iso.enrich.nvd", nvd_enrich_started);
            progress("iso.enrich.nvd.done", "ok");
        } else {
            progress("iso.enrich.nvd.skip", "disabled by SCANNER_NVD_ENRICH");
        }

        if !inventory_complete && allow_heuristic_fallback {
            retag_findings(
                &mut findings_norm,
                ConfidenceTier::HeuristicUnverified,
                fallback_source,
                Some(ISO_HEURISTIC_NOTE),
            );
        }

        let oval_redhat = oval_redhat
            .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
            .filter(|v| !v.trim().is_empty());
        if let Some(oval_path) = oval_redhat.as_deref() {
            progress("iso.enrich.redhat.start", oval_path);
            let redhat_started = std::time::Instant::now();
            match filter_findings_with_redhat_oval(&mut findings_norm, &packages, oval_path) {
                Ok(stats) => {
                    progress_timing("iso.enrich.redhat", redhat_started);
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
                    progress_timing("iso.enrich.redhat", redhat_started);
                    progress("iso.enrich.redhat.error", &format!("{}", e));
                }
            }
        }
    }

    let (scan_status, inventory_status, inventory_reason) = if inventory_complete {
        (ScanStatus::Complete, InventoryStatus::Complete, None)
    } else if !allow_heuristic_fallback {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Missing,
            Some("deep_mode_requires_installed_inventory".into()),
        )
    } else if !packages.is_empty() {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Partial,
            Some(
                runtime_error_reason
                    .clone()
                    .unwrap_or_else(|| "runtime_inventory_unavailable_used_repo_metadata".into()),
            ),
        )
    } else {
        (
            ScanStatus::Unsupported,
            InventoryStatus::Missing,
            Some(
                runtime_error_reason
                    .unwrap_or_else(|| "installed_package_inventory_missing".into()),
            ),
        )
    };

    let scanner = ScannerInfo {
        name: "scanrook",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "iso".into(),
        source: path.to_string(),
        id: None,
    };
    let files = iso_entries_to_file_rows(&entries, 20_000);
    let mut report = Report {
        scanner,
        target,
        scan_status,
        inventory_status,
        inventory_reason,
        sbom: None,
        findings: findings_norm,
        files,
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

fn packages_from_runtime_inventory(
    path: &str,
    entries: &[String],
) -> anyhow::Result<Vec<PackageCoordinate>> {
    let direct = packages_from_runtime_rpmdb_entries(path, entries)?;
    if !direct.is_empty() {
        return Ok(direct);
    }

    let image_candidates = runtime_image_entries(entries);
    if image_candidates.is_empty() {
        return Ok(Vec::new());
    }
    progress(
        "iso.inventory.runtime.images",
        &format!("candidates={}", image_candidates.len()),
    );

    let max_images: usize = std::env::var("SCANNER_ISO_RUNTIME_MAX_IMAGES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(6);

    for entry in image_candidates.into_iter().take(max_images) {
        progress("iso.inventory.runtime.image.start", &entry);
        let image_started = std::time::Instant::now();
        let tmp = tempdir()
            .with_context(|| "failed to create tempdir for ISO runtime image extraction")?;
        let image_path = tmp.path().join("runtime.img");
        let payload = read_iso_entry(path, &entry)?;
        fs::write(&image_path, payload)?;

        let extract_dir = tmp.path().join("runtime-root");
        fs::create_dir_all(&extract_dir)?;
        if !extract_runtime_image(&image_path, &extract_dir)? {
            progress_timing("iso.inventory.runtime.image", image_started);
            progress("iso.inventory.runtime.image.skip", &entry);
            continue;
        }

        let pkgs = query_packages_from_extracted_root(&extract_dir)?;
        progress_timing("iso.inventory.runtime.image", image_started);
        if !pkgs.is_empty() {
            progress(
                "iso.inventory.runtime.image.done",
                &format!("entry={} packages={}", entry, pkgs.len()),
            );
            return Ok(pkgs);
        }
    }

    Ok(Vec::new())
}

fn packages_from_runtime_rpmdb_entries(
    path: &str,
    entries: &[String],
) -> anyhow::Result<Vec<PackageCoordinate>> {
    let markers = ["var/lib/rpm/", "usr/lib/sysimage/rpm/"];
    let mut groups: std::collections::HashMap<(String, String), Vec<String>> =
        std::collections::HashMap::new();

    for entry in entries {
        let norm = normalize_path_like(entry);
        if norm.ends_with('/') {
            continue;
        }
        for marker in markers {
            if let Some(idx) = norm.find(marker) {
                let prefix = norm[..idx].to_string();
                let db_rel = marker.trim_end_matches('/').to_string();
                groups
                    .entry((prefix, db_rel))
                    .or_default()
                    .push(entry.clone());
                break;
            }
        }
    }

    if groups.is_empty() {
        return Ok(Vec::new());
    }

    for ((prefix, db_rel), group_entries) in groups {
        let tmp = tempdir().with_context(|| "failed to create tempdir for ISO rpmdb extraction")?;
        let db_root = tmp.path().join(&db_rel);
        fs::create_dir_all(&db_root)?;

        let marker_with_slash = format!("{}/", db_rel);
        let full_prefix = if prefix.is_empty() {
            marker_with_slash.clone()
        } else {
            format!("{}{}", prefix, marker_with_slash)
        };

        let bulk_extract_root = tmp.path().join("bulk");
        fs::create_dir_all(&bulk_extract_root)?;
        extract_iso_entries_bulk(path, &bulk_extract_root, &group_entries)?;

        let mut extracted = 0usize;
        for entry in group_entries {
            let norm = normalize_path_like(&entry);
            let Some(rel) = norm.strip_prefix(&full_prefix) else {
                continue;
            };
            if rel.is_empty() || rel.ends_with('/') {
                continue;
            }
            let target = db_root.join(rel);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let source = bulk_extract_root.join(&norm);
            if !source.exists() {
                continue;
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source, &target)?;
            extracted += 1;
        }
        if extracted == 0 {
            continue;
        }

        let pkgs = query_rpm_db(&db_root)?;
        if !pkgs.is_empty() {
            return Ok(pkgs
                .into_iter()
                .map(|(name, version)| PackageCoordinate {
                    ecosystem: "redhat".into(),
                    name,
                    version,
                })
                .collect());
        }
    }

    Ok(Vec::new())
}

fn runtime_image_entries(entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        let norm = normalize_path_like(entry);
        let lower = norm.to_ascii_lowercase();
        let is_candidate = lower.ends_with(".squashfs")
            || lower.ends_with(".sqfs")
            || lower.ends_with("squashfs.img")
            || lower.ends_with("rootfs.img")
            || lower.ends_with("install.img")
            || lower.ends_with("/live/rootfs.img")
            || lower.ends_with("/live/filesystem.squashfs")
            || lower.ends_with("/liveos/squashfs.img")
            || lower.ends_with("/liveos/rootfs.img");
        if is_candidate {
            out.push(entry.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn extract_runtime_image(image_path: &Path, dest: &Path) -> anyhow::Result<bool> {
    if command_exists("unsquashfs") {
        let output = Command::new("unsquashfs")
            .arg("-f")
            .arg("-d")
            .arg(dest)
            .arg(image_path)
            .output()
            .with_context(|| format!("failed to invoke unsquashfs on {}", image_path.display()))?;
        if output.status.success() {
            return Ok(true);
        }
        progress(
            "iso.inventory.runtime.unsquashfs.error",
            &String::from_utf8_lossy(&output.stderr),
        );
    }

    let output = Command::new("bsdtar")
        .arg("-xf")
        .arg(image_path)
        .arg("-C")
        .arg(dest)
        .output()
        .with_context(|| format!("failed to invoke bsdtar on {}", image_path.display()))?;
    if output.status.success() {
        return Ok(true);
    }
    progress(
        "iso.inventory.runtime.bsdtar.error",
        &String::from_utf8_lossy(&output.stderr),
    );
    Ok(false)
}

fn command_exists(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {} >/dev/null 2>&1", cmd))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn query_packages_from_extracted_root(root: &Path) -> anyhow::Result<Vec<PackageCoordinate>> {
    let mut rpmdb_paths: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_dir() {
            continue;
        }
        let rel = match entry.path().strip_prefix(root) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let norm = rel.to_string_lossy().replace('\\', "/");
        if norm.ends_with("var/lib/rpm") || norm.ends_with("usr/lib/sysimage/rpm") {
            rpmdb_paths.push(entry.path().to_path_buf());
        }
    }

    rpmdb_paths.sort();
    rpmdb_paths.dedup();
    for dbpath in rpmdb_paths {
        match query_rpm_db(&dbpath) {
            Ok(pkgs) if !pkgs.is_empty() => {
                return Ok(pkgs
                    .into_iter()
                    .map(|(name, version)| PackageCoordinate {
                        ecosystem: "redhat".into(),
                        name,
                        version,
                    })
                    .collect());
            }
            Ok(_) => {}
            Err(e) => {
                progress(
                    "iso.inventory.runtime.rpmdb.error",
                    &format!("{} {}", dbpath.display(), e),
                );
            }
        }
    }
    Ok(Vec::new())
}

fn query_rpm_db(dbpath: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let output = Command::new("rpm")
        .arg("-qa")
        .arg("--dbpath")
        .arg(dbpath)
        .arg("--qf")
        .arg("%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n")
        .output()
        .with_context(|| format!("failed to invoke rpm for dbpath {}", dbpath.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "rpm query failed for dbpath {}: {}",
            dbpath.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
            out.push((
                name.to_string(),
                ver.trim_start_matches("(none):").to_string(),
            ));
        }
    }
    Ok(out)
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

fn extract_iso_entries_bulk(path: &str, dest: &Path, entries: &[String]) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut cmd = Command::new("bsdtar");
    cmd.arg("-xf").arg(path).arg("-C").arg(dest);
    for entry in entries {
        cmd.arg(entry);
    }
    let output = cmd
        .output()
        .with_context(|| "failed bulk extracting ISO subtree with bsdtar")?;
    if !output.status.success() {
        return Err(anyhow!(
            "bsdtar bulk extraction failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
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

fn iso_entries_to_file_rows(entries: &[String], limit: usize) -> Vec<FileEntry> {
    let cap = if limit == 0 { 20_000 } else { limit };
    let mut out: Vec<FileEntry> = Vec::new();
    for entry in entries.iter().take(cap) {
        let norm = normalize_path_like(entry);
        if norm.is_empty() {
            continue;
        }
        let is_dir = norm.ends_with('/');
        let clean = norm.trim_end_matches('/').to_string();
        if clean.is_empty() {
            continue;
        }
        let parent_path = std::path::Path::new(&clean)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .filter(|p| !p.is_empty());
        out.push(FileEntry {
            path: clean,
            entry_type: if is_dir { "dir" } else { "file" }.to_string(),
            size_bytes: None,
            mode: None,
            mtime: None,
            sha256: None,
            parent_path,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
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
