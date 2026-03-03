//! RPM package inventory detection from ISO images: runtime rpmdb, squashfs images, filenames, repodata.

use crate::container::PackageCoordinate;
use crate::utils::{progress, progress_timing};
use super::extract::*;
use anyhow::Context;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;
use walkdir::WalkDir;

pub(super) fn packages_from_runtime_inventory(
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
                    source_name: None,
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
            .arg("-no-xattrs")
            .arg("-d")
            .arg(dest)
            .arg(image_path)
            .output()
            .with_context(|| format!("failed to invoke unsquashfs on {}", image_path.display()))?;
        if output.status.success() {
            validate_extraction_within(dest)?;
            return Ok(true);
        }
        progress(
            "iso.inventory.runtime.unsquashfs.error",
            &String::from_utf8_lossy(&output.stderr),
        );
    }

    let output = Command::new("bsdtar")
        .arg("--no-fflags")
        .arg("-xf")
        .arg(image_path)
        .arg("-C")
        .arg(dest)
        .output()
        .with_context(|| format!("failed to invoke bsdtar on {}", image_path.display()))?;
    if output.status.success() {
        validate_extraction_within(dest)?;
        return Ok(true);
    }
    progress(
        "iso.inventory.runtime.bsdtar.error",
        &String::from_utf8_lossy(&output.stderr),
    );
    Ok(false)
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
                        source_name: None,
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
    // Try native SQLite first
    let sqlite_path = dbpath.join("rpmdb.sqlite");
    if sqlite_path.exists() {
        match crate::container::parse_rpm_sqlite(&sqlite_path) {
            Ok(pkgs) if !pkgs.is_empty() => {
                return Ok(pkgs.into_iter().map(|(n, v, _)| (n, v)).collect());
            }
            Ok(_) => {}
            Err(e) => {
                crate::utils::progress(
                    "iso.rpm.native.sqlite.error",
                    &format!("{}: {}", sqlite_path.display(), e),
                );
            }
        }
    }

    // Try native BerkeleyDB
    for bdb_name in &["Packages", "Packages.db"] {
        let bdb_path = dbpath.join(bdb_name);
        if bdb_path.exists() {
            match crate::container::parse_rpm_bdb(&bdb_path) {
                Ok(pkgs) if !pkgs.is_empty() => {
                    return Ok(pkgs.into_iter().map(|(n, v, _)| (n, v)).collect());
                }
                Ok(_) => {}
                Err(e) => {
                    crate::utils::progress(
                        "iso.rpm.native.bdb.error",
                        &format!("{}: {}", bdb_path.display(), e),
                    );
                }
            }
        }
    }

    // Fall back to rpm CLI
    let output = Command::new("rpm")
        .arg("-qa")
        .arg("--dbpath")
        .arg(dbpath)
        .arg("--qf")
        .arg("%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n")
        .output()
        .with_context(|| format!("failed to invoke rpm for dbpath {}", dbpath.display()))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
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

pub(super) fn packages_from_rpm_entries(entries: &[String]) -> Vec<PackageCoordinate> {
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
                source_name: None,
            });
        }
    }
    out
}

pub(super) fn parse_rpm_filename(file_name: &str) -> Option<(String, String)> {
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

pub(super) fn dedupe_packages(input: Vec<PackageCoordinate>) -> Vec<PackageCoordinate> {
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
