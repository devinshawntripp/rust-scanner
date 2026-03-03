//! ISO entry extraction, decompression, path normalization, and filesystem helpers.

use crate::utils::progress;
use anyhow::{anyhow, Context};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

pub(super) fn list_iso_entries(path: &str) -> anyhow::Result<Vec<String>> {
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

pub(super) fn read_iso_entry(path: &str, entry: &str) -> anyhow::Result<Vec<u8>> {
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

pub(super) fn extract_iso_entries_bulk(path: &str, dest: &Path, entries: &[String]) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    // Reject entries with path-traversal components before passing to bsdtar
    for entry in entries {
        if entry.contains("..") {
            return Err(anyhow!(
                "refusing ISO entry with path-traversal component: {}",
                entry
            ));
        }
    }
    let mut cmd = Command::new("bsdtar");
    cmd.arg("--no-fflags")
        .arg("-xf")
        .arg(path)
        .arg("-C")
        .arg(dest);
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
    validate_extraction_within(dest)?;
    Ok(())
}

pub(super) fn decompress_if_needed(entry: &str, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
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

/// Walks the extraction directory and verifies no symlinks escape it.
pub(super) fn validate_extraction_within(dest: &Path) -> anyhow::Result<()> {
    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
    for entry in WalkDir::new(dest).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_symlink() {
            if let Ok(target) = fs::read_link(path) {
                let resolved = if target.is_absolute() {
                    target.clone()
                } else {
                    path.parent().unwrap_or(dest).join(&target)
                };
                let mut normalized = std::path::PathBuf::new();
                for comp in resolved.components() {
                    match comp {
                        std::path::Component::ParentDir => {
                            normalized.pop();
                        }
                        std::path::Component::CurDir => {}
                        other => normalized.push(other),
                    }
                }
                if !normalized.starts_with(&canonical_dest) {
                    let _ = fs::remove_file(path);
                    crate::utils::progress(
                        "iso.security.symlink_removed",
                        &format!(
                            "removed symlink escaping dest: {} -> {}",
                            path.display(),
                            target.display()
                        ),
                    );
                }
            }
        }
    }
    Ok(())
}

pub(super) fn normalize_path_like(s: &str) -> String {
    s.trim()
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

pub(super) fn find_entry<'a>(entries: &'a [String], wanted: &str) -> Option<&'a str> {
    let wanted_norm = normalize_path_like(wanted);
    entries
        .iter()
        .find(|e| normalize_path_like(e) == wanted_norm)
        .map(String::as_str)
}

pub(super) fn command_exists(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {} >/dev/null 2>&1", cmd))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
