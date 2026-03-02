//! Tar extraction, container layer merging, and fast OS package detection from layers.

use crate::container::apk::parse_apk_installed;
use crate::container::dpkg::parse_dpkg_status;
use crate::container::PackageCoordinate;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tar::Archive;

/// Maximum decompressed size per tar entry (2 GB) to guard against decompression bombs
const MAX_ENTRY_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Extracts a tar archive (optionally gzipped) to dest with path-traversal protection.
///
/// Each entry's path is validated to stay within `dest`. Symlinks pointing outside
/// the destination are rejected. Individual entry sizes are capped at MAX_ENTRY_SIZE.
pub fn extract_tar(tar_path: &str, dest: &Path) -> anyhow::Result<()> {
    let file = File::open(tar_path)?;
    let mut archive: Archive<Box<dyn std::io::Read>> =
        if tar_path.ends_with(".gz") || tar_path.ends_with(".tgz") {
            Archive::new(Box::new(GzDecoder::new(file)))
        } else if tar_path.ends_with(".bz2")
            || tar_path.ends_with(".tbz")
            || tar_path.ends_with(".tbz2")
        {
            Archive::new(Box::new(BzDecoder::new(file)))
        } else {
            Archive::new(Box::new(file))
        };

    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let raw_path = entry.path()?.to_path_buf();

        // Reject entries with absolute paths or path-traversal components
        if raw_path.is_absolute() {
            anyhow::bail!(
                "tar entry has absolute path (potential path traversal): {}",
                raw_path.display()
            );
        }
        for component in raw_path.components() {
            if let std::path::Component::ParentDir = component {
                anyhow::bail!(
                    "tar entry contains '..' (potential path traversal): {}",
                    raw_path.display()
                );
            }
        }

        let target = dest.join(&raw_path);
        // After joining, canonicalize parent to verify it's within dest
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let canonical_target = target
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.join(target.file_name().unwrap_or_default()))
            .unwrap_or_else(|| target.clone());
        if !canonical_target.starts_with(&canonical_dest) {
            anyhow::bail!(
                "tar entry escapes destination directory (path traversal): {}",
                raw_path.display()
            );
        }

        // Reject symlinks that point outside the destination
        if entry.header().entry_type().is_symlink() {
            if let Ok(link_target) = entry.link_name() {
                if let Some(link_path) = link_target.as_ref() {
                    let resolved = if link_path.is_absolute() {
                        link_path.to_path_buf()
                    } else {
                        canonical_target
                            .parent()
                            .unwrap_or(&canonical_dest)
                            .join(link_path)
                    };
                    // Normalize the resolved path by stripping .. components
                    let mut normalized = PathBuf::new();
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
                        anyhow::bail!(
                            "tar symlink escapes destination directory: {} -> {}",
                            raw_path.display(),
                            link_path.display()
                        );
                    }
                }
            }
        }

        // Guard against decompression bombs
        if entry.header().size()? > MAX_ENTRY_SIZE {
            anyhow::bail!(
                "tar entry exceeds maximum allowed size ({} bytes): {}",
                MAX_ENTRY_SIZE,
                raw_path.display()
            );
        }

        entry.unpack(&target)?;
    }
    Ok(())
}

pub(super) fn try_detect_os_packages_from_layout(extracted: &Path) -> anyhow::Result<Vec<PackageCoordinate>> {
    let manifest_path = extracted.join("manifest.json");
    let oci_index_path = extracted.join("index.json");

    let layer_paths = if manifest_path.exists() {
        docker_save_layer_paths(extracted)?
    } else if oci_index_path.exists() {
        oci_layer_paths(extracted)?
    } else {
        return Ok(Vec::new());
    };

    detect_os_packages_from_layers(&layer_paths)
}

fn docker_save_layer_paths(extracted: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let manifest_path = extracted.join("manifest.json");
    let mut manifest_str = String::new();
    File::open(&manifest_path)?.read_to_string(&mut manifest_str)?;
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)?;
    let first = &manifest_json[0];
    let layers = first["Layers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No Layers"))?;

    let mut out = Vec::with_capacity(layers.len());
    for layer_rel in layers {
        let layer_rel = layer_rel
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Layer not string"))?;
        out.push(extracted.join(layer_rel));
    }
    Ok(out)
}

fn oci_layer_paths(extracted: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let index_path = extracted.join("index.json");
    let index_str = fs::read_to_string(&index_path)?;
    let index_json: serde_json::Value = serde_json::from_str(&index_str)?;
    let manifests = index_json["manifests"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("OCI index missing manifests"))?;
    let first = manifests
        .first()
        .ok_or_else(|| anyhow::anyhow!("OCI index manifests empty"))?;
    let manifest_digest = first["digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("OCI descriptor missing digest"))?;
    let manifest_blob = blob_path_from_digest(extracted, manifest_digest)?;

    let manifest_str = fs::read_to_string(&manifest_blob)?;
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)?;
    let layers = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("OCI manifest missing layers"))?;

    let mut out = Vec::with_capacity(layers.len());
    for layer in layers {
        let digest = layer["digest"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("OCI layer missing digest"))?;
        out.push(blob_path_from_digest(extracted, digest)?);
    }
    Ok(out)
}

fn detect_os_packages_from_layers(
    layer_paths: &[PathBuf],
) -> anyhow::Result<Vec<PackageCoordinate>> {
    let mut dpkg_status: Option<Vec<u8>> = None;
    let mut apk_installed: Option<Vec<u8>> = None;

    for layer_path in layer_paths {
        apply_layer_file_overrides(layer_path, &mut dpkg_status, &mut apk_installed)?;
    }

    let mut packages = Vec::new();
    if let Some(bytes) = dpkg_status {
        if let Ok(s) = String::from_utf8(bytes) {
            parse_dpkg_status(&s, &mut packages);
        }
    }
    if let Some(bytes) = apk_installed {
        if let Ok(s) = String::from_utf8(bytes) {
            parse_apk_installed(&s, &mut packages);
        }
    }
    Ok(packages)
}

fn apply_layer_file_overrides(
    layer_tar: &Path,
    dpkg_status: &mut Option<Vec<u8>>,
    apk_installed: &mut Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut file = File::open(layer_tar)?;
    let mut head = [0u8; 3];
    let n = file.read(&mut head)?;
    file.seek(SeekFrom::Start(0))?;

    let is_gz = n >= 2 && head[0] == 0x1f && head[1] == 0x8b;
    let is_bz2 = n >= 3 && head[0] == b'B' && head[1] == b'Z' && head[2] == b'h';

    let mut archive: Archive<Box<dyn Read>> = if is_gz {
        Archive::new(Box::new(GzDecoder::new(file)))
    } else if is_bz2 {
        Archive::new(Box::new(BzDecoder::new(file)))
    } else {
        Archive::new(Box::new(file))
    };

    for entry in archive.entries()? {
        let mut entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(v) => v.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if path.is_empty() {
            continue;
        }

        let parent = std::path::Path::new(&path)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let base = std::path::Path::new(&path)
            .file_name()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // overlayfs whiteout for whole directory content
        if base == ".wh..wh..opq" {
            if parent == "var/lib/dpkg" {
                *dpkg_status = None;
            }
            if parent == "lib/apk/db" {
                *apk_installed = None;
            }
            continue;
        }
        // overlayfs whiteout for single file
        if let Some(stripped) = base.strip_prefix(".wh.") {
            let target = if parent.is_empty() {
                stripped.to_string()
            } else {
                format!("{}/{}", parent, stripped)
            };
            if target == "var/lib/dpkg/status" {
                *dpkg_status = None;
            } else if target == "lib/apk/db/installed" {
                *apk_installed = None;
            }
            continue;
        }

        if path == "var/lib/dpkg/status" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            *dpkg_status = Some(buf);
        } else if path == "lib/apk/db/installed" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            *apk_installed = Some(buf);
        }
    }

    Ok(())
}

pub(super) fn merge_layers_docker_save(extracted: &Path) -> anyhow::Result<PathBuf> {
    // docker save layout: manifest.json + layer tarballs and config
    let layers = docker_save_layer_paths(extracted)?;

    let rootfs_dir = extracted.join("rootfs");
    fs::create_dir_all(&rootfs_dir)?;

    for layer_path in layers {
        apply_layer_tar(&layer_path, &rootfs_dir)?;
    }

    Ok(rootfs_dir)
}

pub(super) fn merge_layers_oci_layout(extracted: &Path) -> anyhow::Result<PathBuf> {
    // OCI image layout: index.json -> manifest blob -> layer blobs
    let layers = oci_layer_paths(extracted)?;

    let rootfs_dir = extracted.join("rootfs");
    fs::create_dir_all(&rootfs_dir)?;

    for layer in layers {
        apply_layer_tar(&layer, &rootfs_dir)?;
    }

    Ok(rootfs_dir)
}

fn blob_path_from_digest(extracted: &Path, digest: &str) -> anyhow::Result<PathBuf> {
    let mut parts = digest.splitn(2, ':');
    let algo = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid digest: missing algorithm"))?;
    let hash = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid digest: missing hash"))?;
    Ok(extracted.join("blobs").join(algo).join(hash))
}

fn apply_layer_tar(layer_tar: &Path, rootfs: &Path) -> anyhow::Result<()> {
    let mut file = File::open(layer_tar)?;
    let mut head = [0u8; 3];
    let n = file.read(&mut head)?;
    file.seek(SeekFrom::Start(0))?;

    let is_gz = n >= 2 && head[0] == 0x1f && head[1] == 0x8b;
    let is_bz2 = n >= 3 && head[0] == b'B' && head[1] == b'Z' && head[2] == b'h';

    if is_gz {
        let gz = GzDecoder::new(file);
        let mut ar = Archive::new(gz);
        ar.unpack(rootfs)?;
    } else if is_bz2 {
        let bz = BzDecoder::new(file);
        let mut ar = Archive::new(bz);
        ar.unpack(rootfs)?;
    } else {
        let mut ar = Archive::new(file);
        ar.unpack(rootfs)?;
    }
    Ok(())
}
