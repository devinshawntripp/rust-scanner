use crate::ScanMode;
use crate::{archive, binary, container, iso, sbom};
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub fn build_scan_report_value(
    file: &str,
    mode: ScanMode,
    yara: Option<String>,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Value> {
    // Early exit for non-existent files
    if !std::path::Path::new(file).exists() {
        eprintln!("File not found: {}", file);
        crate::utils::progress("scan.error", &format!("file_not_found={}", file));
        return None;
    }

    let dmg_like = looks_like_dmg_input(file);
    let tar_like = looks_like_tar_input(file);
    let iso_like = looks_like_iso_input(file);
    let sbom_like = looks_like_sbom_input(file);
    let zip_like = looks_like_zip_input(file);
    // DMG before tar: UDIF DMGs use bzip2 compression internally, which triggers
    // looks_like_tar_input(). Checking DMG first prevents bzip2-compressed DMGs
    // from being misrouted to the tar pipeline.
    if dmg_like {
        if let Some(r) = archive::build_dmg_report(file, mode.clone(), nvd_api_key.clone()) {
            return serde_json::to_value(r).ok();
        }
        return None;
    }
    if tar_like {
        if let Some(r) = container::build_container_report(
            file,
            mode.clone(),
            false,
            nvd_api_key.clone(),
            yara.clone(),
            oval_redhat.clone(),
        ) {
            return serde_json::to_value(r).ok();
        }
        if let Some(r) = container::build_source_report(file, nvd_api_key) {
            return serde_json::to_value(r).ok();
        }
        return None;
    }
    if iso_like {
        if let Some(r) = iso::build_iso_report(file, mode, yara, nvd_api_key, oval_redhat) {
            return serde_json::to_value(r).ok();
        }
        return None;
    }
    if sbom_like {
        if let Some(r) = sbom::build_sbom_report(file, mode, nvd_api_key) {
            return serde_json::to_value(r).ok();
        }
        return None;
    }
    if zip_like {
        if let Some(r) = archive::build_archive_report(file, mode.clone(), nvd_api_key.clone()) {
            return serde_json::to_value(r).ok();
        }
        // Fall through to binary if archive scanning fails
    }
    binary::build_binary_report(file, mode, yara, nvd_api_key)
        .and_then(|r| serde_json::to_value(r).ok())
}

pub fn looks_like_tar_input(path: &str) -> bool {
    let lower = path.to_lowercase();

    // OVAL XML files use bzip2 compression but are not tarballs
    if lower.ends_with(".oval.xml.bz2") || lower.ends_with(".oval.xml") {
        return false;
    }

    if lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar.bz2")
        || lower.ends_with(".tbz2")
        || lower.ends_with(".tbz")
    {
        return true;
    }

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut head = [0u8; 512];
    let n = match f.read(&mut head) {
        Ok(n) => n,
        Err(_) => return false,
    };

    // gzip / bzip2 signatures (can still be non-tar, but worth trying tar path first)
    if n >= 2 && head[0] == 0x1f && head[1] == 0x8b {
        return true;
    }
    if n >= 3 && head[0] == b'B' && head[1] == b'Z' && head[2] == b'h' {
        return true;
    }

    // USTAR magic at offset 257.
    if n >= 262 && &head[257..262] == b"ustar" {
        return true;
    }
    if n < 262 {
        let mut block = [0u8; 262];
        if f.seek(SeekFrom::Start(0)).is_ok() && f.read(&mut block).ok().unwrap_or(0) >= 262 {
            return &block[257..262] == b"ustar";
        }
    }
    false
}

pub fn looks_like_iso_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".iso") {
        return true;
    }

    let mut f = match File::open(path) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // ISO9660 PVD at sector 16 (offset 32768):
    // byte 0 = descriptor type (1 for primary), bytes 1..5 = "CD001"
    if f.seek(SeekFrom::Start(32768)).is_err() {
        return false;
    }
    let mut pvd = [0u8; 7];
    if f.read(&mut pvd).ok().unwrap_or(0) < 7 {
        return false;
    }
    pvd[0] == 0x01 && &pvd[1..6] == b"CD001"
}

pub fn looks_like_sbom_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".spdx.json")
        || lower.ends_with(".cyclonedx.json")
        || lower.ends_with(".cdx.json")
        || lower.ends_with(".sbom.json")
    {
        return true;
    }
    if !lower.ends_with(".json") {
        return false;
    }

    let mut f = match File::open(path) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut head = vec![0u8; 8192];
    let n = match f.read(&mut head) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if n == 0 {
        return false;
    }
    let text = String::from_utf8_lossy(&head[..n]).to_lowercase();
    text.contains("\"bomformat\"")
        || text.contains("\"spdxversion\"")
        || text.contains("\"artifacts\"")
}

pub fn looks_like_zip_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // Extension check for known ZIP-based formats
    if lower.ends_with(".zip")
        || lower.ends_with(".jar")
        || lower.ends_with(".war")
        || lower.ends_with(".ear")
        || lower.ends_with(".aab")
        || lower.ends_with(".whl")
        || lower.ends_with(".nupkg")
        || lower.ends_with(".ipa")
        || lower.ends_with(".xpi")
        || lower.ends_with(".vsix")
        || lower.ends_with(".crx")
    {
        return true;
    }
    // .apk could be Android APK (ZIP) or Alpine package (tar) — check magic bytes
    if lower.ends_with(".apk") {
        let mut f = match File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut magic = [0u8; 4];
        return f.read(&mut magic).ok().unwrap_or(0) >= 4
            && magic[0] == 0x50
            && magic[1] == 0x4b
            && magic[2] == 0x03
            && magic[3] == 0x04;
    }

    // Magic bytes: PK\x03\x04 (ZIP local file header)
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    if f.read(&mut magic).ok().unwrap_or(0) < 4 {
        return false;
    }
    magic[0] == 0x50 && magic[1] == 0x4b && magic[2] == 0x03 && magic[3] == 0x04
}

pub fn looks_like_dmg_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".dmg") {
        return true;
    }
    // Check for UDIF magic at the end of the file (koly block)
    // or common DMG signatures
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // UDIF trailer is at the very end of the file: "koly" magic
    if let Ok(pos) = f.seek(SeekFrom::End(-512)) {
        let _ = pos;
        let mut tail = [0u8; 512];
        if f.read(&mut tail).ok().unwrap_or(0) >= 4 {
            // Look for "koly" signature
            if tail[0] == b'k' && tail[1] == b'o' && tail[2] == b'l' && tail[3] == b'y' {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_file_returns_none_early() {
        let result = build_scan_report_value(
            "/tmp/scanrook_test_nonexistent_file_xyz.tar",
            ScanMode::Light,
            None,
            None,
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn oval_bz2_not_detected_as_tar() {
        assert!(!looks_like_tar_input("rhel-8.oval.xml.bz2"));
        assert!(!looks_like_tar_input("RHEL9/rhel-9.oval.xml.bz2"));
        assert!(!looks_like_tar_input("test.oval.xml"));
        // Real tar files should still be detected
        assert!(looks_like_tar_input("image.tar.bz2"));
        assert!(looks_like_tar_input("archive.tar.gz"));
    }
}
