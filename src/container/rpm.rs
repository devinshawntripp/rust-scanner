//! RPM package detection: SQLite, BerkeleyDB, and CLI fallback.

use crate::utils::progress;
use std::fs;
use std::path::Path;

/// RPM header tag constants
const RPM_TAG_NAME: u32 = 1000;
const RPM_TAG_VERSION: u32 = 1001;
const RPM_TAG_RELEASE: u32 = 1002;
const RPM_TAG_EPOCH: u32 = 1003;
/// RPM tag 1044: SOURCERPM — filename of the source RPM (e.g. "openssl-3.0.7-27.el9.src.rpm")
const RPM_TAG_SOURCERPM: u32 = 1044;
/// RPM tag type: STRING
const RPM_TYPE_STRING: u32 = 6;
/// RPM tag type: INT32
const RPM_TYPE_INT32: u32 = 4;

/// Detect RPM packages using native parsing (SQLite + BerkeleyDB), falling back to rpm CLI.
pub(super) fn detect_rpm_packages_native(
    rootfs: &Path,
) -> anyhow::Result<Vec<(String, String, Option<String>)>> {
    let db_candidates = [
        rootfs.join("var/lib/rpm/rpmdb.sqlite"),
        rootfs.join("usr/lib/sysimage/rpm/rpmdb.sqlite"),
    ];

    // 1. Try SQLite databases first (modern RPM: RHEL 9+, Fedora 33+, Rocky 9+)
    for sqlite_path in &db_candidates {
        if !sqlite_path.exists() {
            continue;
        }
        progress(
            "container.rpm.native.sqlite",
            &sqlite_path.to_string_lossy(),
        );
        match parse_rpm_sqlite(sqlite_path) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress(
                    "container.rpm.native.sqlite.done",
                    &format!("packages={}", pkgs.len()),
                );
                return Ok(pkgs);
            }
            Ok(_) => {
                progress(
                    "container.rpm.native.sqlite.empty",
                    &sqlite_path.to_string_lossy(),
                );
            }
            Err(e) => {
                progress(
                    "container.rpm.native.sqlite.error",
                    &format!("{}: {}", sqlite_path.display(), e),
                );
            }
        }
    }

    // 2. Try BerkeleyDB Packages file (legacy RPM: RHEL 7/8, CentOS, older Fedora)
    let bdb_candidates = [
        rootfs.join("var/lib/rpm/Packages"),
        rootfs.join("var/lib/rpm/Packages.db"),
        rootfs.join("usr/lib/sysimage/rpm/Packages"),
        rootfs.join("usr/lib/sysimage/rpm/Packages.db"),
    ];
    for bdb_path in &bdb_candidates {
        if !bdb_path.exists() {
            continue;
        }
        progress("container.rpm.native.bdb", &bdb_path.to_string_lossy());
        match parse_rpm_bdb(bdb_path) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress(
                    "container.rpm.native.bdb.done",
                    &format!("packages={}", pkgs.len()),
                );
                return Ok(pkgs);
            }
            Ok(_) => {
                progress(
                    "container.rpm.native.bdb.empty",
                    &bdb_path.to_string_lossy(),
                );
            }
            Err(e) => {
                progress(
                    "container.rpm.native.bdb.error",
                    &format!("{}: {}", bdb_path.display(), e),
                );
            }
        }
    }

    // 3. Fall back to rpm CLI as last resort
    progress("container.rpm.native.fallback", "trying rpm CLI");
    detect_rpm_packages_cli(rootfs)
}

/// Parse RPM packages from a SQLite rpmdb.
pub fn parse_rpm_sqlite(path: &Path) -> anyhow::Result<Vec<(String, String, Option<String>)>> {
    use rusqlite::Connection;
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare("SELECT hnum, blob FROM Packages")?;
    let mut results = Vec::new();
    let rows = stmt.query_map([], |row| {
        let _hnum: i64 = row.get(0)?;
        let blob: Vec<u8> = row.get(1)?;
        Ok(blob)
    })?;
    for row in rows {
        let blob = match row {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some((name, version, source_name)) = parse_rpm_header_blob(&blob) {
            results.push((name, version, source_name));
        }
    }
    Ok(results)
}

/// Parse RPM packages from a BerkeleyDB hash-format Packages file.
pub fn parse_rpm_bdb(path: &Path) -> anyhow::Result<Vec<(String, String, Option<String>)>> {
    let data = fs::read(path)?;
    if data.len() < 512 {
        return Err(anyhow::anyhow!("file too small for BerkeleyDB"));
    }

    // BerkeleyDB hash magic: 0x00061561 (little-endian) at offset 12
    // Or btree magic: 0x00053162 at offset 12
    let magic = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let is_hash = magic == 0x00061561;
    let is_btree = magic == 0x00053162;
    if !is_hash && !is_btree {
        return Err(anyhow::anyhow!(
            "not a BerkeleyDB hash/btree file (magic=0x{:08x})",
            magic
        ));
    }

    // Page size at offset 20 (4 bytes LE)
    let page_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
    if page_size == 0 || page_size > 65536 || data.len() % page_size != 0 {
        // Try common page sizes
        return parse_rpm_bdb_scan(&data);
    }

    parse_rpm_bdb_scan(&data)
}

/// Scan BerkeleyDB data for RPM header blobs by looking for the RPM header magic.
fn parse_rpm_bdb_scan(data: &[u8]) -> anyhow::Result<Vec<(String, String, Option<String>)>> {
    let mut results = Vec::new();
    let rpm_magic: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];

    // Scan for RPM header magic bytes throughout the file
    let mut offset = 0;
    while offset + 16 < data.len() {
        if data[offset..offset + 4] == rpm_magic {
            // Found an RPM header; try to parse it
            if let Some((name, version, source_name)) = parse_rpm_header_blob(&data[offset..]) {
                results.push((name, version, source_name));
            }
        }
        offset += 1;
    }

    if results.is_empty() {
        return Err(anyhow::anyhow!("no RPM headers found in BerkeleyDB file"));
    }
    Ok(results)
}

/// Parse NAME, VERSION, RELEASE, EPOCH from an RPM header binary blob.
///
/// RPM header format:
///   Bytes 0-3:   magic (8e ad e8 01)
///   Bytes 4-7:   reserved (4 bytes)
///   Bytes 8-11:  nindex — number of tag entries (big-endian u32)
///   Bytes 12-15: hsize — size of the data section in bytes (big-endian u32)
///   Bytes 16..:  nindex * 16-byte tag entries, then hsize bytes of data
///
/// Each tag entry (16 bytes):
///   Bytes 0-3: tag id (big-endian u32)
///   Bytes 4-7: type (big-endian u32)
///   Bytes 8-11: offset into data section (big-endian u32)
///   Bytes 12-15: count (big-endian u32)
/// Returns (name, version, source_name) where source_name is derived from SOURCERPM tag.
pub(super) fn parse_rpm_header_blob(blob: &[u8]) -> Option<(String, String, Option<String>)> {
    if blob.len() < 16 {
        return None;
    }

    // RPM header blobs come in two formats:
    // 1. With magic prefix: [8e ad e8 01] [reserved 4B] [nindex 4B] [hsize 4B] ...
    // 2. Without magic (rpmdb.sqlite in RPM 4.16+): [nindex 4B] [hsize 4B] ...
    let (nindex, hsize, entries_start) = if blob[0..4] == [0x8e, 0xad, 0xe8, 0x01] {
        // Format 1: magic header present
        let ni = u32::from_be_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let hs = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
        (ni, hs, 16usize)
    } else {
        // Format 2: no magic, starts with nindex + hsize directly (RPM 4.16+ SQLite)
        let ni = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        let hs = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        (ni, hs, 8usize)
    };

    // Sanity check: nindex and hsize shouldn't be unreasonably large
    if nindex > 10000 || hsize > 64 * 1024 * 1024 {
        return None;
    }

    let entries_size = nindex * 16;
    let data_start = entries_start + entries_size;
    let total_needed = data_start + hsize;
    if blob.len() < total_needed {
        // If the blob is smaller, try with available data
        if blob.len() < data_start {
            return None;
        }
    }

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut release: Option<String> = None;
    let mut epoch: Option<u32> = None;
    let mut source_rpm: Option<String> = None;

    for i in 0..nindex {
        let e = entries_start + i * 16;
        if e + 16 > blob.len() {
            break;
        }
        let tag = u32::from_be_bytes([blob[e], blob[e + 1], blob[e + 2], blob[e + 3]]);
        let ttype = u32::from_be_bytes([blob[e + 4], blob[e + 5], blob[e + 6], blob[e + 7]]);
        let toffset =
            u32::from_be_bytes([blob[e + 8], blob[e + 9], blob[e + 10], blob[e + 11]]) as usize;

        let abs_offset = data_start + toffset;

        match tag {
            RPM_TAG_NAME | RPM_TAG_VERSION | RPM_TAG_RELEASE | RPM_TAG_SOURCERPM
                if ttype == RPM_TYPE_STRING =>
            {
                if abs_offset < blob.len() {
                    let end = blob[abs_offset..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(blob.len() - abs_offset);
                    if let Ok(s) = std::str::from_utf8(&blob[abs_offset..abs_offset + end]) {
                        match tag {
                            RPM_TAG_NAME => name = Some(s.to_string()),
                            RPM_TAG_VERSION => version = Some(s.to_string()),
                            RPM_TAG_RELEASE => release = Some(s.to_string()),
                            RPM_TAG_SOURCERPM => source_rpm = Some(s.to_string()),
                            _ => {}
                        }
                    }
                }
            }
            RPM_TAG_EPOCH if ttype == RPM_TYPE_INT32 => {
                if abs_offset + 4 <= blob.len() {
                    epoch = Some(u32::from_be_bytes([
                        blob[abs_offset],
                        blob[abs_offset + 1],
                        blob[abs_offset + 2],
                        blob[abs_offset + 3],
                    ]));
                }
            }
            _ => {}
        }

        // Short-circuit if we found everything (name+version+release+epoch+sourcerpm)
        if name.is_some() && version.is_some() && release.is_some() && source_rpm.is_some() {
            if epoch.is_some() || i > nindex / 2 {
                break;
            }
        }
    }

    let n = name?;
    let v = version?;
    let r = release.unwrap_or_default();

    let full_version = if let Some(e) = epoch {
        if e > 0 {
            format!("{}:{}-{}", e, v, r)
        } else if r.is_empty() {
            v
        } else {
            format!("{}-{}", v, r)
        }
    } else if r.is_empty() {
        v
    } else {
        format!("{}-{}", v, r)
    };

    // Parse source package name from SOURCERPM (e.g. "openssl-3.0.7-27.el9.src.rpm" → "openssl")
    let source_name = source_rpm.and_then(|srpm| {
        // Format: name-version-release.arch.src.rpm
        // Strip ".src.rpm" suffix, then find the last two "-" to get the name
        let stripped = srpm.strip_suffix(".src.rpm").unwrap_or(&srpm);
        // Find the second-to-last "-" (separates name from version)
        let mut last_dash = None;
        let mut second_last_dash = None;
        for (i, c) in stripped.char_indices() {
            if c == '-' {
                second_last_dash = last_dash;
                last_dash = Some(i);
            }
        }
        second_last_dash
            .map(|i| {
                let src_name = stripped[..i].to_string();
                if src_name == n {
                    None
                } else {
                    Some(src_name)
                }
            })
            .flatten()
    });

    Some((n, full_version, source_name))
}

/// Fallback: detect RPM packages using the system rpm CLI.
pub(super) fn detect_rpm_packages_cli(
    rootfs: &Path,
) -> anyhow::Result<Vec<(String, String, Option<String>)>> {
    use std::process::Command;
    let dbpaths = [
        rootfs.join("var/lib/rpm"),
        rootfs.join("usr/lib/sysimage/rpm"),
    ];

    let mut last_err: Option<anyhow::Error> = None;
    for dbpath in dbpaths.iter() {
        if !dbpath.exists() {
            continue;
        }

        let output = Command::new("rpm")
            .arg("-qa")
            .arg("--dbpath")
            .arg(dbpath)
            .arg("--qf")
            .arg("%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{SOURCERPM}\n")
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout);
                let mut results = Vec::new();
                for line in s.lines() {
                    let mut parts = line.split_whitespace();
                    if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
                        let ver = ver.trim_start_matches("(none):");
                        let srpm = parts.next().unwrap_or("(none)");
                        let source_name = if srpm == "(none)" {
                            None
                        } else {
                            // Parse source name from SOURCERPM filename
                            let stripped = srpm.strip_suffix(".src.rpm").unwrap_or(srpm);
                            let mut last_dash = None;
                            let mut second_last = None;
                            for (i, c) in stripped.char_indices() {
                                if c == '-' {
                                    second_last = last_dash;
                                    last_dash = Some(i);
                                }
                            }
                            second_last
                                .map(|i| stripped[..i].to_string())
                                .filter(|s| s != name)
                        };
                        results.push((name.to_string(), ver.to_string(), source_name));
                    }
                }
                if !results.is_empty() {
                    return Ok(results);
                }
                last_err = Some(anyhow::anyhow!(
                    "rpm query returned no packages for dbpath {}",
                    dbpath.display()
                ));
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                last_err = Some(anyhow::anyhow!(
                    "rpm exited with status {} for dbpath {}: {}",
                    out.status,
                    dbpath.display(),
                    stderr.trim()
                ));
            }
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "failed to invoke rpm for dbpath {}: {}",
                    dbpath.display(),
                    e
                ));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no rpm database found in rootfs")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Build a minimal RPM header blob with NAME, VERSION, RELEASE tags.
    fn make_rpm_header(name: &str, version: &str, release: &str, epoch: Option<u32>) -> Vec<u8> {
        let mut tag_count: u32 = 3; // NAME, VERSION, RELEASE
        if epoch.is_some() {
            tag_count += 1;
        }

        // Data section: strings laid out sequentially with NUL terminators, then optional epoch
        let mut data = Vec::new();
        let name_offset = data.len() as u32;
        data.extend_from_slice(name.as_bytes());
        data.push(0);
        let version_offset = data.len() as u32;
        data.extend_from_slice(version.as_bytes());
        data.push(0);
        let release_offset = data.len() as u32;
        data.extend_from_slice(release.as_bytes());
        data.push(0);
        // Align to 4-byte boundary for INT32 if needed
        let epoch_offset = if epoch.is_some() {
            while data.len() % 4 != 0 {
                data.push(0);
            }
            let off = data.len() as u32;
            let e = epoch.unwrap();
            data.extend_from_slice(&e.to_be_bytes());
            off
        } else {
            0
        };

        let hsize = data.len() as u32;
        let nindex = tag_count;

        let mut blob = Vec::new();
        // Header magic
        blob.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01]);
        // Reserved
        blob.extend_from_slice(&[0, 0, 0, 0]);
        // nindex
        blob.extend_from_slice(&nindex.to_be_bytes());
        // hsize
        blob.extend_from_slice(&hsize.to_be_bytes());
        // Tag entries (16 bytes each): tag, type, offset, count
        // NAME
        blob.extend_from_slice(&RPM_TAG_NAME.to_be_bytes());
        blob.extend_from_slice(&RPM_TYPE_STRING.to_be_bytes());
        blob.extend_from_slice(&name_offset.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        // VERSION
        blob.extend_from_slice(&RPM_TAG_VERSION.to_be_bytes());
        blob.extend_from_slice(&RPM_TYPE_STRING.to_be_bytes());
        blob.extend_from_slice(&version_offset.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        // RELEASE
        blob.extend_from_slice(&RPM_TAG_RELEASE.to_be_bytes());
        blob.extend_from_slice(&RPM_TYPE_STRING.to_be_bytes());
        blob.extend_from_slice(&release_offset.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        // EPOCH (optional)
        if epoch.is_some() {
            blob.extend_from_slice(&RPM_TAG_EPOCH.to_be_bytes());
            blob.extend_from_slice(&RPM_TYPE_INT32.to_be_bytes());
            blob.extend_from_slice(&epoch_offset.to_be_bytes());
            blob.extend_from_slice(&1u32.to_be_bytes());
        }
        // Data section
        blob.extend_from_slice(&data);

        blob
    }

    #[test]
    fn test_parse_rpm_header_blob_basic() {
        let blob = make_rpm_header("bash", "5.1.8", "6.el9", None);
        let result = parse_rpm_header_blob(&blob);
        assert_eq!(
            result,
            Some(("bash".to_string(), "5.1.8-6.el9".to_string(), None))
        );
    }

    #[test]
    fn test_parse_rpm_header_blob_with_epoch() {
        let blob = make_rpm_header("openssl", "3.0.7", "20.el9", Some(1));
        let result = parse_rpm_header_blob(&blob);
        assert_eq!(
            result,
            Some(("openssl".to_string(), "1:3.0.7-20.el9".to_string(), None))
        );
    }

    #[test]
    fn test_parse_rpm_header_blob_epoch_zero() {
        let blob = make_rpm_header("glibc", "2.34", "60.el9", Some(0));
        let result = parse_rpm_header_blob(&blob);
        assert_eq!(
            result,
            Some(("glibc".to_string(), "2.34-60.el9".to_string(), None))
        );
    }

    #[test]
    fn test_parse_rpm_header_blob_bad_magic() {
        let blob = vec![0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_rpm_header_blob(&blob), None);
    }

    #[test]
    fn test_parse_rpm_header_blob_too_short() {
        let blob = vec![0x8e, 0xad, 0xe8, 0x01];
        assert_eq!(parse_rpm_header_blob(&blob), None);
    }

    #[test]
    fn test_parse_rpm_sqlite_nonexistent() {
        let result = parse_rpm_sqlite(Path::new("/nonexistent/rpmdb.sqlite"));
        assert!(result.is_err());
    }
}
