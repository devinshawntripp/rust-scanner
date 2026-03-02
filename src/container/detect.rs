//! OS package detection and Go binary scanning in container rootfs.

use crate::container::apk::parse_apk_installed_with_ecosystem;
use crate::container::dpkg::parse_dpkg_status_with_ecosystem;
use crate::container::ecosystem::{detect_apk_ecosystem, detect_dpkg_ecosystem, detect_rpm_ecosystem};
use crate::container::rpm::detect_rpm_packages_native;
use crate::container::PackageCoordinate;
use crate::utils::progress;
use std::fs;
use std::path::Path;

pub(super) fn detect_os_packages(rootfs: &Path) -> Vec<PackageCoordinate> {
    let mut packages = Vec::new();

    // Debian/Ubuntu: /var/lib/dpkg/status
    let dpkg_status = rootfs.join("var/lib/dpkg/status");
    if dpkg_status.exists() {
        if let Ok(s) = fs::read_to_string(&dpkg_status) {
            let dpkg_eco = detect_dpkg_ecosystem(rootfs);
            parse_dpkg_status_with_ecosystem(&s, &dpkg_eco, &mut packages);
        }
    }

    // Alpine / Chainguard / Wolfi: /lib/apk/db/installed
    let apk_db = rootfs.join("lib/apk/db/installed");
    if apk_db.exists() {
        let apk_eco = detect_apk_ecosystem(rootfs);
        if let Ok(s) = fs::read_to_string(&apk_db) {
            parse_apk_installed_with_ecosystem(&s, &apk_eco, &mut packages);
        }
    }

    // RPM: try native parsing first (SQLite/BDB), then fall back to rpm CLI.
    // RHEL-like images may use /var/lib/rpm, newer distros may use /usr/lib/sysimage/rpm.
    let rpmdb_legacy = rootfs.join("var/lib/rpm");
    let rpmdb_modern = rootfs.join("usr/lib/sysimage/rpm");
    if rpmdb_legacy.exists() || rpmdb_modern.exists() {
        let rpm_ecosystem = detect_rpm_ecosystem(rootfs);
        progress(
            "container.rpm.ecosystem",
            &format!("detected={}", rpm_ecosystem),
        );
        match detect_rpm_packages_native(rootfs) {
            Ok(list) => {
                if list.is_empty() {
                    progress("container.rpm.detect.warn", "rpm CLI returned 0 packages");
                } else {
                    progress(
                        "container.rpm.detect.done",
                        &format!("ecosystem={} packages={}", rpm_ecosystem, list.len()),
                    );
                }
                for (name, version, source_name) in list {
                    packages.push(PackageCoordinate {
                        ecosystem: rpm_ecosystem.clone(),
                        name,
                        version,
                        source_name,
                    });
                }
            }
            Err(e) => {
                progress(
                    "container.rpm.detect.warn",
                    &format!("rpm CLI failed: {}", e),
                );
                eprintln!("Warning: RPM package detection failed: {}", e);
            }
        }
    }

    packages
}

/// Scan Go binaries in the rootfs for embedded buildinfo (modules + stdlib version).
/// This catches Go stdlib CVEs that OS package managers don't track.
pub(super) fn scan_go_binaries_in_rootfs(rootfs: &Path) -> Vec<PackageCoordinate> {
    use std::collections::HashSet;

    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Directories to scan for Go binaries. Use a walkdir approach for deeper paths.
    let search_roots = [
        "usr/local/bin",
        "usr/local/go/bin",
        "usr/bin",
        "usr/sbin",
        "bin",
        "sbin",
        "app",
        "opt",
        "home",
    ];

    let go_magic = b"\xff Go build info:";

    // Collect candidate binary paths (non-recursive for bin dirs, limited depth for others)
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    for dir in &search_roots {
        let full = rootfs.join(dir);
        if !full.is_dir() {
            continue;
        }
        // Walk up to 2 levels deep to find Go binaries
        fn collect_binaries(dir: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
            if depth > 2 { return; }
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_binaries(&path, depth + 1, out);
                } else if path.is_file() {
                    out.push(path);
                }
            }
        }
        collect_binaries(&full, 0, &mut candidates);
    }

    for path in &candidates {
        {
            if !path.is_file() {
                continue;
            }
            // Quick check: read first 4 bytes for ELF magic
            let mut header = [0u8; 4];
            if let Ok(mut f) = fs::File::open(&path) {
                use std::io::Read;
                if f.read_exact(&mut header).is_err() {
                    continue;
                }
            }
            // ELF: \x7fELF, Mach-O: \xfe\xed\xfa\xce / \xcf\xfa\xed\xfe
            let is_binary = header[..4] == [0x7f, b'E', b'L', b'F']
                || header[..4] == [0xfe, 0xed, 0xfa, 0xce]
                || header[..4] == [0xcf, 0xfa, 0xed, 0xfe];
            if !is_binary {
                continue;
            }

            // Read the binary (limit to 50MB to avoid OOM on huge binaries)
            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 50 * 1024 * 1024 {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Check for Go buildinfo magic
            if bytes.windows(go_magic.len()).all(|w| w != go_magic) {
                continue;
            }

            // Extract Go stdlib version
            if let Some(go_ver) = crate::binary::find_go_version(&bytes, bytes.len()) {
                let key = format!("stdlib|{}", go_ver);
                if seen.insert(key) {
                    packages.push(PackageCoordinate {
                        ecosystem: "Go".into(),
                        name: "stdlib".into(),
                        version: go_ver,
                        source_name: None,
                    });
                }
            }

            // Extract Go module dependencies
            let modules = crate::binary::parse_go_buildinfo(&bytes);
            for (mod_path, mod_ver) in modules {
                let key = format!("{}|{}", mod_path, mod_ver);
                if seen.insert(key) {
                    packages.push(PackageCoordinate {
                        ecosystem: "Go".into(),
                        name: mod_path,
                        version: mod_ver,
                        source_name: None,
                    });
                }
            }
        }
    }

    packages
}
