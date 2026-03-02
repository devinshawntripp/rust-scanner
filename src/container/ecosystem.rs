//! OS/ecosystem detection from /etc/os-release.

use std::fs;
use std::path::Path;

/// Distinguish Ubuntu from Debian by reading /etc/os-release.
/// OSV has separate "Ubuntu" and "Debian" ecosystems with different advisory data.
pub(super) fn detect_dpkg_ecosystem(rootfs: &Path) -> String {
    let os_release = rootfs.join("etc/os-release");
    let content = match fs::read_to_string(os_release) {
        Ok(s) => s,
        Err(_) => return "deb".to_string(),
    };
    let mut id = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = trim_os_release_value(v).to_lowercase();
        }
    }
    if id == "ubuntu" {
        "ubuntu-deb".to_string()
    } else {
        "deb".to_string()
    }
}

pub(super) fn detect_rpm_ecosystem(rootfs: &Path) -> String {
    let os_release = rootfs.join("etc/os-release");
    let content = match fs::read_to_string(os_release) {
        Ok(s) => s,
        Err(_) => return "redhat".to_string(),
    };

    let mut id = String::new();
    let mut like = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = trim_os_release_value(v).to_lowercase();
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            like = trim_os_release_value(v).to_lowercase();
        }
    }
    let hay = format!("{} {}", id, like);

    if hay.contains("rocky") {
        return "rocky".to_string();
    }
    if hay.contains("alma") {
        return "almalinux".to_string();
    }
    if id == "amzn" || hay.contains("amazon") {
        return "amazonlinux".to_string();
    }
    if hay.contains("opensuse") {
        return "opensuse".to_string();
    }
    if hay.contains("sles") || hay.contains("suse") {
        return "suse".to_string();
    }
    if id == "ol" || hay.contains("oracle") {
        return "oraclelinux".to_string();
    }
    if id == "fedora" {
        return "fedora".to_string();
    }
    if id == "centos" {
        return "centos".to_string();
    }
    if id == "chainguard" || hay.contains("chainguard") {
        return "chainguard".to_string();
    }
    if id == "wolfi" || hay.contains("wolfi") {
        return "wolfi".to_string();
    }

    // Default all RHEL-like RPM families to Red Hat for OSV queries.
    "redhat".to_string()
}

pub(super) fn detect_apk_ecosystem(rootfs: &Path) -> String {
    let os_release = rootfs.join("etc/os-release");
    let content = match fs::read_to_string(os_release) {
        Ok(s) => s,
        Err(_) => return "apk".to_string(),
    };
    let mut id = String::new();
    let mut like = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = trim_os_release_value(v).to_lowercase();
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            like = trim_os_release_value(v).to_lowercase();
        }
    }
    let hay = format!("{} {}", id, like);
    if id == "chainguard" || hay.contains("chainguard") {
        return "chainguard".to_string();
    }
    if id == "wolfi" || hay.contains("wolfi") {
        return "wolfi".to_string();
    }
    "apk".to_string()
}

pub(super) fn trim_os_release_value(v: &str) -> String {
    v.trim().trim_matches('"').to_string()
}
