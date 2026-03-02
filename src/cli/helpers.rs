use crate::utils::progress;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ScanMode;
/// Default YARA rules bundled with the scanner binary.
#[cfg(feature = "yara")]
use crate::DEFAULT_YARA_RULES;

/// Resolve YARA rules path: use user-specified file, or write bundled defaults for deep mode.
pub fn resolve_yara_rules(user_yara: &Option<String>, mode: &ScanMode) -> Option<String> {
    // If user specified a YARA rules file, use that
    if user_yara.is_some() {
        return user_yara.clone();
    }
    // In deep mode, write bundled defaults to a temp file
    #[cfg(feature = "yara")]
    if matches!(mode, ScanMode::Deep) {
        match write_default_yara_to_temp() {
            Ok(path) => {
                progress("yara.defaults.loaded", &path);
                return Some(path);
            }
            Err(e) => {
                progress("yara.defaults.error", &format!("{}", e));
            }
        }
    }
    #[cfg(not(feature = "yara"))]
    let _ = mode;
    None
}

#[cfg(feature = "yara")]
fn write_default_yara_to_temp() -> anyhow::Result<String> {
    // Write to cache dir so it persists across scans in the same session
    let cache_dir = resolve_cache_dir();
    let yara_path = cache_dir.join("default_rules.yar");
    std::fs::create_dir_all(&cache_dir)?;
    std::fs::write(&yara_path, DEFAULT_YARA_RULES)?;
    Ok(yara_path.to_string_lossy().to_string())
}

pub fn resolve_cache_dir() -> PathBuf {
    if let Ok(v) = std::env::var("SCANNER_CACHE") {
        return PathBuf::from(v);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".scanrook").join("cache");
    }
    PathBuf::from(".scanrook-cache")
}

pub fn clear_scanrook_cache() -> anyhow::Result<()> {
    let dir = resolve_cache_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    set_dir_permissions_0700(&dir);
    Ok(())
}

/// Set directory permissions to 0o700 (owner-only) on unix systems.
#[cfg(unix)]
pub fn set_dir_permissions_0700(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
pub fn set_dir_permissions_0700(_dir: &std::path::Path) {}

pub fn clear_trivy_cache() {
    let _ = Command::new("trivy").arg("clean").arg("--all").status();
    if let Some(home) = std::env::var_os("HOME") {
        let _ = std::fs::remove_dir_all(PathBuf::from(&home).join(".cache").join("trivy"));
        let _ = std::fs::remove_dir_all(
            PathBuf::from(&home)
                .join("Library")
                .join("Caches")
                .join("trivy"),
        );
    }
}

pub fn clear_grype_cache() {
    if let Some(home) = std::env::var_os("HOME") {
        let _ = std::fs::remove_dir_all(PathBuf::from(&home).join(".cache").join("grype"));
        let _ = std::fs::remove_dir_all(
            PathBuf::from(&home)
                .join("Library")
                .join("Caches")
                .join("grype"),
        );
    }
}

#[derive(Clone, Copy)]
pub struct DataSourceDef {
    pub source: &'static str,
    pub provider: &'static str,
    pub ecosystems: &'static str,
    pub kind: &'static str,
    pub status: &'static str,
    pub notes: &'static str,
}

pub const SCANROOK_DATA_SOURCES: &[DataSourceDef] = &[
    DataSourceDef {
        source: "Open Source Vulnerabilities API",
        provider: "osv",
        ecosystems: ".NET, Go, Java, JavaScript, Python, Ruby, Rust, DPKG, APK, RPM",
        kind: "advisories+vuln details",
        status: "active",
        notes: "primary cross-ecosystem advisory feed",
    },
    DataSourceDef {
        source: "National Vulnerability Database",
        provider: "nvd",
        ecosystems: "CVE-backed cross-ecosystem",
        kind: "disclosures+cvss",
        status: "active",
        notes: "CVE enrichment, CVSS/vector, references",
    },
    DataSourceDef {
        source: "Red Hat Security Data API (Hydra)",
        provider: "redhat",
        ecosystems: "RPM (RHEL family)",
        kind: "RHSA/CVE/CSAF",
        status: "active",
        notes: "applicability + fixed build context",
    },
    DataSourceDef {
        source: "Red Hat OVAL XML (user supplied)",
        provider: "redhat_oval",
        ecosystems: "RPM (RHEL family)",
        kind: "fixed-state verification",
        status: "active",
        notes: "full OVAL applicability when file is provided via --oval-redhat",
    },
    DataSourceDef {
        source: "Ubuntu CVE Tracker",
        provider: "ubuntu",
        ecosystems: "DPKG",
        kind: "distribution advisories",
        status: "active",
        notes: "direct notices feed enrichment with package-level fixed version mapping",
    },
    DataSourceDef {
        source: "Debian Security Tracker",
        provider: "debian",
        ecosystems: "DPKG",
        kind: "distribution advisories",
        status: "active",
        notes: "direct tracker feed enrichment with package-level fixed version mapping",
    },
    DataSourceDef {
        source: "Alpine SecDB",
        provider: "alpine",
        ecosystems: "APK",
        kind: "distribution advisories",
        status: "active",
        notes: "direct SecDB enrichment with package-level secfix mapping",
    },
    DataSourceDef {
        source: "AlmaLinux OSV Database",
        provider: "alma",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Amazon Linux Security Center",
        provider: "amazon",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "SUSE Security OVAL",
        provider: "sles",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Oracle Linux Security",
        provider: "oracle",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Chainguard Security",
        provider: "chainguard",
        ecosystems: "APK",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Wolfi Security",
        provider: "wolfi",
        ecosystems: "APK",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "EPSS",
        provider: "epss",
        ecosystems: "cross-ecosystem",
        kind: "auxiliary prioritization",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "CISA KEV",
        provider: "kev",
        ecosystems: "cross-ecosystem",
        kind: "auxiliary exploit status",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
];

#[derive(Default)]
pub struct LocalCacheStats {
    pub entries: usize,
    pub bytes: u64,
    pub latest: Option<SystemTime>,
}

pub fn collect_local_cache_stats(dir: &PathBuf) -> LocalCacheStats {
    let mut stats = LocalCacheStats::default();
    if !dir.exists() {
        return stats;
    }
    for e in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !e.file_type().is_file() {
            continue;
        }
        stats.entries += 1;
        if let Ok(m) = e.metadata() {
            stats.bytes += m.len();
            if let Ok(mt) = m.modified() {
                if stats.latest.map(|x| mt > x).unwrap_or(true) {
                    stats.latest = Some(mt);
                }
            }
        }
    }
    stats
}

pub fn fmt_epoch(ts: Option<SystemTime>) -> String {
    ts.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|| "-".to_string())
}

pub fn env_bool_default(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

pub fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Strip references array from each finding when refs flag not set
pub fn strip_references_in_findings(v: &mut Value) {
    if let Some(arr) = v.get_mut("findings").and_then(|f| f.as_array_mut()) {
        for f in arr.iter_mut() {
            f.as_object_mut().map(|o| o.remove("references"));
        }
    }
}

/// Print a hint if the vulnerability cache is empty (e.g. fresh install without `make install`).
pub fn nudge_seed_if_empty() {
    let cache_dir = resolve_cache_dir();
    let sentinel = cache_dir.join(".seed_done");
    if sentinel.exists() {
        return;
    }
    let is_empty = match std::fs::read_dir(&cache_dir) {
        Ok(entries) => entries.count() <= 1, // allow the dir itself
        Err(_) => true,
    };
    if is_empty {
        progress(
            "cache.empty",
            "run `scanrook db seed --all` to pre-warm the vulnerability cache for faster scans",
        );
    }
}
