#[cfg(test)]
use crate::container::PackageCoordinate;
use crate::utils::progress;

use super::http::enrich_http_client;

// --- Functions used only by tests (test-only but compiler-visible) ---

/// Detect the Debian release codename from a set of packages.
/// Returns "bookworm" for Debian 12, "bullseye" for 11, "trixie" for 13, etc.
#[cfg(test)]
pub(super) fn detect_debian_release(packages: &[PackageCoordinate]) -> Option<&'static str> {
    for pkg in packages {
        if pkg.ecosystem != "deb" && pkg.ecosystem != "ubuntu-deb" {
            continue;
        }
        let v = &pkg.version;
        if v.contains("deb13") || v.contains("trixie") {
            return Some("trixie");
        }
        if v.contains("deb12") || v.contains("bookworm") {
            return Some("bookworm");
        }
        if v.contains("deb11") || v.contains("bullseye") {
            return Some("bullseye");
        }
        if v.contains("deb10") || v.contains("buster") {
            return Some("buster");
        }
    }
    Some("bookworm")
}

#[cfg(test)]
pub(super) fn urgency_to_severity(urgency: &str) -> &'static str {
    match urgency {
        "high" => "HIGH",
        "medium" => "MEDIUM",
        "low" | "low*" | "low**" => "LOW",
        "end-of-life" => "MEDIUM",
        _ => "MEDIUM",
    }
}

/// Pre-download the Debian Security Tracker JSON to the local cache for seeding.
pub fn debian_tracker_enrich_seed(cache_dir: &std::path::Path) -> anyhow::Result<()> {
    fetch_debian_tracker_json(Some(cache_dir))?;
    Ok(())
}

fn fetch_debian_tracker_json(
    cache_dir: Option<&std::path::Path>,
) -> anyhow::Result<serde_json::Value> {
    let _cache_key_str = "debian_tracker_json_v1";

    // Check file cache
    if let Some(dir) = cache_dir {
        let cached = dir.join("debian_tracker.json");
        if cached.exists() {
            if let Ok(meta) = std::fs::metadata(&cached) {
                if let Ok(modified) = meta.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();
                    if age < std::time::Duration::from_secs(24 * 3600) {
                        progress("debian.tracker.cache_hit", &cached.to_string_lossy());
                        if let Ok(data) = std::fs::read(&cached) {
                            if let Ok(v) = serde_json::from_slice(&data) {
                                return Ok(v);
                            }
                        }
                    }
                }
            }
        }
    }

    // Fetch from Debian Security Tracker
    progress(
        "debian.tracker.fetch",
        "https://security-tracker.debian.org/tracker/data/json",
    );
    let client = enrich_http_client();
    let resp = client
        .get("https://security-tracker.debian.org/tracker/data/json")
        .timeout(std::time::Duration::from_secs(120))
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Debian tracker HTTP {}", resp.status()));
    }

    let bytes = resp.bytes()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;

    // Cache
    if let Some(dir) = cache_dir {
        let _ = std::fs::create_dir_all(dir);
        let cached = dir.join("debian_tracker.json");
        let _ = std::fs::write(&cached, &bytes);
        progress("debian.tracker.cached", &cached.to_string_lossy());
    }

    Ok(value)
}
