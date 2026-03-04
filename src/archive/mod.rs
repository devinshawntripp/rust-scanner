mod detect;
mod dmg;
mod parsers;
mod scan;

pub use detect::detect_app_packages;
// Re-exported for external callers and test code; dmg.rs uses the module path directly.
#[allow(unused_imports)]
pub use detect::detect_macos_packages;
pub use dmg::build_dmg_report;
pub use scan::build_archive_report;

use crate::container::PackageCoordinate;
use std::collections::HashSet;

fn pkg_key(eco: &str, name: &str, version: &str) -> String {
    format!("{}:{}:{}", eco, name, version)
}

pub(crate) fn push_if_new(
    packages: &mut Vec<PackageCoordinate>,
    seen: &mut HashSet<String>,
    ecosystem: &str,
    name: &str,
    version: &str,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    let key = pkg_key(ecosystem, name, version);
    if seen.insert(key) {
        packages.push(PackageCoordinate {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source_name: None,
        });
    }
}

#[cfg(test)]
mod tests;
