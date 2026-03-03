mod apk;
mod detect;
mod dpkg;
mod ecosystem;
mod extract;
mod image;
mod rpm;
mod scan;

pub use image::pull_and_save_image;
pub use rpm::{parse_rpm_bdb, parse_rpm_sqlite};
pub use scan::{build_container_report, build_source_report, scan_container, scan_source_tarball};

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct PackageCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// For dpkg packages: the Debian source package name (from `Source:` field).
    /// OSV's Debian ecosystem indexes by source name, not binary name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
}
