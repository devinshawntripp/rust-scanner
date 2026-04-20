mod apk;
mod cli;
mod detect;
mod dpkg;
mod ecosystem;
mod enrich;
mod extract;
mod image;
mod rpm;
mod scan;
mod source;

pub use cli::scan_container;
pub use image::pull_and_save_image;
pub use rpm::{parse_rpm_bdb, parse_rpm_sqlite};
pub use scan::build_container_report;
pub use source::{build_source_report, scan_source_tarball};
pub(crate) use detect::parse_debian_copyright_license;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct PackageCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// For dpkg packages: the Debian source package name (from `Source:` field).
    /// OSV's Debian ecosystem indexes by source name, not binary name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// SPDX license identifier extracted from the package manager database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}
