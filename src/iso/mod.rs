//! ISO image scanning: RPM inventory detection, repodata parsing, and vulnerability reporting.

mod extract;
mod inventory;
mod repodata;
mod report;

pub use report::build_iso_report;

#[cfg(test)]
mod tests;
