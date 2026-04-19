pub mod evr;
mod xml_helpers;
pub mod oval;

// --- Public re-exports (same API as the original flat file) ---
pub use evr::{compare_evr, detect_rhel_major_version, fetch_redhat_oval, is_rpm_ecosystem};
pub use oval::{apply_redhat_oval_enrichment, check_redhat_cve, filter_findings_with_redhat_oval};
