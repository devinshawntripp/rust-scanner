mod cve_enrich;
mod errata_enrich;
mod helpers;
mod inject;

// --- Public re-exports (same API as the original flat file) ---
pub use inject::redhat_inject_unfixed_cves;

// --- Internal re-exports for sibling submodules via `super::` ---
pub(in crate::vuln) use cve_enrich::redhat_enrich_cve_findings;
pub(in crate::vuln) use errata_enrich::redhat_enrich_findings;

// --- Internal re-exports for test access (used by vuln/tests.rs via `use super::*`) ---
#[cfg(test)]
pub(in crate::vuln) use helpers::{
    best_redhat_fixed_release, extract_el_tag, extract_redhat_errata_from_url,
    package_name_matches, parse_redhat_release_package, retain_relevant_redhat_references,
    RedHatFixedRelease,
};
