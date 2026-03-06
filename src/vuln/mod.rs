// --- Submodules ---
pub mod circuit;
mod cvss;
mod debian_legacy;
mod distro;
mod epss;
mod http;
mod kev;
mod nvd;
mod osv;
mod parallel;
pub mod pg;
mod redhat_enrich;
mod version;

// --- Public re-exports (used by container.rs, binary.rs, sbom.rs, archive.rs, iso.rs, main.rs) ---
#[allow(unused_imports)]
pub use circuit::CircuitBreaker;
pub use debian_legacy::debian_tracker_enrich_seed;
pub use distro::seed_distro_feeds;
pub use epss::{apply_epss_scores, epss_enrich_findings, fetch_epss_scores};
pub use kev::{apply_kev_set, fetch_kev_set, kev_enrich_findings};
pub use parallel::parallel_enrich_epss_kev;
pub use nvd::{
    enrich_findings_with_nvd, match_vuln, nvd_cpe_findings, nvd_findings_by_product_version,
    nvd_keyword_findings, nvd_keyword_findings_name,
};
pub use osv::{map_osv_results_to_findings, osv_batch_query, osv_enrich_findings};
pub use pg::{pg_connect, pg_init_schema, resolve_enrich_cache_dir};
pub use redhat_enrich::redhat_inject_unfixed_cves;

// --- Internal re-exports used by sibling submodules via `super::` ---
use distro::{distro_feed_enrich_findings, map_debian_advisory_to_cves};
use redhat_enrich::{redhat_enrich_cve_findings, redhat_enrich_findings};

// --- Internal re-exports for test access (only used by vuln/tests.rs via `use super::*`) ---
#[cfg(test)]
use distro::{
    build_ubuntu_candidate_index, DistroFixCandidate, pkg_cve_key, select_best_candidate,
};
#[cfg(test)]
use osv::drop_fixed_findings;
#[cfg(test)]
use redhat_enrich::{
    best_redhat_fixed_release, extract_el_tag, extract_redhat_errata_from_url,
    package_name_matches, parse_redhat_release_package,
    retain_relevant_redhat_references, RedHatFixedRelease,
};

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

/// Returns true when the scanner is running in cluster mode (SCANROOK_CLUSTER_MODE=1).
/// In cluster mode the local file cache is skipped and PostgreSQL is used as the
/// primary enrichment cache so that all workers in the cluster share results.
pub fn cluster_mode() -> bool {
    std::env::var("SCANROOK_CLUSTER_MODE")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests;
