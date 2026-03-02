use std::collections::{HashMap, HashSet};
use std::thread::sleep;
use std::time::Duration;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::container::PackageCoordinate;
use crate::redhat::{compare_evr, is_rpm_ecosystem};
use crate::report::{
    severity_from_score, ConfidenceTier, CvssInfo, EvidenceItem, EvidenceSource, Finding,
    PackageInfo, ReferenceInfo,
};
use crate::utils::{progress, progress_timing};
use rayon::prelude::*;
use reqwest::blocking::Client;
use serde_json::Value;
use std::path::PathBuf;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;

// --- Submodules ---
mod cvss;
mod debian_legacy;
mod epss;
mod http;
mod kev;
pub mod pg;
mod nvd;
mod redhat_enrich;
mod distro;
mod osv;
mod version;

pub use pg::{pg_connect, pg_init_schema, resolve_enrich_cache_dir};
pub use debian_legacy::{debian_tracker_enrich, debian_tracker_enrich_seed};
pub use epss::epss_enrich_findings;
pub use kev::kev_enrich_findings;
pub use osv::{map_osv_results_to_findings, osv_batch_query, osv_enrich_findings};
use osv::drop_fixed_findings;
use distro::{distro_feed_enrich_findings, map_debian_advisory_to_cves, DistroFixCandidate, pkg_cve_key, select_best_candidate, build_ubuntu_candidate_index};
pub use distro::seed_distro_feeds;
use redhat_enrich::{redhat_enrich_findings, redhat_enrich_cve_findings, RedHatFixedRelease, extract_el_tag, package_name_matches, extract_redhat_errata_from_url, retain_relevant_redhat_references, parse_redhat_release_package, best_redhat_fixed_release};
pub use redhat_enrich::redhat_inject_unfixed_cves;
pub use nvd::{enrich_findings_with_nvd, match_vuln, nvd_cpe_findings, nvd_findings_by_product_version, nvd_keyword_findings, nvd_keyword_findings_name};

use cvss::{normalize_redhat_severity, parse_cvss_score};
use http::{build_http_client, cached_http_json, enrich_http_client, nvd_get_json};
use pg::{
    compute_dynamic_ttl_days, parse_nvd_last_modified, parse_osv_last_modified,
    parse_redhat_cve_last_modified, parse_redhat_last_modified, pg_get_cve, pg_get_osv,
    pg_get_redhat, pg_get_redhat_cve, pg_get_rhel_cves, pg_put_cve, pg_put_osv, pg_put_redhat,
    pg_put_redhat_cve, pg_put_rhel_cve,
};
use version::{cmp_versions, cpe_parts, is_version_in_range};

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
