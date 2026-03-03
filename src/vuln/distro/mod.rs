mod debian_map;
mod feed;

pub(in crate::vuln) use debian_map::map_debian_advisory_to_cves;
pub(in crate::vuln) use feed::distro_feed_enrich_findings;
pub use feed::seed_distro_feeds;

#[cfg(test)]
pub(in crate::vuln) use feed::{
    build_ubuntu_candidate_index, DistroFixCandidate, pkg_cve_key, select_best_candidate,
};
