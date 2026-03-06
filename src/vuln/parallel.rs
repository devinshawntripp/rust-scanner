use std::collections::HashSet;

use crate::report::Finding;
use crate::utils::progress;

use super::CircuitBreaker;

/// Run EPSS and KEV enrichment in parallel using scoped threads.
///
/// Each enrichment opens its own PG connection so they can run concurrently.
/// The data-fetch phase runs in parallel; the apply phase runs sequentially
/// (writes to different fields so ordering doesn't matter, but avoids needing
/// concurrent mutable access to the findings vec).
pub fn parallel_enrich_epss_kev(
    findings: &mut [Finding],
    cache_dir: Option<&std::path::Path>,
    epss_breaker: &CircuitBreaker,
    kev_breaker: &CircuitBreaker,
) {
    let cve_ids: Vec<String> = findings
        .iter()
        .filter(|f| f.id.starts_with("CVE-"))
        .map(|f| f.id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if cve_ids.is_empty() {
        return;
    }

    progress(
        "enrich.parallel.start",
        &format!("cves={} (epss+kev)", cve_ids.len()),
    );
    let started = std::time::Instant::now();

    // Fetch EPSS scores and KEV catalog concurrently
    let (epss_scores, kev_set) = std::thread::scope(|s| {
        let epss_handle = s.spawn(|| {
            super::epss::fetch_epss_scores(&cve_ids, cache_dir, epss_breaker)
        });
        // Run KEV fetch in the current thread (no need for a third thread)
        let kev_set = super::kev::fetch_kev_set(cache_dir, kev_breaker);
        let epss_scores = epss_handle.join().unwrap_or_default();
        (epss_scores, kev_set)
    });

    // Apply results sequentially
    let epss_enriched = super::epss::apply_epss_scores(findings, &epss_scores);
    let kev_enriched = super::kev::apply_kev_set(findings, &kev_set);

    let elapsed = started.elapsed();
    progress(
        "enrich.parallel.done",
        &format!(
            "epss={}/{} kev={}/{} elapsed={}ms",
            epss_enriched,
            findings.len(),
            kev_enriched,
            findings.len(),
            elapsed.as_millis()
        ),
    );
}
