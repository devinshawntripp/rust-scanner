//! Shared enrichment pipeline for container scans.
//! Used by both build_container_report() (scan.rs) and scan_container() (cli.rs).

use crate::container::PackageCoordinate;
use crate::redhat::apply_redhat_oval_enrichment;
use crate::report::{retag_findings, ConfidenceTier, EvidenceSource, Finding};
use crate::utils::{parse_name_version_from_filename, progress, progress_timing};
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, nvd_cpe_findings, nvd_keyword_findings,
    nvd_keyword_findings_name, osv_batch_query, redhat_inject_unfixed_cves, CircuitBreaker,
};
use crate::ScanMode;
use std::collections::HashSet;
use std::path::Path;

use super::scan::{
    dedup_findings_by_cve_package, filter_findings_by_rhel_version, heuristic_fallback_allowed,
    IMAGE_HEURISTIC_NOTE,
};
use super::source::detect_busybox_version_in_tree;

/// Context for the shared enrichment pipeline.
pub(super) struct EnrichCtx<'a> {
    pub packages: &'a Vec<PackageCoordinate>,
    pub mode: &'a ScanMode,
    pub nvd_api_key: Option<&'a str>,
    pub tar_path: &'a str,
    pub rootfs: &'a Path,
    pub has_container_layout: bool,
    pub oval_redhat: Option<String>,
    pub pg: &'a mut Option<postgres::Client>,
    pub osv_breaker: &'a CircuitBreaker,
    pub nvd_breaker: &'a CircuitBreaker,
    pub epss_breaker: &'a CircuitBreaker,
    pub kev_breaker: &'a CircuitBreaker,
}

/// Run the full enrichment pipeline: OSV → RHEL supplement → OSV enrich → RedHat unfixed →
/// NVD → Heuristic fallback → OVAL → Dedup → RHEL filter → EPSS/KEV.
///
/// OVAL XML download runs in a background thread while sequential enrichment
/// (steps 1-6) proceeds, overlapping 2-10s of I/O with 5-30s of processing.
///
/// Returns `(findings, heuristic_used)`.
pub(super) fn run_enrichment_pipeline(ctx: &mut EnrichCtx) -> (Vec<Finding>, bool) {
    let mut heuristic_used = false;

    // Pre-fetch OVAL XML in background: resolve explicit path / env override first,
    // then spawn download thread if we need to fetch from Red Hat.
    let oval_disabled = std::env::var("SCANNER_OVAL_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "0" | "false" | "no" | "off"))
        .unwrap_or(false);
    let oval_explicit = if oval_disabled {
        None
    } else {
        ctx.oval_redhat
            .take()
            .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
            .filter(|v| !v.trim().is_empty())
    };
    let oval_fetch_handle = if oval_explicit.is_none() && !oval_disabled {
        let has_rpm = ctx
            .packages
            .iter()
            .any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem));
        if has_rpm {
            let pkgs_for_oval = ctx.packages.to_vec();
            let cache_for_oval = crate::vuln::resolve_enrich_cache_dir();
            progress("container.oval.prefetch.start", "downloading in background");
            Some(std::thread::spawn(move || {
                crate::redhat::fetch_redhat_oval(&pkgs_for_oval, cache_for_oval.as_deref())
            }))
        } else {
            None
        }
    } else {
        None
    };

    // 1. OSV batch query
    crate::progress::enter_stage("osv_query");
    progress(
        "container.osv.query.start",
        &format!("packages={}", ctx.packages.len()),
    );
    let osv_query_started = std::time::Instant::now();
    let osv_results = osv_batch_query(ctx.packages, ctx.pg, ctx.osv_breaker);
    progress_timing("container.osv.query", osv_query_started);
    progress("container.osv.query.done", "ok");
    let mut findings = map_osv_results_to_findings(ctx.packages, &osv_results);

    // 2. RHEL supplement for RHEL-compatible distros
    {
        let rhel_supp_pkgs: Vec<PackageCoordinate> = ctx
            .packages
            .iter()
            .filter(|p| {
                matches!(
                    p.ecosystem.as_str(),
                    "rocky" | "almalinux" | "oraclelinux" | "fedora" | "centos"
                )
            })
            .map(|p| PackageCoordinate {
                ecosystem: "redhat".into(),
                name: p.name.clone(),
                version: p.version.clone(),
                source_name: None,
                license: None,
            })
            .collect();
        if !rhel_supp_pkgs.is_empty() {
            progress(
                "container.osv.rhel_supplement.start",
                &format!("pkg_count={}", rhel_supp_pkgs.len()),
            );
            let rhel_supp_results = osv_batch_query(&rhel_supp_pkgs, ctx.pg, ctx.osv_breaker);
            let mut supp_findings =
                map_osv_results_to_findings(&rhel_supp_pkgs, &rhel_supp_results);
            let name_to_ecosystem: std::collections::HashMap<String, String> = ctx
                .packages
                .iter()
                .map(|p| (p.name.clone(), p.ecosystem.clone()))
                .collect();
            for f in supp_findings.iter_mut() {
                if let Some(pkg) = f.package.as_mut() {
                    if let Some(orig_eco) = name_to_ecosystem.get(&pkg.name) {
                        pkg.ecosystem = orig_eco.clone();
                    }
                }
            }
            let existing_keys: std::collections::HashSet<String> = findings
                .iter()
                .map(|f| {
                    let pkg_name = f.package.as_ref().map_or("", |p| p.name.as_str());
                    format!("{}|{}", f.id, pkg_name)
                })
                .collect();
            let pre_merge_count = findings.len();
            for f in supp_findings {
                let pkg_name = f.package.as_ref().map_or("", |p| p.name.as_str());
                let key = format!("{}|{}", f.id, pkg_name);
                if !existing_keys.contains(&key) {
                    findings.push(f);
                }
            }
            progress(
                "container.osv.rhel_supplement.done",
                &format!("added={}", findings.len() - pre_merge_count),
            );
        }
    }

    // 3. OSV enrichment (severity, CVSS, descriptions from OSV payloads)
    crate::progress::enter_stage("osv_enrich");
    progress(
        "container.enrich.osv.start",
        &format!("findings_pre_enrich={}", findings.len()),
    );
    let osv_enrich_started = std::time::Instant::now();
    crate::vuln::osv_enrich_findings(&mut findings, ctx.pg, ctx.osv_breaker);
    progress_timing("container.enrich.osv", osv_enrich_started);
    progress(
        "container.enrich.osv.done",
        &format!("findings={}", findings.len()),
    );

    // 4. RedHat unfixed CVE injection (before NVD so injected findings get enriched)
    if ctx
        .packages
        .iter()
        .any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem))
    {
        redhat_inject_unfixed_cves(&mut findings, ctx.packages, ctx.pg);
    }

    // 5. NVD enrichment
    crate::progress::enter_stage("nvd_enrich");
    let nvd_enrich_enabled = std::env::var("SCANNER_NVD_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if nvd_enrich_enabled {
        let unique: HashSet<String> = findings
            .iter()
            .filter(|f| f.id.starts_with("CVE-"))
            .map(|f| f.id.clone())
            .collect();
        progress(
            "container.enrich.nvd.start",
            &format!("cves={}", unique.len()),
        );
        let nvd_enrich_started = std::time::Instant::now();
        enrich_findings_with_nvd(
            &mut findings,
            ctx.nvd_api_key,
            ctx.pg,
            ctx.nvd_breaker,
        );
        progress_timing("container.enrich.nvd", nvd_enrich_started);
        progress("container.enrich.nvd.done", "ok");
    } else {
        progress(
            "container.enrich.nvd.skip",
            "disabled by SCANNER_NVD_ENRICH",
        );
    }

    // 6. Heuristic fallback when package DBs are absent
    let allow_heuristic_fallback = heuristic_fallback_allowed(ctx.mode);
    if ctx.packages.is_empty() && ctx.has_container_layout && allow_heuristic_fallback {
        if let Some((name, ver)) = parse_name_version_from_filename(ctx.tar_path) {
            let mut extra = nvd_cpe_findings(
                &name, &name, &ver, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
            );
            if extra.is_empty() {
                extra = crate::vuln::nvd_findings_by_product_version(
                    &name, &name, &ver, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                );
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings(
                    &name, &ver, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                );
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings_name(
                    &name, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                );
            }
            let start = findings.len();
            findings.append(&mut extra);
            if findings.len() > start {
                retag_findings(
                    &mut findings[start..],
                    ConfidenceTier::HeuristicUnverified,
                    EvidenceSource::FilenameHeuristic,
                    Some(IMAGE_HEURISTIC_NOTE),
                );
                heuristic_used = true;
            }
        }
        if findings.is_empty() {
            if let Some((name, ver)) = detect_busybox_version_in_tree(ctx.rootfs) {
                progress(
                    "container.filename.heuristic",
                    &format!("{} {}", name, ver),
                );
                let mut extra = nvd_cpe_findings(
                    &name, &name, &ver, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                );
                if extra.is_empty() {
                    extra = crate::vuln::nvd_findings_by_product_version(
                        &name, &name, &ver, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                    );
                }
                if extra.is_empty() {
                    extra = nvd_keyword_findings(
                        &name, &ver, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                    );
                }
                if extra.is_empty() {
                    extra = nvd_keyword_findings_name(
                        &name, ctx.nvd_api_key, Some(ctx.tar_path), ctx.nvd_breaker,
                    );
                }
                let start = findings.len();
                findings.append(&mut extra);
                if findings.len() > start {
                    retag_findings(
                        &mut findings[start..],
                        ConfidenceTier::HeuristicUnverified,
                        EvidenceSource::BinaryHeuristic,
                        Some(IMAGE_HEURISTIC_NOTE),
                    );
                    heuristic_used = true;
                }
            }
        }
    } else if ctx.packages.is_empty() && !allow_heuristic_fallback {
        progress(
            "container.heuristic.skip",
            "heuristic fallback disabled by deep inventory policy",
        );
    }

    // 7. Red Hat OVAL — use pre-fetched result from background thread
    crate::progress::enter_stage("redhat");
    let oval_redhat = if let Some(explicit) = oval_explicit {
        Some(explicit)
    } else if let Some(handle) = oval_fetch_handle {
        match handle.join() {
            Ok(result) => {
                progress("container.oval.prefetch.done", "joined background fetch");
                result
            }
            Err(_) => {
                progress("container.oval.prefetch.error", "background thread panicked");
                None
            }
        }
    } else {
        None
    };
    if let Some(oval_path) = oval_redhat.as_deref() {
        progress("container.enrich.redhat.start", oval_path);
        let redhat_started = std::time::Instant::now();
        match apply_redhat_oval_enrichment(&mut findings, ctx.packages, oval_path, ctx.pg.as_mut())
        {
            Ok((generated, stats)) => {
                progress_timing("container.enrich.redhat", redhat_started);
                progress(
                    "container.enrich.redhat.done",
                    &format!(
                        "generated={} defs={}/{} cves={}/{} findings={}->{} filtered={}",
                        generated,
                        stats.definitions_evaluable,
                        stats.definitions_total,
                        stats.vulnerable_cves,
                        stats.covered_cves,
                        stats.findings_before,
                        stats.findings_after,
                        stats.findings_filtered
                    ),
                );
            }
            Err(e) => {
                progress_timing("container.enrich.redhat", redhat_started);
                progress("container.enrich.redhat.error", &format!("{}", e));
            }
        }
    }

    // 8. Post-enrichment deduplication
    {
        let before_count = findings.len();
        dedup_findings_by_cve_package(&mut findings);
        progress(
            "container.dedup.done",
            &format!("before={} after={}", before_count, findings.len()),
        );
    }

    // 9. RHEL-version CPE gating
    filter_findings_by_rhel_version(&mut findings, ctx.packages);

    // 10. Parallel EPSS + KEV enrichment
    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::progress::enter_stage("epss_kev");
    crate::vuln::parallel_enrich_epss_kev(
        &mut findings,
        cache_dir.as_deref(),
        ctx.epss_breaker,
        ctx.kev_breaker,
    );

    (findings, heuristic_used)
}
