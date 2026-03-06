//! Container scan orchestration.

use crate::container::detect::{detect_os_packages, scan_go_binaries_in_rootfs};
use crate::container::extract::{
    extract_tar, merge_layers_docker_save, merge_layers_oci_layout,
    try_detect_os_packages_from_layout,
};
use crate::container::PackageCoordinate;
use crate::redhat::apply_redhat_oval_enrichment;
use crate::report::{
    compute_summary, retag_findings, ConfidenceTier, EvidenceSource, InventoryStatus, Report,
    SbomInfo, ScanStatus, ScannerInfo, TargetInfo,
};
use crate::utils::parse_name_version_from_filename;
use crate::utils::{progress, progress_timing, run_syft_generate_sbom};
use super::source::detect_busybox_version_in_tree;
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, nvd_cpe_findings, nvd_keyword_findings,
    nvd_keyword_findings_name, osv_batch_query, redhat_inject_unfixed_cves,
};
use crate::ScanMode;
use std::collections::HashSet;
use std::path::Path;
use tempfile::tempdir;
#[cfg(feature = "yara")]
use walkdir::WalkDir;
#[cfg(feature = "yara")]
use yara::Compiler;

pub(super) const IMAGE_HEURISTIC_NOTE: &str =
    "Installed package inventory could not be fully determined for this image. Finding may be false positive.";

pub(super) fn report_state_for_inventory(
    packages_detected: usize,
    mode: &ScanMode,
    heuristic_used: bool,
) -> (ScanStatus, InventoryStatus, Option<String>) {
    if packages_detected > 0 {
        (ScanStatus::Complete, InventoryStatus::Complete, None)
    } else if heuristic_used {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Partial,
            Some("runtime_inventory_unavailable_used_heuristics".into()),
        )
    } else if matches!(mode, ScanMode::Deep) && deep_require_installed_inventory() {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Missing,
            Some("deep_mode_requires_installed_inventory".into()),
        )
    } else {
        (
            ScanStatus::PartialFailed,
            InventoryStatus::Missing,
            Some("installed_package_inventory_missing".into()),
        )
    }
}

pub(super) fn light_allow_heuristic_fallback() -> bool {
    std::env::var("SCANNER_LIGHT_ALLOW_HEURISTIC_FALLBACK")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

pub(super) fn deep_require_installed_inventory() -> bool {
    std::env::var("SCANNER_DEEP_REQUIRE_INSTALLED_INVENTORY")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

pub(super) fn heuristic_fallback_allowed(mode: &ScanMode) -> bool {
    match mode {
        ScanMode::Light => light_allow_heuristic_fallback(),
        ScanMode::Deep => !deep_require_installed_inventory(),
    }
}

pub(super) fn include_file_tree() -> bool {
    std::env::var("SCANNER_INCLUDE_FILE_TREE")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn file_tree_limit() -> usize {
    std::env::var("SCANNER_TREE_MAX_ENTRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

pub(super) fn collect_file_tree_if_enabled(root: &Path) -> Vec<crate::report::FileEntry> {
    if !include_file_tree() {
        progress(
            "files.collect.skip",
            "disabled by SCANNER_INCLUDE_FILE_TREE",
        );
        return Vec::new();
    }
    let started = std::time::Instant::now();
    let limit = file_tree_limit();
    progress("files.collect.start", &format!("limit={}", limit));
    let files = crate::utils::collect_file_tree(root, limit);
    progress_timing("files.collect", started);
    progress("files.collect.done", &format!("entries={}", files.len()));
    files
}

/// Build a container report (no printing)
pub fn build_container_report(
    tar_path: &str,
    mode: ScanMode,
    sbom: bool,
    nvd_api_key: Option<String>,
    yara_rules: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Report> {
    let tmp = tempdir().ok()?;
    #[cfg(not(feature = "yara"))]
    let _ = &yara_rules;

    crate::progress::init_pipeline("container");
    crate::progress::enter_stage("extract");
    let extract_started = std::time::Instant::now();
    progress("container.extract.start", tar_path);
    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        progress("container.extract.error", &format!("{}", e));
        return None;
    }
    progress_timing("container.extract", extract_started);
    progress("container.extract.done", tar_path);
    let manifest_path = tmp.path().join("manifest.json");
    let oci_index_path = tmp.path().join("index.json");
    let has_manifest = manifest_path.exists();
    let has_oci_index = oci_index_path.exists();
    let needs_full_rootfs = include_file_tree()
        || sbom
        || matches!(mode, ScanMode::Deep) && yara_rules.as_deref().is_some();

    crate::progress::enter_stage("inventory");
    let mut packages = Vec::new();
    if !needs_full_rootfs {
        let fast_started = std::time::Instant::now();
        progress("container.packages.detect.fast.start", "");
        match try_detect_os_packages_from_layout(tmp.path()) {
            Ok(pkgs) if !pkgs.is_empty() => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress(
                    "container.packages.detect.fast.done",
                    &format!("packages={}", pkgs.len()),
                );
                packages = pkgs;
            }
            Ok(_) => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress("container.packages.detect.fast.empty", "");
            }
            Err(e) => {
                progress_timing("container.packages.detect.fast", fast_started);
                progress("container.packages.detect.fast.error", &format!("{}", e));
            }
        }
    }

    // Always merge layers to get a rootfs — needed for Go binary scanning and app detection.
    let rootfs;
    {
        rootfs = if has_manifest {
            progress("container.layers.merge.start", "layout=docker-save");
            match merge_layers_docker_save(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else if has_oci_index {
            progress("container.layers.merge.start", "layout=oci");
            match merge_layers_oci_layout(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else {
            progress(
                "container.layers.merge.skip",
                &format!("layout=unknown; rootfs={}", tmp.path().display()),
            );
            tmp.path().to_path_buf()
        };

        if packages.is_empty() {
            progress(
                "container.packages.detect.start",
                rootfs.to_string_lossy().as_ref(),
            );
            let packages_started = std::time::Instant::now();
            packages = detect_os_packages(&rootfs);
            progress_timing("container.packages.detect", packages_started);
            progress(
                "container.packages.detect.done",
                &format!("packages={}", packages.len()),
            );
        }
    }

    // Detect application-level packages (npm, pip, gem, go, maven, cargo, etc.)
    let app_started = std::time::Instant::now();
    progress(
        "container.packages.app.start",
        rootfs.to_string_lossy().as_ref(),
    );
    let app_packages = crate::archive::detect_app_packages(&rootfs);
    progress_timing("container.packages.app", app_started);
    progress(
        "container.packages.app.done",
        &format!("app_packages={}", app_packages.len()),
    );
    packages.extend(app_packages);

    // Scan Go binaries in the rootfs for embedded buildinfo (Go modules + stdlib)
    let go_started = std::time::Instant::now();
    let go_packages = scan_go_binaries_in_rootfs(&rootfs);
    if !go_packages.is_empty() {
        progress(
            "container.go.binaries.done",
            &format!("go_packages={}", go_packages.len()),
        );
        packages.extend(go_packages);
    }
    progress_timing("container.go.binaries", go_started);

    // Connect to PG early so osv_batch_query can use cluster-mode chunk cache
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }

    // Create per-scan circuit breakers (one per API source, not static/shared)
    let osv_breaker = crate::vuln::CircuitBreaker::new("osv", 5);
    let nvd_breaker = crate::vuln::CircuitBreaker::new("nvd", 5);
    let epss_breaker = crate::vuln::CircuitBreaker::new("epss", 5);
    let kev_breaker = crate::vuln::CircuitBreaker::new("kev", 5);

    crate::progress::enter_stage("osv_query");
    progress(
        "container.osv.query.start",
        &format!("packages={}", packages.len()),
    );
    let osv_query_started = std::time::Instant::now();
    let osv_results = osv_batch_query(&packages, &mut pg, &osv_breaker);
    progress_timing("container.osv.query", osv_query_started);
    progress("container.osv.query.done", "ok");
    let mut findings_norm = map_osv_results_to_findings(&packages, &osv_results);
    let mut heuristic_used = false;

    // For RHEL-compatible distros (Rocky Linux, AlmaLinux, Oracle Linux, CentOS, Fedora),
    // supplement with a "Red Hat" ecosystem query to capture RHSA advisory coverage for
    // subpackages (e.g. openssl-libs, python3-libs, glibc-minimal-langpack) that are not
    // indexed under distro-specific OSV ecosystems.
    {
        let rhel_supp_pkgs: Vec<PackageCoordinate> = packages
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
            })
            .collect();
        if !rhel_supp_pkgs.is_empty() {
            progress(
                "container.osv.rhel_supplement.start",
                &format!("pkg_count={}", rhel_supp_pkgs.len()),
            );
            let rhel_supp_results = osv_batch_query(&rhel_supp_pkgs, &mut pg, &osv_breaker);
            let mut supp_findings =
                map_osv_results_to_findings(&rhel_supp_pkgs, &rhel_supp_results);
            let name_to_ecosystem: std::collections::HashMap<String, String> = packages
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
            let existing_keys: std::collections::HashSet<String> = findings_norm
                .iter()
                .map(|f| {
                    let pkg_name = f.package.as_ref().map_or("", |p| p.name.as_str());
                    format!("{}|{}", f.id, pkg_name)
                })
                .collect();
            let pre_merge_count = findings_norm.len();
            for f in supp_findings {
                let pkg_name = f.package.as_ref().map_or("", |p| p.name.as_str());
                let key = format!("{}|{}", f.id, pkg_name);
                if !existing_keys.contains(&key) {
                    findings_norm.push(f);
                }
            }
            progress(
                "container.osv.rhel_supplement.done",
                &format!("added={}", findings_norm.len() - pre_merge_count),
            );
        }
    }

    crate::progress::enter_stage("osv_enrich");
    progress(
        "container.enrich.osv.start",
        &format!("findings_pre_enrich={}", findings_norm.len()),
    );
    let osv_enrich_started = std::time::Instant::now();
    crate::vuln::osv_enrich_findings(&mut findings_norm, &mut pg, &osv_breaker);
    progress_timing("container.enrich.osv", osv_enrich_started);
    progress(
        "container.enrich.osv.done",
        &format!("findings={}", findings_norm.len()),
    );

    // NOTE: Debian tracker enrichment already handled in osv_enrich_findings — see scan_container.

    // Discover unfixed CVEs from the Red Hat per-package CVE list API (patch-only OVAL misses these).
    // Must run BEFORE enrich_findings_with_nvd so redhat_enrich_cve_findings processes injected findings.
    if packages
        .iter()
        .any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem))
    {
        redhat_inject_unfixed_cves(&mut findings_norm, &packages, &mut pg);
    }

    crate::progress::enter_stage("nvd_enrich");
    let nvd_enrich_enabled = std::env::var("SCANNER_NVD_ENRICH")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    if nvd_enrich_enabled {
        let unique: HashSet<String> = findings_norm
            .iter()
            .filter(|f| f.id.starts_with("CVE-"))
            .map(|f| f.id.clone())
            .collect();
        progress(
            "container.enrich.nvd.start",
            &format!("cves={}", unique.len()),
        );
        let nvd_enrich_started = std::time::Instant::now();
        enrich_findings_with_nvd(&mut findings_norm, nvd_api_key.as_deref(), &mut pg, &nvd_breaker);
        progress_timing("container.enrich.nvd", nvd_enrich_started);
        progress("container.enrich.nvd.done", "ok");
    } else {
        progress(
            "container.enrich.nvd.skip",
            "disabled by SCANNER_NVD_ENRICH",
        );
    }

    // Fallback heuristics when package DBs are absent (light mode by default).
    let allow_heuristic_fallback = heuristic_fallback_allowed(&mode);
    if packages.is_empty() && (has_manifest || has_oci_index) && allow_heuristic_fallback {
        if let Some((name, ver)) = parse_name_version_from_filename(tar_path) {
            let mut extra = nvd_cpe_findings(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
            if extra.is_empty() {
                extra = crate::vuln::nvd_findings_by_product_version(
                    &name,
                    &name,
                    &ver,
                    nvd_api_key.as_deref(),
                    Some(tar_path),
                    &nvd_breaker,
                );
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
            }
            if extra.is_empty() {
                extra = nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
            }
            let start = findings_norm.len();
            findings_norm.append(&mut extra);
            if findings_norm.len() > start {
                retag_findings(
                    &mut findings_norm[start..],
                    ConfidenceTier::HeuristicUnverified,
                    EvidenceSource::FilenameHeuristic,
                    Some(IMAGE_HEURISTIC_NOTE),
                );
                heuristic_used = true;
            }
        }
        if findings_norm.is_empty() {
            if let Some((name, ver)) = detect_busybox_version_in_tree(&rootfs) {
                progress("container.filename.heuristic", &format!("{} {}", name, ver));
                let mut extra =
                    nvd_cpe_findings(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
                if extra.is_empty() {
                    extra = crate::vuln::nvd_findings_by_product_version(
                        &name,
                        &name,
                        &ver,
                        nvd_api_key.as_deref(),
                        Some(tar_path),
                        &nvd_breaker,
                    );
                }
                if extra.is_empty() {
                    extra =
                        nvd_keyword_findings(&name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
                }
                if extra.is_empty() {
                    extra =
                        nvd_keyword_findings_name(&name, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
                }
                let start = findings_norm.len();
                findings_norm.append(&mut extra);
                if findings_norm.len() > start {
                    retag_findings(
                        &mut findings_norm[start..],
                        ConfidenceTier::HeuristicUnverified,
                        EvidenceSource::BinaryHeuristic,
                        Some(IMAGE_HEURISTIC_NOTE),
                    );
                    heuristic_used = true;
                }
            }
        }
    } else if packages.is_empty() && !allow_heuristic_fallback {
        progress(
            "container.heuristic.skip",
            "heuristic fallback disabled by deep inventory policy",
        );
    }

    crate::progress::enter_stage("redhat");
    let oval_redhat = oval_redhat
        .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            // Auto-download OVAL for RPM-based images when not explicitly provided
            let has_rpm = packages
                .iter()
                .any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem));
            if has_rpm {
                let cache = crate::vuln::resolve_enrich_cache_dir();
                crate::redhat::fetch_redhat_oval(&packages, cache.as_deref())
            } else {
                None
            }
        });
    if let Some(oval_path) = oval_redhat.as_deref() {
        progress("container.enrich.redhat.start", oval_path);
        let redhat_started = std::time::Instant::now();
        match apply_redhat_oval_enrichment(&mut findings_norm, &packages, oval_path) {
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

    // Post-enrichment deduplication pass: remove duplicate (CVE, package) pairs keeping
    // the finding with the most complete metadata.
    {
        let before_count = findings_norm.len();
        dedup_findings_by_cve_package(&mut findings_norm);
        progress(
            "container.dedup.done",
            &format!("before={} after={}", before_count, findings_norm.len()),
        );
    }

    // RHEL-version CPE gating: remove findings whose package version references a different
    // RHEL major version than the one detected in the scanned image.
    filter_findings_by_rhel_version(&mut findings_norm, &packages);

    // If this doesn't look like a container and we still found nothing, let caller
    // fall back to source/binary handlers.
    if !has_manifest && !has_oci_index && packages.is_empty() && findings_norm.is_empty() {
        return None;
    }

    // Optional YARA in deep mode (ignored if feature not enabled)
    if let ScanMode::Deep = mode {
        if packages.is_empty() && deep_require_installed_inventory() {
            progress(
                "container.yara.skip",
                "deep mode requires installed inventory; skipping heuristic binary scan",
            );
        } else {
            #[cfg(feature = "yara")]
            if let Some(rule_path) = yara_rules.as_deref() {
                if let Ok(mut compiler) = Compiler::new() {
                    let _ = compiler.add_rules_file(rule_path);
                    if let Ok(rules) = compiler.compile_rules() {
                        for entry in WalkDir::new(&rootfs).into_iter().filter_map(|e| e.ok()) {
                            if entry.file_type().is_file() {
                                if let Ok(scan) = rules.scan_file(entry.path(), 5) {
                                    for m in scan.matches {
                                        findings_norm.push(crate::report::Finding {
                                        id: format!("YARA:{}", m.identifier),
                                        source_ids: Vec::new(),
                                        package: None,
                                        confidence_tier: ConfidenceTier::HeuristicUnverified,
                                        evidence_source: EvidenceSource::BinaryHeuristic,
                                        accuracy_note: Some(
                                            "Derived from binary pattern matching; package inventory is not available."
                                                .into(),
                                        ),
                                        fixed: None,
                                        fixed_in: None,
                                        recommendation: None,
                                        severity: None,
                                        cvss: None,
                                        description: None,
                                        evidence: vec![crate::report::EvidenceItem {
                                            evidence_type: "yara".into(),
                                            path: Some(entry.path().display().to_string()),
                                            detail: Some(m.identifier.to_string()),
                                        }],
                                        references: Vec::new(),
                                        confidence: Some("MEDIUM".into()),
                                        epss_score: None,
                                        epss_percentile: None,
                                        in_kev: None,
                                    });
                                        heuristic_used = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let scanner = ScannerInfo {
        name: "scanrook",
        version: env!("CARGO_PKG_VERSION"),
    };
    let target = TargetInfo {
        target_type: "container".into(),
        source: tar_path.to_string(),
        id: None,
    };
    let mut sbom_info: Option<SbomInfo> = None;
    if sbom {
        progress("container.sbom.start", rootfs.to_string_lossy().as_ref());
        let sbom_started = std::time::Instant::now();
        let sbom_path = tmp.path().join("sbom.cdx.json");
        if run_syft_generate_sbom(
            rootfs.to_str().unwrap_or("."),
            sbom_path.to_str().unwrap_or("sbom.cdx.json"),
        )
        .is_ok()
        {
            sbom_info = Some(SbomInfo {
                format: "cyclonedx".into(),
                path: sbom_path.display().to_string(),
            });
        }
        progress_timing("container.sbom", sbom_started);
        progress("container.sbom.done", "ok");
    }

    let cache_dir = crate::vuln::resolve_enrich_cache_dir();
    crate::progress::enter_stage("epss");
    crate::vuln::epss_enrich_findings(&mut findings_norm, &mut pg, cache_dir.as_deref(), &epss_breaker);
    crate::progress::enter_stage("kev");
    crate::vuln::kev_enrich_findings(&mut findings_norm, &mut pg, cache_dir.as_deref(), &kev_breaker);

    crate::progress::enter_stage("report");
    let (scan_status, inventory_status, inventory_reason) =
        report_state_for_inventory(packages.len(), &mode, heuristic_used);
    let mut report = Report {
        scanner,
        target,
        scan_status,
        inventory_status,
        inventory_reason,
        sbom: sbom_info,
        findings: findings_norm,
        files: collect_file_tree_if_enabled(&rootfs),
            iso_profile: None,
        summary: Default::default(),
    };
    report.summary = compute_summary(&report.findings);

    // Collect warnings from tripped circuit breakers into report.summary.warnings
    let all_breakers: [&crate::vuln::CircuitBreaker; 4] =
        [&osv_breaker, &nvd_breaker, &epss_breaker, &kev_breaker];
    for b in &all_breakers {
        if b.is_open() {
            report.summary.warnings.push(format!(
                "{} unavailable — results may be incomplete (5 consecutive failures)",
                b.source_name()
            ));
        }
    }

    crate::progress::finish_pipeline();
    Some(report)
}

/// Returns a numeric score representing how complete a finding's metadata is.
/// Higher score = preferred when deduplicating.
fn metadata_score(f: &crate::report::Finding) -> u32 {
    let mut score = 0u32;
    if f.cvss.is_some() {
        score += 3;
    }
    if f.fixed_in.is_some() {
        score += 2;
    }
    // advisory_id represented via source_ids being non-empty
    if !f.source_ids.is_empty() {
        score += 1;
    }
    score
}

/// Deduplicates findings by (cve_id, package_name) composite key.
/// When duplicates exist, keeps the finding with the highest metadata score.
/// Findings with no package are deduplicated by cve_id alone.
/// Findings from different packages are always preserved.
pub(crate) fn dedup_findings_by_cve_package(findings: &mut Vec<crate::report::Finding>) {
    use std::collections::HashMap;

    // Map of (cve_id, package_name_or_empty) -> index of best candidate so far
    let mut best: HashMap<(String, String), usize> = HashMap::new();
    let mut keep = vec![true; findings.len()];

    for (i, f) in findings.iter().enumerate() {
        let pkg_name = f
            .package
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let key = (f.id.clone(), pkg_name);
        match best.get(&key).copied() {
            None => {
                best.insert(key, i);
            }
            Some(prev_idx) => {
                if metadata_score(f) > metadata_score(&findings[prev_idx]) {
                    keep[prev_idx] = false;
                    best.insert(key, i);
                } else {
                    keep[i] = false;
                }
            }
        }
    }

    let mut iter = keep.into_iter();
    findings.retain(|_| iter.next().unwrap_or(false));
}

/// Detects the RHEL major version from the installed package list by inspecting
/// `.elN` suffixes in package version strings. Returns the most common major version found,
/// or None if no RPM packages are present or no el-tag is detected.
fn detect_rhel_major_from_packages(packages: &[crate::container::PackageCoordinate]) -> Option<u32> {
    use std::collections::HashMap;
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for pkg in packages {
        let ver = &pkg.version;
        // find ".elN" or ".elN." patterns
        if let Some(pos) = ver.find(".el") {
            let rest = &ver[pos + 3..];
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num_str.parse::<u32>() {
                *counts.entry(n).or_insert(0) += 1;
            }
        }
    }
    counts.into_iter().max_by_key(|&(_, count)| count).map(|(v, _)| v)
}

/// Removes findings whose package version string references a different RHEL major version
/// than the one detected in the scanned container's packages.
/// Only applies when a single dominant RHEL major version can be detected.
pub(crate) fn filter_findings_by_rhel_version(
    findings: &mut Vec<crate::report::Finding>,
    packages: &[crate::container::PackageCoordinate],
) {
    let major = match detect_rhel_major_from_packages(packages) {
        Some(v) => v,
        None => return,
    };

    let before = findings.len();
    findings.retain(|f| {
        let pkg_ver = match f.package.as_ref() {
            Some(p) => &p.version,
            None => return true, // no package version info — keep
        };
        // Check if the finding's package version references a *wrong* RHEL major version
        // by looking for .elN patterns that do NOT match the detected major.
        let has_wrong_el = (1u32..=10u32)
            .filter(|&n| n != major)
            .any(|n| pkg_ver.contains(&format!(".el{}", n)));
        let has_correct_el = pkg_ver.contains(&format!(".el{}", major));

        if has_wrong_el && !has_correct_el {
            false // remove: this finding is for a different RHEL version
        } else {
            true
        }
    });

    let removed = before - findings.len();
    if removed > 0 || before > 0 {
        progress(
            "container.rhel_version_gating",
            &format!("rhel_major={} removed={}", major, removed),
        );
    }
}

#[cfg(test)]
mod dedup_tests {
    use super::*;
    use crate::report::{ConfidenceTier, CvssInfo, EvidenceSource, Finding, PackageInfo};

    fn make_finding(id: &str, pkg_name: &str, pkg_ver: &str, cvss: Option<f32>, fixed_in: Option<&str>) -> Finding {
        Finding {
            id: id.to_string(),
            source_ids: Vec::new(),
            package: if pkg_name.is_empty() {
                None
            } else {
                Some(PackageInfo {
                    name: pkg_name.to_string(),
                    ecosystem: "redhat".to_string(),
                    version: pkg_ver.to_string(),
                })
            },
            confidence_tier: ConfidenceTier::ConfirmedInstalled,
            evidence_source: EvidenceSource::InstalledDb,
            accuracy_note: None,
            fixed: None,
            fixed_in: fixed_in.map(|s| s.to_string()),
            recommendation: None,
            severity: None,
            cvss: cvss.map(|s| CvssInfo { base: s, vector: "CVSS:3.1/AV:N".to_string() }),
            description: None,
            evidence: Vec::new(),
            references: Vec::new(),
            confidence: None,
            epss_score: None,
            epss_percentile: None,
            in_kev: None,
        }
    }

    fn make_pkg(name: &str, ver: &str) -> crate::container::PackageCoordinate {
        crate::container::PackageCoordinate {
            ecosystem: "redhat".to_string(),
            name: name.to_string(),
            version: ver.to_string(),
            source_name: None,
        }
    }

    /// RHEL-01: duplicate (CVE, package) pairs are collapsed, keeping highest-score finding
    #[test]
    fn test_dedup_findings_by_cve_package() {
        let mut findings = vec![
            make_finding("CVE-2024-1234", "openssl", "3.0.7-24.el9", None, None),
            make_finding("CVE-2024-1234", "openssl", "3.0.7-24.el9", Some(7.5), None),
            make_finding("CVE-2024-1234", "glibc", "2.34-60.el9", None, None),
        ];
        dedup_findings_by_cve_package(&mut findings);
        assert_eq!(findings.len(), 2, "should collapse openssl dups but keep glibc");
        let openssl_f = findings.iter().find(|f| {
            f.package.as_ref().map(|p| p.name.as_str()) == Some("openssl")
        }).expect("openssl finding must remain");
        assert!(openssl_f.cvss.is_some(), "should keep the finding with CVSS score");
    }

    /// RHEL-03: different packages with the same CVE are both preserved
    #[test]
    fn test_dedup_preserves_different_packages() {
        let mut findings = vec![
            make_finding("CVE-2024-5678", "openssl-libs", "3.0.7-24.el9", None, None),
            make_finding("CVE-2024-5678", "openssl-devel", "3.0.7-24.el9", None, None),
        ];
        dedup_findings_by_cve_package(&mut findings);
        assert_eq!(findings.len(), 2, "different packages must both be preserved");
    }

    /// RHEL-03: unfixed CVE appearing from multiple sources deduplicates to one per package,
    /// preferring the entry with fixed_in set.
    #[test]
    fn test_dedup_unfixed_cves_once_per_package() {
        let mut findings = vec![
            make_finding("CVE-2024-9999", "curl", "7.76.1-26.el9", None, None),
            make_finding("CVE-2024-9999", "curl", "7.76.1-26.el9", None, Some("7.76.1-27.el9")),
            make_finding("CVE-2024-9999", "curl", "7.76.1-26.el9", None, None),
        ];
        dedup_findings_by_cve_package(&mut findings);
        assert_eq!(findings.len(), 1, "three dups for same CVE+package should become one");
        assert!(
            findings[0].fixed_in.is_some(),
            "the surviving finding should be the one with fixed_in set"
        );
    }

    /// RHEL-02: RHEL-version gating removes findings whose package version references a
    /// different RHEL major version than the detected image version.
    #[test]
    fn test_rhel_version_cpe_gating() {
        let mut findings = vec![
            // RHEL 7 finding — should be removed in a RHEL 9 context
            make_finding("CVE-2023-1111", "openssl", "1.0.2k-19.el7", None, None),
            // RHEL 9 finding — should be kept
            make_finding("CVE-2023-2222", "openssl", "3.0.7-24.el9", None, None),
        ];
        // Simulate a RHEL 9 container: packages have .el9 versions
        let packages = vec![
            make_pkg("glibc", "2.34-60.el9"),
            make_pkg("bash", "5.1.8-6.el9"),
        ];
        filter_findings_by_rhel_version(&mut findings, &packages);
        assert_eq!(findings.len(), 1, "RHEL 7 finding should be removed in RHEL 9 context");
        assert_eq!(
            findings[0].id, "CVE-2023-2222",
            "only the RHEL 9 finding should remain"
        );
    }
}

