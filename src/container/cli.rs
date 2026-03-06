//! CLI-facing container scan function (prints output directly).

use crate::container::detect::detect_os_packages;
use crate::container::extract::{
    extract_tar, merge_layers_docker_save, merge_layers_oci_layout,
    try_detect_os_packages_from_layout,
};
use crate::container::PackageCoordinate;
use crate::redhat::apply_redhat_oval_enrichment;
use crate::report::{
    compute_summary, retag_findings, ConfidenceTier, EvidenceSource, Report,
    SbomInfo, ScannerInfo, TargetInfo,
};
use crate::utils::parse_name_version_from_filename;
use crate::utils::{progress, progress_timing, run_syft_generate_sbom, write_output_if_needed};
use super::source::detect_busybox_version_in_tree;
use crate::vuln::{
    enrich_findings_with_nvd, map_osv_results_to_findings, nvd_cpe_findings, nvd_keyword_findings,
    nvd_keyword_findings_name, osv_batch_query, redhat_inject_unfixed_cves,
};
use crate::{OutputFormat, ScanMode};
use std::collections::HashSet;
use tempfile::tempdir;
#[cfg(feature = "yara")]
use walkdir::WalkDir;
#[cfg(feature = "yara")]
use yara::Compiler;

use super::scan::{
    collect_file_tree_if_enabled, deep_require_installed_inventory, heuristic_fallback_allowed,
    include_file_tree, report_state_for_inventory, IMAGE_HEURISTIC_NOTE,
};

pub fn scan_container(
    tar_path: &str,
    mode: ScanMode,
    format: OutputFormat,
    _cache_dir: Option<String>,
    yara_rules: Option<String>,
    out: Option<String>,
    sbom: bool,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) {
    let tmp = match tempdir() {
        Ok(td) => td,
        Err(e) => {
            eprintln!("Failed to create tempdir: {}", e);
            return;
        }
    };
    #[cfg(not(feature = "yara"))]
    let _ = &yara_rules;

    let extract_started = std::time::Instant::now();
    progress("container.extract.start", tar_path);

    if let Err(e) = extract_tar(tar_path, tmp.path()) {
        eprintln!("Failed to extract {}: {}", tar_path, e);
        progress("container.extract.error", &format!("{}", e));
        return;
    }
    progress_timing("container.extract", extract_started);
    progress("container.extract.done", tar_path);

    let needs_full_rootfs = include_file_tree()
        || sbom
        || matches!(mode, ScanMode::Deep) && yara_rules.as_deref().is_some();

    let manifest_path = tmp.path().join("manifest.json");
    let oci_index_path = tmp.path().join("index.json");
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

    let rootfs;
    {
        rootfs = if manifest_path.exists() {
            progress("container.layers.merge.start", "layout=docker-save");
            match merge_layers_docker_save(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    eprintln!("Failed to merge docker-save layers: {}", e);
                    progress("container.layers.merge.error", &format!("{}", e));
                    tmp.path().to_path_buf()
                }
            }
        } else if oci_index_path.exists() {
            progress("container.layers.merge.start", "layout=oci");
            match merge_layers_oci_layout(tmp.path()) {
                Ok(p) => {
                    progress("container.layers.merge.done", p.to_string_lossy().as_ref());
                    p
                }
                Err(e) => {
                    eprintln!("Failed to merge OCI layers: {}", e);
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

    // Connect to PG early so osv_batch_query can use cluster-mode chunk cache
    let mut pg = if crate::vuln::cluster_mode() {
        crate::vuln::pg_connect()
    } else {
        None
    };
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }

    // Create per-scan circuit breakers (one per API source, not static/shared)
    let osv_breaker = crate::vuln::CircuitBreaker::new("osv", 5);
    let nvd_breaker = crate::vuln::CircuitBreaker::new("nvd", 5);
    let epss_breaker = crate::vuln::CircuitBreaker::new("epss", 5);
    let kev_breaker = crate::vuln::CircuitBreaker::new("kev", 5);

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

    // RHEL supplement
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

    // Enrichment
    progress(
        "container.enrich.osv.start",
        &format!("findings_pre_enrich={}", findings_norm.len()),
    );
    let osv_enrich_started = std::time::Instant::now();
    let mut pg = crate::vuln::pg_connect();
    if let Some(c) = pg.as_mut() {
        crate::vuln::pg_init_schema(c);
    }
    crate::vuln::osv_enrich_findings(&mut findings_norm, &mut pg, &osv_breaker);
    progress_timing("container.enrich.osv", osv_enrich_started);
    progress(
        "container.enrich.osv.done",
        &format!("findings={}", findings_norm.len()),
    );

    if packages
        .iter()
        .any(|p| crate::redhat::is_rpm_ecosystem(&p.ecosystem))
    {
        redhat_inject_unfixed_cves(&mut findings_norm, &packages, &mut pg);
    }

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

    // Heuristic fallback
    let allow_heuristic_fallback = heuristic_fallback_allowed(&mode);
    if packages.is_empty()
        && (manifest_path.exists() || oci_index_path.exists())
        && allow_heuristic_fallback
    {
        if let Some((name, ver)) = parse_name_version_from_filename(tar_path) {
            let mut extra = nvd_cpe_findings(&name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker);
            if extra.is_empty() {
                extra = crate::vuln::nvd_findings_by_product_version(
                    &name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker,
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
                        &name, &name, &ver, nvd_api_key.as_deref(), Some(tar_path), &nvd_breaker,
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

    // OVAL
    let oval_redhat = oval_redhat
        .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
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
                eprintln!("Failed Red Hat OVAL evaluation: {}", e);
                progress_timing("container.enrich.redhat", redhat_started);
                progress("container.enrich.redhat.error", &format!("{}", e));
            }
        }
    }

    // YARA
    #[cfg(feature = "yara")]
    let mut yara_hits: Vec<String> = Vec::new();
    #[cfg(not(feature = "yara"))]
    let yara_hits: Vec<String> = Vec::new();
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
                    if let Err(e) = compiler.add_rules_file(rule_path) {
                        eprintln!("Failed to add YARA rules: {}", e);
                    } else if let Ok(rules) = compiler.compile_rules() {
                        for entry in WalkDir::new(&rootfs).into_iter().filter_map(|e| e.ok()) {
                            if entry.file_type().is_file() {
                                if let Ok(scan) = rules.scan_file(entry.path(), 5) {
                                    for m in scan.matches {
                                        yara_hits.push(format!(
                                            "{}: {}",
                                            entry.path().display(),
                                            m.identifier
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Output
    match format {
        OutputFormat::Text => {
            println!("Merged RootFS: {}", rootfs.display());
            println!("Detected packages: {}", packages.len());
            for p in &packages {
                println!("- {}:{}@{}", p.ecosystem, p.name, p.version);
            }
            println!("Findings: {}", findings_norm.len());
            if !yara_hits.is_empty() {
                println!("YARA hits: {}", yara_hits.len());
            }
        }
        OutputFormat::Json => {
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
                if let Err(e) = run_syft_generate_sbom(
                    rootfs.to_str().unwrap_or("."),
                    sbom_path.to_str().unwrap_or("sbom.cdx.json"),
                ) {
                    eprintln!("Syft SBOM generation failed: {}", e);
                    progress("container.sbom.error", &format!("{}", e));
                } else {
                    sbom_info = Some(SbomInfo {
                        format: "cyclonedx".into(),
                        path: sbom_path.display().to_string(),
                    });
                    progress("container.sbom.done", "ok");
                }
                progress_timing("container.sbom", sbom_started);
            }
            let (scan_status, inventory_status, inventory_reason) =
                report_state_for_inventory(packages.len(), &mode, heuristic_used);
            let cache_dir = crate::vuln::resolve_enrich_cache_dir();
            crate::vuln::epss_enrich_findings(&mut findings_norm, &mut pg, cache_dir.as_deref(), &epss_breaker);
            crate::vuln::kev_enrich_findings(&mut findings_norm, &mut pg, cache_dir.as_deref(), &kev_breaker);

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

            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("{}", json);
            write_output_if_needed(&out, &json);
        }
    }
}
