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

    let osv_breaker = crate::vuln::CircuitBreaker::new("osv", 5);
    let nvd_breaker = crate::vuln::CircuitBreaker::new("nvd", 5);
    let epss_breaker = crate::vuln::CircuitBreaker::new("epss", 5);
    let kev_breaker = crate::vuln::CircuitBreaker::new("kev", 5);

    let (mut findings_norm, heuristic_used) = {
        let mut ectx = super::enrich::EnrichCtx {
            packages: &packages,
            mode: &mode,
            nvd_api_key: nvd_api_key.as_deref(),
            tar_path,
            rootfs: &rootfs,
            has_container_layout: manifest_path.exists() || oci_index_path.exists(),
            oval_redhat,
            pg: &mut pg,
            osv_breaker: &osv_breaker,
            nvd_breaker: &nvd_breaker,
            epss_breaker: &epss_breaker,
            kev_breaker: &kev_breaker,
        };
        super::enrich::run_enrichment_pipeline(&mut ectx)
    };

    // YARA (cli-specific: collects hits for text display)
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
        OutputFormat::Json | OutputFormat::Ndjson => {
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

            match format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&report).unwrap();
                    println!("{}", json);
                    write_output_if_needed(&out, &json);
                }
                OutputFormat::Ndjson => {
                    let mut buf = Vec::new();
                    crate::report::NdjsonWriter::new(&mut buf)
                        .write_report(&report)
                        .unwrap();
                    let text = String::from_utf8(buf).unwrap();
                    print!("{}", text);
                    write_output_if_needed(&out, &text);
                }
                _ => unreachable!(),
            }
        }
    }
}
