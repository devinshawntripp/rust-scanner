//! SBOM subcommand handlers: import, diff, and policy check.

use crate::sbom;
use crate::utils;
use crate::utils::progress;
use crate::OutputFormat;
use crate::SbomCommands;

use super::strip_references_in_findings;

pub fn run_sbom(command: SbomCommands, nvd_api_key: Option<String>) {
    match command {
        SbomCommands::Import {
            file,
            format,
            out,
            mode,
            refs,
        } => {
            std::env::set_var("SCANNER_OSV_ENRICH", "1");
            if std::env::var("SCANNER_NVD_ENRICH").is_err() {
                let nvd_on = if nvd_api_key.is_some() { "1" } else { "0" };
                std::env::set_var("SCANNER_NVD_ENRICH", nvd_on);
            }
            progress("sbom.scan.start", &file);
            let report = match sbom::build_sbom_report(&file, mode, nvd_api_key.clone()) {
                Ok(r) => r,
                Err(e) => {
                    progress("sbom.scan.error", &file);
                    utils::progress_panel_finish("sbom import failed");
                    eprintln!("failed to import SBOM: {} — {}", file, e);
                    std::process::exit(1);
                }
            };
            let mut report_value = match serde_json::to_value(report) {
                Ok(v) => v,
                Err(e) => {
                    progress("sbom.scan.error", &file);
                    utils::progress_panel_finish("sbom import failed");
                    eprintln!("failed to serialize SBOM report: {}", e);
                    std::process::exit(1);
                }
            };
            if !refs {
                strip_references_in_findings(&mut report_value);
            }
            let summary = report_value
                .get("summary")
                .and_then(|s| s.as_object())
                .and_then(|o| o.get("total_findings"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            progress(
                "sbom.scan.done",
                &format!("file={} findings={}", file, summary),
            );
            utils::progress_panel_finish(&format!(
                "sbom import complete findings={}",
                summary
            ));

            let text = match format {
                OutputFormat::Json => serde_json::to_string_pretty(&report_value).unwrap(),
                OutputFormat::Ndjson => crate::report::value_to_ndjson(&report_value),
                OutputFormat::Text => crate::cli::text_report::render_text_report(&report_value),
            };
            print!("{}", text);
            utils::write_output_if_needed(&out, &text);
        }
        SbomCommands::Diff {
            baseline,
            current,
            json,
            out,
        } => {
            let diff = match sbom::build_sbom_diff(&baseline, &current) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("sbom diff failed: {}", e);
                    std::process::exit(1);
                }
            };

            if json {
                let payload = serde_json::to_string_pretty(&diff).unwrap_or_default();
                println!("{}", payload);
                utils::write_output_if_needed(&out, &payload);
            } else {
                println!(
                    "sbom_diff baseline={} current={} baseline_pkgs={} current_pkgs={} added={} removed={} changed={}",
                    baseline,
                    current,
                    diff.summary.baseline_packages,
                    diff.summary.current_packages,
                    diff.summary.added,
                    diff.summary.removed,
                    diff.summary.changed
                );
                for c in diff.changed.iter().take(20) {
                    println!(
                        "changed\t{}\t{}\t{} -> {}",
                        c.ecosystem, c.name, c.from_version, c.to_version
                    );
                }
                for a in diff.added.iter().take(20) {
                    println!("added\t{}\t{}\t{}", a.ecosystem, a.name, a.version);
                }
                for r in diff.removed.iter().take(20) {
                    println!("removed\t{}\t{}\t{}", r.ecosystem, r.name, r.version);
                }
            }
        }
        SbomCommands::Policy {
            policy,
            diff,
            report,
        } => {
            let pol = match sbom::load_policy(&policy) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("failed to load policy: {}", e);
                    std::process::exit(1);
                }
            };
            let diff_json: sbom::SbomDiff = match std::fs::read_to_string(&diff)
                .map_err(|e| anyhow::anyhow!("{}", e))
                .and_then(|s| serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{}", e)))
            {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("failed to parse diff JSON: {}", e);
                    std::process::exit(1);
                }
            };
            let report_value: Option<serde_json::Value> = report.and_then(|p| {
                std::fs::read_to_string(&p)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
            });
            let result = sbom::check_policy_from_value(&pol, &diff_json, report_value.as_ref());
            let output = serde_json::to_string_pretty(&result).unwrap_or_default();
            println!("{}", output);
            if !result.passed {
                std::process::exit(1);
            }
        }
    }
}
