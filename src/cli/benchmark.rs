use crate::cli::detect::build_scan_report_value;
use crate::cli::helpers::{
    clear_grype_cache, clear_scanrook_cache, clear_trivy_cache, command_exists,
};
use crate::{BenchmarkProfile, ScanMode};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

pub fn run_benchmark(file: &str, out_dir: &str, profile: BenchmarkProfile) -> anyhow::Result<()> {
    let out_dir = PathBuf::from(out_dir);
    std::fs::create_dir_all(&out_dir)?;

    if matches!(profile, BenchmarkProfile::Cold) {
        clear_scanrook_cache()?;
        clear_trivy_cache();
        clear_grype_cache();
    }

    let sr_out = out_dir.join("scanrook.json");
    let tr_out = out_dir.join("trivy.json");
    let gr_out = out_dir.join("grype.json");

    let mut rows: Vec<(String, f64, usize, String)> = Vec::new();

    // ScanRook
    let sr_started = Instant::now();
    let prev_skip = std::env::var("SCANNER_SKIP_CACHE").ok();
    if matches!(profile, BenchmarkProfile::NoCache) {
        std::env::set_var("SCANNER_SKIP_CACHE", "1");
    } else {
        std::env::remove_var("SCANNER_SKIP_CACHE");
    }
    let report = build_scan_report_value(file, ScanMode::Light, None, None, None)
        .ok_or_else(|| anyhow::anyhow!("scanrook benchmark run failed"))?;
    std::fs::write(&sr_out, serde_json::to_string_pretty(&report)?)?;
    match prev_skip {
        Some(v) => std::env::set_var("SCANNER_SKIP_CACHE", v),
        None => std::env::remove_var("SCANNER_SKIP_CACHE"),
    }
    let sr_secs = sr_started.elapsed().as_secs_f64();
    let sr_findings = count_scanrook_findings(&sr_out)?;
    rows.push((
        "scanrook".to_string(),
        sr_secs,
        sr_findings,
        sr_out.to_string_lossy().to_string(),
    ));

    // Trivy
    if command_exists("trivy") {
        let tr_started = Instant::now();
        let mut tr_cmd = Command::new("trivy");
        tr_cmd
            .arg("image")
            .arg("--input")
            .arg(file)
            .arg("--format")
            .arg("json")
            .arg("--output")
            .arg(tr_out.to_string_lossy().to_string());
        let temp_cache;
        if matches!(profile, BenchmarkProfile::NoCache) {
            temp_cache = tempfile::tempdir()?;
            tr_cmd.env("TRIVY_CACHE_DIR", temp_cache.path());
        }
        let tr_status = tr_cmd.status()?;
        if tr_status.success() {
            let tr_secs = tr_started.elapsed().as_secs_f64();
            let tr_findings = count_trivy_findings(&tr_out)?;
            rows.push((
                "trivy".to_string(),
                tr_secs,
                tr_findings,
                tr_out.to_string_lossy().to_string(),
            ));
        }
    } else {
        eprintln!("trivy not found on PATH; skipping");
    }

    // Grype
    if command_exists("grype") {
        let gr_started = Instant::now();
        let output = {
            let mut gr_cmd = Command::new("grype");
            gr_cmd.arg(file).arg("-o").arg("json");
            let temp_cache;
            if matches!(profile, BenchmarkProfile::NoCache) {
                temp_cache = tempfile::tempdir()?;
                gr_cmd.env("GRYPE_DB_CACHE_DIR", temp_cache.path());
            }
            gr_cmd.output()?
        };
        if output.status.success() {
            std::fs::write(&gr_out, &output.stdout)?;
            let gr_secs = gr_started.elapsed().as_secs_f64();
            let gr_findings = count_grype_findings(&gr_out)?;
            rows.push((
                "grype".to_string(),
                gr_secs,
                gr_findings,
                gr_out.to_string_lossy().to_string(),
            ));
        }
    } else {
        eprintln!("grype not found on PATH; skipping");
    }

    let summary = out_dir.join("summary.csv");
    let mut csv = String::from("tool,duration_seconds,findings_count,output_path\n");
    for (tool, secs, count, path) in &rows {
        csv.push_str(&format!("{},{:.3},{},{}\n", tool, secs, count, path));
    }
    std::fs::write(&summary, csv)?;

    println!("benchmark_profile={:?}", profile);
    for (tool, secs, count, path) in &rows {
        println!(
            "tool={} duration_seconds={:.3} findings={} output={}",
            tool, secs, count, path
        );
    }
    println!("summary_csv={}", summary.display());
    Ok(())
}

fn count_scanrook_findings(path: &PathBuf) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let v: Value = serde_json::from_str(&text)?;
    Ok(v.get("findings")
        .and_then(|f| f.as_array())
        .map(|a| a.len())
        .unwrap_or(0))
}

fn count_trivy_findings(path: &PathBuf) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let v: Value = serde_json::from_str(&text)?;
    let mut n = 0usize;
    if let Some(results) = v.get("Results").and_then(|x| x.as_array()) {
        for r in results {
            n += r
                .get("Vulnerabilities")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
        }
    }
    Ok(n)
}

fn count_grype_findings(path: &PathBuf) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let v: Value = serde_json::from_str(&text)?;
    Ok(v.get("matches")
        .and_then(|m| m.as_array())
        .map(|a| a.len())
        .unwrap_or(0))
}
