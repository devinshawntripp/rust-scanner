mod binary;
mod cache;
mod container;
mod iso;
mod license;
mod redhat;
mod report;
mod usercli;
mod utils;
mod vuln;

use crate::utils::progress;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "scanrook", version = env!("CARGO_PKG_VERSION"))]
#[command(about = "ScanRook installed-state-first security scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Cache directory for API results and SBOMs
    #[arg(long)]
    cache_dir: Option<String>,
    /// Optional YARA rules file for deep scans
    #[arg(long)]
    yara: Option<String>,
    /// Optional NVD API key for enrichment
    #[arg(long)]
    nvd_api_key: Option<String>,
    /// ScanRook API base URL for CLI auth/limits
    #[arg(long)]
    api_base: Option<String>,
    /// ScanRook API key (overrides saved config)
    #[arg(long)]
    api_key: Option<String>,
    /// Emit progress events to stderr
    #[arg(long, default_value_t = false)]
    progress: bool,
    /// Write progress events (NDJSON) to a file
    #[arg(long)]
    progress_file: Option<String>,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum ScanMode {
    Light,
    Deep,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum BenchmarkProfile {
    Warm,
    Cold,
    NoCache,
}

#[derive(Subcommand)]
enum Commands {
    /// Smart scan: detect type (container tar, source tar, or binary) and report
    Scan {
        /// Path to file (tar/tar.gz/tar.bz2/iso/bin)
        #[arg(short, long)]
        file: String,
        /// Output format: json or text
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        /// Output file for JSON format
        #[arg(long)]
        out: Option<String>,
        /// Include references in report
        #[arg(long, default_value_t = false)]
        refs: bool,
        /// Scan mode: light or deep (deep enables YARA if available)
        #[arg(long, value_enum, default_value_t = ScanMode::Light)]
        mode: ScanMode,
        /// Path to Red Hat OVAL XML for fixed checks in RPM/container scans
        #[arg(long)]
        oval_redhat: Option<String>,
    },
    /// Scan a binary file
    Bin {
        /// Path to binary
        #[arg(short, long)]
        path: String,
        /// Output format: json or text
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Output file for JSON format
        #[arg(long)]
        out: Option<String>,
        /// Scan mode: light or deep
        #[arg(long, value_enum, default_value_t = ScanMode::Light)]
        mode: ScanMode,
    },
    /// Scan a source tarball
    Source {
        /// Path to source tarball
        #[arg(short, long)]
        tar: String,
        /// Output format: json or text
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Output file for JSON format
        #[arg(long)]
        out: Option<String>,
    },
    /// Scan a container image (from saved tar)
    Container {
        #[arg(short, long)]
        tar: String,
        /// Scan mode: light or deep
        #[arg(long, value_enum, default_value_t = ScanMode::Light)]
        mode: ScanMode,
        /// Output format: json or text
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Output file for JSON format
        #[arg(long)]
        out: Option<String>,
        /// Generate SBOM using syft and include in report
        #[arg(long, default_value_t = false)]
        sbom: bool,
        /// Path to Red Hat OVAL XML for fixed checks
        #[arg(long)]
        oval_redhat: Option<String>,
    },
    /// Detect license in a file
    License {
        #[arg(short, long)]
        path: String,
    },
    /// Match CVE from component/version
    Vuln {
        #[arg(short, long)]
        component: String,
        #[arg(short, long)]
        version: String,
    },
    /// Check Red Hat OVAL XML for CVE
    Redhat {
        #[arg(short, long)]
        cve: String,
        #[arg(short, long)]
        oval: String,
    },
    /// Authentication and local CLI credential management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Show current caller identity against ScanRook API
    Whoami {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show cloud-enrichment limit status
    Limits {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// CLI config management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Benchmark ScanRook vs Trivy/Grype on the same artifact
    Benchmark {
        /// Artifact path (tar/iso/bin)
        #[arg(short, long)]
        file: String,
        /// Output directory for summary.csv and tool JSON outputs
        #[arg(long, default_value = "benchmark-out")]
        out_dir: String,
        /// Benchmark profile: warm, cold, no-cache
        #[arg(long, value_enum, default_value_t = BenchmarkProfile::Warm)]
        profile: BenchmarkProfile,
    },
    /// Diff CVE IDs between ScanRook output and another scanner JSON
    Diff {
        /// ScanRook report JSON path
        #[arg(long)]
        ours: String,
        /// Other report JSON path (Trivy/Grype/ScanRook)
        #[arg(long)]
        against: String,
        /// Optional JSON output path for full diff details
        #[arg(long)]
        out: Option<String>,
    },
    /// Manage local vulnerability cache
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Login by saving API key or starting device flow
    Login {
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        api_base: Option<String>,
    },
    /// Remove stored API key
    Logout,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Set config values. Example: scanrook config set telemetry.opt_in true
    Set { key: String, value: String },
}

#[derive(Subcommand)]
enum DbCommands {
    /// Show local cache path and size
    Status,
    /// Remove local cache contents
    Clear,
    /// Download and pre-warm local vulnerability DB/cache for an artifact
    Download {
        /// Artifact path to prefetch advisories for
        #[arg(short, long)]
        file: String,
        /// Scan mode used during prefetch
        #[arg(long, value_enum, default_value_t = ScanMode::Deep)]
        mode: ScanMode,
    },
    /// Pre-warm local cache by scanning an artifact
    Warm {
        /// Artifact path to prefetch advisories for
        #[arg(short, long)]
        file: String,
        /// Scan mode used during warm-up
        #[arg(long, value_enum, default_value_t = ScanMode::Deep)]
        mode: ScanMode,
    },
}

fn main() {
    if let Some(argv0) = std::env::args().next() {
        if argv0.ends_with("scanner") {
            eprintln!(
                "warning: `scanner` binary name is deprecated and will be removed after the compatibility window. use `scanrook`."
            );
        }
    }

    let cli = Cli::parse();
    let nvd_api_key = cli
        .nvd_api_key
        .clone()
        .or_else(|| std::env::var("NVD_API_KEY").ok())
        .filter(|v| !v.trim().is_empty());

    if let Some(dir) = &cli.cache_dir {
        std::env::set_var("SCANNER_CACHE", dir);
    } else if std::env::var("SCANNER_CACHE").is_err() {
        if let Some(home) = std::env::var_os("HOME") {
            let default_cache = PathBuf::from(home).join(".scanrook").join("cache");
            let _ = std::fs::create_dir_all(&default_cache);
            std::env::set_var("SCANNER_CACHE", default_cache);
        }
    }
    if cli.progress {
        std::env::set_var("SCANNER_PROGRESS_STDERR", "1");
    }
    if let Some(p) = &cli.progress_file {
        std::env::set_var("SCANNER_PROGRESS_FILE", p);
    }

    match cli.command {
        Commands::Scan {
            file,
            format,
            out,
            refs,
            mode,
            oval_redhat,
        } => {
            // Keep default scans responsive:
            // - refs=true: full enrichment (OSV + NVD)
            // - refs=false: keep OSV enrichment and enable NVD only when API key is available
            if refs {
                std::env::set_var("SCANNER_OSV_ENRICH", "1");
                std::env::set_var("SCANNER_NVD_ENRICH", "1");
            } else {
                std::env::set_var("SCANNER_OSV_ENRICH", "1");
                if std::env::var("SCANNER_NVD_ENRICH").is_err() {
                    let nvd_on = if nvd_api_key.is_some() { "1" } else { "0" };
                    std::env::set_var("SCANNER_NVD_ENRICH", nvd_on);
                }
            }

            let osv_enabled = std::env::var("SCANNER_OSV_ENRICH")
                .map(|v| v != "0")
                .unwrap_or(true);
            let nvd_enabled = std::env::var("SCANNER_NVD_ENRICH")
                .map(|v| v != "0")
                .unwrap_or(true);
            if osv_enabled || nvd_enabled {
                let cloud_allowed =
                    usercli::consume_cloud_enrich_token(cli.api_base.clone(), cli.api_key.clone());
                if !cloud_allowed {
                    std::env::set_var("SCANNER_OSV_ENRICH", "0");
                    std::env::set_var("SCANNER_NVD_ENRICH", "0");
                    progress(
                        "cli.cloud_enrich.skip",
                        "disabled by /api/cli/enrich rate limit; continuing local scan",
                    );
                }
            }

            progress("scan.start", &file);
            let report_json = build_scan_report_value(
                &file,
                mode.clone(),
                cli.yara.clone(),
                nvd_api_key.clone(),
                oval_redhat
                    .or_else(|| std::env::var("SCANNER_OVAL_REDHAT").ok())
                    .filter(|v| !v.trim().is_empty()),
            );

            if let Some(mut v) = report_json {
                if !refs {
                    // Strip references array from each finding when refs flag not set
                    strip_references_in_findings(&mut v);
                }
                let text = if matches!(format, OutputFormat::Json) {
                    serde_json::to_string_pretty(&v).unwrap()
                } else {
                    format!("{}", v)
                };
                println!("{}", text);
                utils::write_output_if_needed(&out, &text);
                let summary = v
                    .get("summary")
                    .and_then(|s| s.as_object())
                    .and_then(|o| o.get("total_findings"))
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0);
                progress("scan.done", &format!("file={} findings={}", file, summary));
            } else {
                eprintln!("Failed to detect or scan file: {}", file);
                progress("scan.error", &format!("file={}", file));
                std::process::exit(1);
            }
        }
        Commands::Bin {
            path,
            format,
            out,
            mode,
        } => match format {
            OutputFormat::Text => binary::scan_binary(&path),
            OutputFormat::Json => {
                if let Some(report) =
                    binary::build_binary_report(&path, mode, None, nvd_api_key.clone())
                {
                    let json = serde_json::to_string_pretty(&report).unwrap();
                    println!("{}", json);
                    utils::write_output_if_needed(&out, &json);
                }
            }
        },
        Commands::Container {
            tar,
            mode,
            format,
            out,
            sbom,
            oval_redhat,
        } => {
            container::scan_container(
                &tar,
                mode,
                format,
                cli.cache_dir.clone(),
                cli.yara.clone(),
                out,
                sbom,
                nvd_api_key.clone(),
                oval_redhat,
            );
        }
        Commands::Source { tar, format, out } => {
            container::scan_source_tarball(&tar, format, nvd_api_key.clone(), out);
        }
        Commands::License { path } => {
            license::detect_license(&path);
        }
        Commands::Vuln { component, version } => {
            vuln::match_vuln(&component, &version);
        }
        Commands::Redhat { cve, oval } => {
            redhat::check_redhat_cve(&cve, &oval);
        }
        Commands::Auth { command } => match command {
            AuthCommands::Login { api_key, api_base } => {
                if let Err(e) = usercli::login(
                    api_base.or(cli.api_base.clone()),
                    api_key.or(cli.api_key.clone()),
                ) {
                    eprintln!("login failed: {}", e);
                    std::process::exit(1);
                }
            }
            AuthCommands::Logout => {
                if let Err(e) = usercli::logout() {
                    eprintln!("logout failed: {}", e);
                    std::process::exit(1);
                }
            }
        },
        Commands::Whoami { json } => {
            if let Err(e) = usercli::whoami(cli.api_base.clone(), cli.api_key.clone(), json) {
                eprintln!("whoami failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Limits { json } => {
            if let Err(e) = usercli::show_limits(cli.api_base.clone(), cli.api_key.clone(), json) {
                eprintln!("limits failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Config { command } => match command {
            ConfigCommands::Set { key, value } => {
                if let Err(e) = usercli::set_config_value(&key, &value) {
                    eprintln!("config set failed: {}", e);
                    std::process::exit(1);
                }
            }
        },
        Commands::Benchmark {
            file,
            out_dir,
            profile,
        } => {
            if let Err(e) = run_benchmark(&file, &out_dir, profile) {
                eprintln!("benchmark failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Diff { ours, against, out } => {
            if let Err(e) = run_diff(&ours, &against, out.as_deref()) {
                eprintln!("diff failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Db { command } => {
            if let Err(e) = run_db(command, cli.yara.clone(), nvd_api_key.clone()) {
                eprintln!("db command failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn strip_references_in_findings(v: &mut Value) {
    if let Some(arr) = v.get_mut("findings").and_then(|f| f.as_array_mut()) {
        for f in arr.iter_mut() {
            f.as_object_mut().map(|o| o.remove("references"));
        }
    }
}

fn build_scan_report_value(
    file: &str,
    mode: ScanMode,
    yara: Option<String>,
    nvd_api_key: Option<String>,
    oval_redhat: Option<String>,
) -> Option<Value> {
    let tar_like = looks_like_tar_input(file);
    let iso_like = looks_like_iso_input(file);
    if tar_like {
        if let Some(r) = container::build_container_report(
            file,
            mode.clone(),
            false,
            nvd_api_key.clone(),
            yara.clone(),
            oval_redhat.clone(),
        ) {
            return serde_json::to_value(r).ok();
        }
        if let Some(r) = container::build_source_report(file, nvd_api_key) {
            return serde_json::to_value(r).ok();
        }
        return None;
    }
    if iso_like {
        if let Some(r) = iso::build_iso_report(file, mode, yara, nvd_api_key, oval_redhat) {
            return serde_json::to_value(r).ok();
        }
        return None;
    }
    binary::build_binary_report(file, mode, yara, nvd_api_key)
        .and_then(|r| serde_json::to_value(r).ok())
}

fn resolve_cache_dir() -> PathBuf {
    if let Ok(v) = std::env::var("SCANNER_CACHE") {
        return PathBuf::from(v);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".scanrook").join("cache");
    }
    PathBuf::from(".scanrook-cache")
}

fn clear_scanrook_cache() -> anyhow::Result<()> {
    let dir = resolve_cache_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(())
}

fn clear_trivy_cache() {
    let _ = Command::new("trivy").arg("clean").arg("--all").status();
    if let Some(home) = std::env::var_os("HOME") {
        let _ = std::fs::remove_dir_all(PathBuf::from(&home).join(".cache").join("trivy"));
        let _ = std::fs::remove_dir_all(
            PathBuf::from(&home)
                .join("Library")
                .join("Caches")
                .join("trivy"),
        );
    }
}

fn clear_grype_cache() {
    if let Some(home) = std::env::var_os("HOME") {
        let _ = std::fs::remove_dir_all(PathBuf::from(&home).join(".cache").join("grype"));
        let _ = std::fs::remove_dir_all(
            PathBuf::from(&home)
                .join("Library")
                .join("Caches")
                .join("grype"),
        );
    }
}

fn run_db(
    command: DbCommands,
    yara: Option<String>,
    nvd_api_key: Option<String>,
) -> anyhow::Result<()> {
    match command {
        DbCommands::Status => {
            let dir = resolve_cache_dir();
            let mut files = 0usize;
            let mut bytes = 0u64;
            if dir.exists() {
                for e in walkdir::WalkDir::new(&dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if e.file_type().is_file() {
                        files += 1;
                        if let Ok(m) = e.metadata() {
                            bytes += m.len();
                        }
                    }
                }
            }
            println!("cache_dir={}", dir.display());
            println!("entries={}", files);
            println!("bytes={}", bytes);
        }
        DbCommands::Clear => {
            clear_scanrook_cache()?;
            println!("cache_cleared path={}", resolve_cache_dir().display());
        }
        DbCommands::Download { file, mode } | DbCommands::Warm { file, mode } => {
            std::env::remove_var("SCANNER_SKIP_CACHE");
            let started = Instant::now();
            let report = build_scan_report_value(&file, mode, yara, nvd_api_key, None)
                .ok_or_else(|| anyhow::anyhow!("scan warm-up failed to produce report"))?;
            let findings = report
                .get("findings")
                .and_then(|f| f.as_array())
                .map(|v| v.len())
                .unwrap_or(0);
            println!(
                "cache_warm_done file={} findings={} elapsed_ms={}",
                file,
                findings,
                started.elapsed().as_millis()
            );
        }
    }
    Ok(())
}

fn run_benchmark(file: &str, out_dir: &str, profile: BenchmarkProfile) -> anyhow::Result<()> {
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
    let report = build_scan_report_value(file, ScanMode::Deep, None, None, None)
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

#[derive(Debug, Default)]
struct ParsedIds {
    tool: String,
    ids: BTreeSet<String>,
    id_packages: BTreeMap<String, BTreeSet<String>>,
}

fn parse_report_ids(path: &str) -> anyhow::Result<ParsedIds> {
    let text = std::fs::read_to_string(path)?;
    let v: Value = serde_json::from_str(&text)?;
    let mut out = ParsedIds::default();

    if let Some(arr) = v.get("findings").and_then(|x| x.as_array()) {
        out.tool = "scanrook".to_string();
        for f in arr {
            if let Some(id) = f.get("id").and_then(|x| x.as_str()) {
                if id.starts_with("CVE-") {
                    out.ids.insert(id.to_string());
                    if let Some(pkg) = f
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|x| x.as_str())
                    {
                        out.id_packages
                            .entry(id.to_string())
                            .or_default()
                            .insert(pkg.to_string());
                    }
                }
            }
        }
        return Ok(out);
    }

    if let Some(results) = v.get("Results").and_then(|x| x.as_array()) {
        out.tool = "trivy".to_string();
        for r in results {
            if let Some(vulns) = r.get("Vulnerabilities").and_then(|x| x.as_array()) {
                for vuln in vulns {
                    if let Some(id) = vuln.get("VulnerabilityID").and_then(|x| x.as_str()) {
                        if id.starts_with("CVE-") {
                            out.ids.insert(id.to_string());
                            if let Some(pkg) = vuln.get("PkgName").and_then(|x| x.as_str()) {
                                out.id_packages
                                    .entry(id.to_string())
                                    .or_default()
                                    .insert(pkg.to_string());
                            }
                        }
                    }
                }
            }
        }
        return Ok(out);
    }

    if let Some(matches) = v.get("matches").and_then(|x| x.as_array()) {
        out.tool = "grype".to_string();
        for m in matches {
            if let Some(id) = m
                .get("vulnerability")
                .and_then(|vv| vv.get("id"))
                .and_then(|x| x.as_str())
            {
                if id.starts_with("CVE-") {
                    out.ids.insert(id.to_string());
                    if let Some(pkg) = m
                        .get("artifact")
                        .and_then(|a| a.get("name"))
                        .and_then(|x| x.as_str())
                    {
                        out.id_packages
                            .entry(id.to_string())
                            .or_default()
                            .insert(pkg.to_string());
                    }
                }
            }
        }
        return Ok(out);
    }

    Err(anyhow::anyhow!("unsupported report schema: {}", path))
}

fn run_diff(ours: &str, against: &str, out: Option<&str>) -> anyhow::Result<()> {
    let ours_ids = parse_report_ids(ours)?;
    let other_ids = parse_report_ids(against)?;

    let missing: Vec<String> = other_ids.ids.difference(&ours_ids.ids).cloned().collect();
    let extra: Vec<String> = ours_ids.ids.difference(&other_ids.ids).cloned().collect();

    println!(
        "ours_tool={} ours_cves={} against_tool={} against_cves={}",
        ours_ids.tool,
        ours_ids.ids.len(),
        other_ids.tool,
        other_ids.ids.len()
    );
    println!("missing_vs_against={}", missing.len());
    println!("extra_vs_against={}", extra.len());

    println!("missing_sample:");
    for cve in missing.iter().take(25) {
        println!("  {}", cve);
    }
    println!("extra_sample:");
    for cve in extra.iter().take(25) {
        println!("  {}", cve);
    }

    let mut miss_pkg_freq: BTreeMap<String, usize> = BTreeMap::new();
    for cve in &missing {
        if let Some(pkgs) = other_ids.id_packages.get(cve) {
            for p in pkgs {
                *miss_pkg_freq.entry(p.clone()).or_insert(0) += 1;
            }
        }
    }
    if !miss_pkg_freq.is_empty() {
        println!("missing_package_frequency:");
        let mut ranked: Vec<(String, usize)> = miss_pkg_freq.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (pkg, n) in ranked.into_iter().take(15) {
            println!("  {} {}", pkg, n);
        }
    }

    if let Some(path) = out {
        let payload = serde_json::json!({
            "ours_tool": ours_ids.tool,
            "against_tool": other_ids.tool,
            "ours_count": ours_ids.ids.len(),
            "against_count": other_ids.ids.len(),
            "missing_vs_against": missing,
            "extra_vs_against": extra,
        });
        std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
    }
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

fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn looks_like_tar_input(path: &str) -> bool {
    let lower = path.to_lowercase();
    if lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar.bz2")
        || lower.ends_with(".tbz2")
        || lower.ends_with(".tbz")
    {
        return true;
    }

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut head = [0u8; 512];
    let n = match f.read(&mut head) {
        Ok(n) => n,
        Err(_) => return false,
    };

    // gzip / bzip2 signatures (can still be non-tar, but worth trying tar path first)
    if n >= 2 && head[0] == 0x1f && head[1] == 0x8b {
        return true;
    }
    if n >= 3 && head[0] == b'B' && head[1] == b'Z' && head[2] == b'h' {
        return true;
    }

    // USTAR magic at offset 257.
    if n >= 262 && &head[257..262] == b"ustar" {
        return true;
    }
    if n < 262 {
        let mut block = [0u8; 262];
        if f.seek(SeekFrom::Start(0)).is_ok() && f.read(&mut block).ok().unwrap_or(0) >= 262 {
            return &block[257..262] == b"ustar";
        }
    }
    false
}

fn looks_like_iso_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".iso") {
        return true;
    }

    let mut f = match File::open(path) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // ISO9660 PVD at sector 16 (offset 32768):
    // byte 0 = descriptor type (1 for primary), bytes 1..5 = "CD001"
    if f.seek(SeekFrom::Start(32768)).is_err() {
        return false;
    }
    let mut pvd = [0u8; 7];
    if f.read(&mut pvd).ok().unwrap_or(0) < 7 {
        return false;
    }
    pvd[0] == 0x01 && &pvd[1..6] == b"CD001"
}
