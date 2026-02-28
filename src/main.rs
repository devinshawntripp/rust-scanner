mod binary;
mod cache;
mod container;
mod iso;
mod license;
mod redhat;
mod report;
mod sbom;
mod usercli;
mod utils;
mod vuln;

use crate::utils::progress;
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::blocking::Client;

/// Default YARA rules bundled with the scanner binary.
#[cfg(feature = "yara")]
const DEFAULT_YARA_RULES: &str = include_str!("../rules/default.yar");
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Log output format for --progress stderr stream (text uses bracketed Trivy-style)
    #[arg(long, value_enum, default_value_t = ScannerLogFormat::Text)]
    log_format: ScannerLogFormat,
    /// Log verbosity threshold for --progress stderr stream
    #[arg(long, value_enum, default_value_t = ScannerLogLevel::Info)]
    log_level: ScannerLogLevel,
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
pub enum ScannerLogFormat {
    Text,
    Json,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum ScannerLogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum BenchmarkProfile {
    Warm,
    Cold,
    NoCache,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum DbSource {
    All,
    Nvd,
    Osv,
    Redhat,
}

#[derive(Subcommand)]
enum SbomCommands {
    /// Import and scan an SBOM (CycloneDX JSON, SPDX JSON, or Syft JSON)
    Import {
        /// Path to SBOM JSON
        #[arg(short, long)]
        file: String,
        /// Output format: json or text
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        /// Output file for JSON format
        #[arg(long)]
        out: Option<String>,
        /// Scan mode: light or deep
        #[arg(long, value_enum, default_value_t = ScanMode::Light)]
        mode: ScanMode,
        /// Include references in report
        #[arg(long, default_value_t = false)]
        refs: bool,
    },
    /// Compare two SBOM snapshots to monitor package change over time
    Diff {
        /// Baseline SBOM JSON path
        #[arg(long)]
        baseline: String,
        /// Current SBOM JSON path
        #[arg(long)]
        current: String,
        /// Emit JSON diff
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Optional output file
        #[arg(long)]
        out: Option<String>,
    },
    /// Check SBOM diff against a policy file (exit code 1 if violated)
    Policy {
        /// Path to policy file (YAML or JSON)
        #[arg(long)]
        policy: String,
        /// Path to diff JSON file (from `sbom diff --json`)
        #[arg(long)]
        diff: String,
        /// Path to current scan report JSON (optional, used for severity checks)
        #[arg(long)]
        report: Option<String>,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Smart scan: detect type (container tar, source tar, or binary) and report
    Scan {
        /// Path to file (tar/tar.gz/tar.bz2/iso/bin)
        #[arg(short, long, required_unless_present = "image")]
        file: Option<String>,
        /// Docker/OCI image reference to scan (e.g., alpine:3.20, ubuntu:latest)
        #[arg(long, conflicts_with = "file")]
        image: Option<String>,
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
    /// SBOM import and SDLC change monitoring
    Sbom {
        #[command(subcommand)]
        command: SbomCommands,
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
    /// Check local cache + remote source connectivity + Postgres cache health
    Check,
    /// List vulnerability data sources ScanRook uses (active and planned)
    Sources {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Remove local cache contents
    Clear,
    /// Refresh selected source caches (optional artifact scan warm-up)
    Update {
        /// Source to refresh
        #[arg(long, value_enum, default_value_t = DbSource::All)]
        source: DbSource,
        /// Optional artifact path for full scan-driven warm-up
        #[arg(short, long)]
        file: Option<String>,
        /// Scan mode if --file is provided
        #[arg(long, value_enum, default_value_t = ScanMode::Deep)]
        mode: ScanMode,
        /// Optional CVE id seed for NVD/OSV/Red Hat refresh
        #[arg(long)]
        cve: Option<String>,
        /// Optional Red Hat errata id seed for CSAF refresh (example RHSA-2022:8162)
        #[arg(long)]
        errata: Option<String>,
    },
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
    /// Pre-populate local cache from PostgreSQL CVE data or by downloading key feeds
    Seed {
        /// Seed from PostgreSQL DATABASE_URL (copies cached CVE data to local file cache)
        #[arg(long, default_value_t = false)]
        from_pg: bool,
        /// Download Debian Security Tracker JSON to local cache
        #[arg(long, default_value_t = false)]
        debian: bool,
        /// Download Red Hat OVAL XML for a specific RHEL version (e.g. 9)
        #[arg(long)]
        rhel: Option<u32>,
        /// Download EPSS and KEV data
        #[arg(long, default_value_t = false)]
        epss: bool,
        /// Pre-warm NVD cache with a sample CVE query
        #[arg(long, default_value_t = false)]
        nvd: bool,
        /// Pre-warm OSV cache with a sample ecosystem query
        #[arg(long, default_value_t = false)]
        osv: bool,
        /// Download Ubuntu USN and Alpine SecDB advisory feeds
        #[arg(long, default_value_t = false)]
        distro: bool,
        /// Download all available feeds (debian, rhel7-9, epss, kev, nvd, osv, ubuntu, alpine)
        #[arg(long, default_value_t = false)]
        all: bool,
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
            set_dir_permissions_0700(&default_cache);
            std::env::set_var("SCANNER_CACHE", default_cache);
        }
    }
    // Nudge user to run `db seed` if cache is empty on first scan.
    if matches!(
        &cli.command,
        Commands::Scan { .. } | Commands::Container { .. }
    ) {
        nudge_seed_if_empty();
    }

    if cli.progress {
        std::env::set_var("SCANNER_PROGRESS_STDERR", "1");
    }
    let is_interactive_scan = std::io::stderr().is_terminal()
        && matches!(&cli.command, Commands::Scan { .. } | Commands::Sbom { .. });
    if is_interactive_scan && std::env::var("SCANNER_PROGRESS_STDERR").is_err() {
        std::env::set_var("SCANNER_PROGRESS_STDERR", "1");
    }
    if is_interactive_scan && std::env::var("SCANNER_PROGRESS_COMPACT").is_err() {
        std::env::set_var("SCANNER_PROGRESS_COMPACT", "1");
    }
    if let Some(p) = &cli.progress_file {
        std::env::set_var("SCANNER_PROGRESS_FILE", p);
    }
    std::env::set_var(
        "SCANNER_LOG_FORMAT",
        match cli.log_format {
            ScannerLogFormat::Text => "text",
            ScannerLogFormat::Json => "json",
        },
    );
    std::env::set_var(
        "SCANNER_LOG_LEVEL",
        match cli.log_level {
            ScannerLogLevel::Error => "error",
            ScannerLogLevel::Warn => "warn",
            ScannerLogLevel::Info => "info",
            ScannerLogLevel::Debug => "debug",
        },
    );

    match cli.command {
        Commands::Scan {
            file,
            image,
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

            // Resolve actual file path: either --file directly or --image via docker/podman save
            let (_image_tmpdir, file) = if let Some(image_ref) = image {
                progress("scan.image.pull", &image_ref);
                match container::pull_and_save_image(&image_ref) {
                    Ok((tmpdir, tar_path)) => {
                        progress("scan.image.saved", &tar_path);
                        (Some(tmpdir), tar_path)
                    }
                    Err(e) => {
                        eprintln!("Failed to pull/save image '{}': {}", image_ref, e);
                        progress(
                            "scan.image.error",
                            &format!("image={} err={}", image_ref, e),
                        );
                        utils::progress_panel_finish("scan failed");
                        std::process::exit(1);
                    }
                }
            } else if let Some(f) = file {
                (None, f)
            } else {
                eprintln!("Either --file or --image must be provided");
                std::process::exit(1);
            };

            progress("scan.start", &file);
            let yara_rules = resolve_yara_rules(&cli.yara, &mode);
            let report_json = build_scan_report_value(
                &file,
                mode.clone(),
                yara_rules,
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
                let summary = v
                    .get("summary")
                    .and_then(|s| s.as_object())
                    .and_then(|o| o.get("total_findings"))
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0);
                progress("scan.done", &format!("file={} findings={}", file, summary));
                utils::progress_panel_finish(&format!("scan complete findings={}", summary));

                let text = if matches!(format, OutputFormat::Json) {
                    serde_json::to_string_pretty(&v).unwrap()
                } else {
                    format!("{}", v)
                };
                println!("{}", text);
                utils::write_output_if_needed(&out, &text);
            } else {
                eprintln!("Failed to detect or scan file: {}", file);
                progress("scan.error", &format!("file={}", file));
                utils::progress_panel_finish("scan failed");
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
        Commands::Sbom { command } => match command {
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
                if let Some(mut report) = sbom::build_sbom_report(&file, mode, nvd_api_key.clone())
                    .and_then(|r| serde_json::to_value(r).ok())
                {
                    if !refs {
                        strip_references_in_findings(&mut report);
                    }
                    let summary = report
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

                    let text = if matches!(format, OutputFormat::Json) {
                        serde_json::to_string_pretty(&report).unwrap()
                    } else {
                        format!("{}", report)
                    };
                    println!("{}", text);
                    utils::write_output_if_needed(&out, &text);
                } else {
                    progress("sbom.scan.error", &file);
                    utils::progress_panel_finish("sbom import failed");
                    eprintln!("failed to import SBOM: {}", file);
                    std::process::exit(1);
                }
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
                let report_value: Option<Value> = report.and_then(|p| {
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
        },
    }
}

fn strip_references_in_findings(v: &mut Value) {
    if let Some(arr) = v.get_mut("findings").and_then(|f| f.as_array_mut()) {
        for f in arr.iter_mut() {
            f.as_object_mut().map(|o| o.remove("references"));
        }
    }
}

/// Print a hint if the vulnerability cache is empty (e.g. fresh install without `make install`).
fn nudge_seed_if_empty() {
    let cache_dir = resolve_cache_dir();
    let sentinel = cache_dir.join(".seed_done");
    if sentinel.exists() {
        return;
    }
    let is_empty = match std::fs::read_dir(&cache_dir) {
        Ok(entries) => entries.count() <= 1, // allow the dir itself
        Err(_) => true,
    };
    if is_empty {
        progress(
            "cache.empty",
            "run `scanrook db seed --all` to pre-warm the vulnerability cache for faster scans",
        );
    }
}

/// Resolve YARA rules path: use user-specified file, or write bundled defaults for deep mode.
fn resolve_yara_rules(user_yara: &Option<String>, mode: &ScanMode) -> Option<String> {
    // If user specified a YARA rules file, use that
    if user_yara.is_some() {
        return user_yara.clone();
    }
    // In deep mode, write bundled defaults to a temp file
    #[cfg(feature = "yara")]
    if matches!(mode, ScanMode::Deep) {
        match write_default_yara_to_temp() {
            Ok(path) => {
                progress("yara.defaults.loaded", &path);
                return Some(path);
            }
            Err(e) => {
                progress("yara.defaults.error", &format!("{}", e));
            }
        }
    }
    #[cfg(not(feature = "yara"))]
    let _ = mode;
    None
}

#[cfg(feature = "yara")]
fn write_default_yara_to_temp() -> anyhow::Result<String> {
    // Write to cache dir so it persists across scans in the same session
    let cache_dir = resolve_cache_dir();
    let yara_path = cache_dir.join("default_rules.yar");
    std::fs::create_dir_all(&cache_dir)?;
    std::fs::write(&yara_path, DEFAULT_YARA_RULES)?;
    Ok(yara_path.to_string_lossy().to_string())
}

/// Seed local file cache by copying CVE data from PostgreSQL.
///
/// Handles multiple table shapes gracefully — if a table doesn't exist,
/// it's skipped rather than failing the whole seed operation.
fn seed_cache_from_pg(cache_dir: &std::path::Path) -> anyhow::Result<usize> {
    let mut pg = vuln::pg_connect()
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL not set or connection failed"))?;
    vuln::pg_init_schema(&mut pg);

    let mut count = 0usize;

    // Try cve_cache table (NVD/OSV/Red Hat enrichment data)
    match pg.query(
        "SELECT cve_id, source, response_json FROM cve_cache ORDER BY cve_id",
        &[],
    ) {
        Ok(rows) => {
            for row in &rows {
                let cve_id: String = row.get(0);
                let source: String = row.get(1);
                let json: serde_json::Value = row.get(2);
                let key_hash = cache::cache_key(&["pg_seed", &source, &cve_id]);
                let cache_path = cache_dir.join(&key_hash);
                if cache_path.exists() {
                    continue;
                }
                let data = serde_json::to_vec(&json)?;
                std::fs::write(&cache_path, &data)?;
                count += 1;
            }
            progress("db.seed.pg.cve_cache", &format!("entries={}", rows.len()));
        }
        Err(e) => {
            progress(
                "db.seed.pg.cve_cache.skip",
                &format!("table may not exist: {}", e),
            );
        }
    }

    // Try osv_cache table if it exists
    match pg.query(
        "SELECT advisory_id, response_json FROM osv_cache ORDER BY advisory_id",
        &[],
    ) {
        Ok(rows) => {
            for row in &rows {
                let id: String = row.get(0);
                let json: serde_json::Value = row.get(1);
                let key_hash = cache::cache_key(&["pg_seed_osv", &id]);
                let cache_path = cache_dir.join(&key_hash);
                if cache_path.exists() {
                    continue;
                }
                let data = serde_json::to_vec(&json)?;
                std::fs::write(&cache_path, &data)?;
                count += 1;
            }
            progress("db.seed.pg.osv_cache", &format!("entries={}", rows.len()));
        }
        Err(_) => {
            // Table doesn't exist, that's fine
        }
    }

    Ok(count)
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
    let sbom_like = looks_like_sbom_input(file);
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
    if sbom_like {
        if let Some(r) = sbom::build_sbom_report(file, mode, nvd_api_key) {
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
    set_dir_permissions_0700(&dir);
    Ok(())
}

/// Set directory permissions to 0o700 (owner-only) on unix systems.
#[cfg(unix)]
fn set_dir_permissions_0700(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_permissions_0700(_dir: &std::path::Path) {}

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

#[derive(Clone, Copy)]
struct DataSourceDef {
    source: &'static str,
    provider: &'static str,
    ecosystems: &'static str,
    kind: &'static str,
    status: &'static str,
    notes: &'static str,
}

const SCANROOK_DATA_SOURCES: &[DataSourceDef] = &[
    DataSourceDef {
        source: "Open Source Vulnerabilities API",
        provider: "osv",
        ecosystems: ".NET, Go, Java, JavaScript, Python, Ruby, Rust, DPKG, APK, RPM",
        kind: "advisories+vuln details",
        status: "active",
        notes: "primary cross-ecosystem advisory feed",
    },
    DataSourceDef {
        source: "National Vulnerability Database",
        provider: "nvd",
        ecosystems: "CVE-backed cross-ecosystem",
        kind: "disclosures+cvss",
        status: "active",
        notes: "CVE enrichment, CVSS/vector, references",
    },
    DataSourceDef {
        source: "Red Hat Security Data API (Hydra)",
        provider: "redhat",
        ecosystems: "RPM (RHEL family)",
        kind: "RHSA/CVE/CSAF",
        status: "active",
        notes: "applicability + fixed build context",
    },
    DataSourceDef {
        source: "Red Hat OVAL XML (user supplied)",
        provider: "redhat_oval",
        ecosystems: "RPM (RHEL family)",
        kind: "fixed-state verification",
        status: "active",
        notes: "full OVAL applicability when file is provided via --oval-redhat",
    },
    DataSourceDef {
        source: "Ubuntu CVE Tracker",
        provider: "ubuntu",
        ecosystems: "DPKG",
        kind: "distribution advisories",
        status: "active",
        notes: "direct notices feed enrichment with package-level fixed version mapping",
    },
    DataSourceDef {
        source: "Debian Security Tracker",
        provider: "debian",
        ecosystems: "DPKG",
        kind: "distribution advisories",
        status: "active",
        notes: "direct tracker feed enrichment with package-level fixed version mapping",
    },
    DataSourceDef {
        source: "Alpine SecDB",
        provider: "alpine",
        ecosystems: "APK",
        kind: "distribution advisories",
        status: "active",
        notes: "direct SecDB enrichment with package-level secfix mapping",
    },
    DataSourceDef {
        source: "AlmaLinux OSV Database",
        provider: "alma",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Amazon Linux Security Center",
        provider: "amazon",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "SUSE Security OVAL",
        provider: "sles",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Oracle Linux Security",
        provider: "oracle",
        ecosystems: "RPM",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Chainguard Security",
        provider: "chainguard",
        ecosystems: "APK",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "Wolfi Security",
        provider: "wolfi",
        ecosystems: "APK",
        kind: "distribution advisories",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "EPSS",
        provider: "epss",
        ecosystems: "cross-ecosystem",
        kind: "auxiliary prioritization",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
    DataSourceDef {
        source: "CISA KEV",
        provider: "kev",
        ecosystems: "cross-ecosystem",
        kind: "auxiliary exploit status",
        status: "planned",
        notes: "not yet first-class in scanner",
    },
];

#[derive(Default)]
struct LocalCacheStats {
    entries: usize,
    bytes: u64,
    latest: Option<SystemTime>,
}

fn collect_local_cache_stats(dir: &PathBuf) -> LocalCacheStats {
    let mut stats = LocalCacheStats::default();
    if !dir.exists() {
        return stats;
    }
    for e in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !e.file_type().is_file() {
            continue;
        }
        stats.entries += 1;
        if let Ok(m) = e.metadata() {
            stats.bytes += m.len();
            if let Ok(mt) = m.modified() {
                if stats.latest.map(|x| mt > x).unwrap_or(true) {
                    stats.latest = Some(mt);
                }
            }
        }
    }
    stats
}

fn fmt_epoch(ts: Option<SystemTime>) -> String {
    ts.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn env_bool_default(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn db_http_client() -> anyhow::Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| anyhow::anyhow!("http client init failed: {}", e))
}

fn check_endpoint_nvd(client: &Client, nvd_api_key: Option<&str>) -> anyhow::Result<u16> {
    let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1";
    let mut req = client.get(url);
    if let Some(k) = nvd_api_key {
        req = req.header("apiKey", k);
    }
    let resp = req.send()?;
    Ok(resp.status().as_u16())
}

fn check_endpoint_osv(client: &Client) -> anyhow::Result<u16> {
    let resp = client
        .post("https://api.osv.dev/v1/query")
        .json(&serde_json::json!({
            "package": { "ecosystem": "Debian", "name": "bash" },
            "version": "5.1-2"
        }))
        .send()?;
    Ok(resp.status().as_u16())
}

fn check_endpoint_redhat(client: &Client) -> anyhow::Result<u16> {
    let resp = client
        .get("https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-25219.json")
        .send()?;
    Ok(resp.status().as_u16())
}

fn print_db_sources(json: bool) {
    if json {
        let rows: Vec<Value> = SCANROOK_DATA_SOURCES
            .iter()
            .map(|s| {
                serde_json::json!({
                    "source": s.source,
                    "provider": s.provider,
                    "ecosystems": s.ecosystems,
                    "kind": s.kind,
                    "status": s.status,
                    "notes": s.notes,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        );
        return;
    }
    println!("source\tprovider\tecosystems\tkind\tstatus\tnotes");
    for s in SCANROOK_DATA_SOURCES {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            s.source, s.provider, s.ecosystems, s.kind, s.status, s.notes
        );
    }
}

fn print_pg_cache_check() {
    let mut client = match vuln::pg_connect() {
        Some(c) => c,
        None => {
            println!("pg_cache=disabled reason=DATABASE_URL missing or connect failed");
            return;
        }
    };
    vuln::pg_init_schema(&mut client);
    let tables = [
        ("nvd_cve_cache", "nvd_last_modified"),
        ("osv_vuln_cache", "osv_last_modified"),
        ("redhat_csaf_cache", "redhat_last_modified"),
        ("redhat_cve_cache", "redhat_last_modified"),
    ];
    println!("pg_cache=enabled");
    for (table, lm_col) in tables {
        let sql = format!(
            "SELECT count(*)::BIGINT,\
             COALESCE(to_char(max(last_checked_at),'YYYY-MM-DD\"T\"HH24:MI:SSOF'),''),\
             COALESCE(to_char(max({}),'YYYY-MM-DD\"T\"HH24:MI:SSOF'),'')\
             FROM {}",
            lm_col, table
        );
        match client.query_one(&sql, &[]) {
            Ok(row) => {
                let count: i64 = row.get(0);
                let last_checked: String = row.get(1);
                let last_modified: String = row.get(2);
                println!(
                    "pg_table={} count={} last_checked={} last_modified={}",
                    table,
                    count,
                    if last_checked.is_empty() {
                        "-"
                    } else {
                        &last_checked
                    },
                    if last_modified.is_empty() {
                        "-"
                    } else {
                        &last_modified
                    }
                );
            }
            Err(e) => {
                println!("pg_table={} err={}", table, e);
            }
        }
    }
}

fn run_scan_warm(
    file: &str,
    mode: ScanMode,
    yara: Option<String>,
    nvd_api_key: Option<String>,
) -> anyhow::Result<()> {
    std::env::remove_var("SCANNER_SKIP_CACHE");
    let started = Instant::now();
    let report = build_scan_report_value(file, mode, yara, nvd_api_key, None)
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
    Ok(())
}

fn run_db_check(nvd_api_key: Option<&str>) -> anyhow::Result<()> {
    let dir = resolve_cache_dir();
    let stats = collect_local_cache_stats(&dir);
    println!("cache_dir={}", dir.display());
    println!("entries={}", stats.entries);
    println!("bytes={}", stats.bytes);
    println!("latest_epoch={}", fmt_epoch(stats.latest));
    println!(
        "enrich_flags nvd={} osv={} redhat={}",
        env_bool_default("SCANNER_NVD_ENRICH", true),
        env_bool_default("SCANNER_OSV_ENRICH", true),
        env_bool_default("SCANNER_REDHAT_ENRICH", true)
    );

    let client = db_http_client()?;
    let nvd = check_endpoint_nvd(&client, nvd_api_key);
    let osv = check_endpoint_osv(&client);
    let redhat = check_endpoint_redhat(&client);

    match nvd {
        Ok(code) => println!("source_check nvd status={}", code),
        Err(e) => println!("source_check nvd err={}", e),
    }
    match osv {
        Ok(code) => println!("source_check osv status={}", code),
        Err(e) => println!("source_check osv err={}", e),
    }
    match redhat {
        Ok(code) => println!("source_check redhat status={}", code),
        Err(e) => println!("source_check redhat err={}", e),
    }

    print_pg_cache_check();
    Ok(())
}

fn update_nvd_seed(client: &Client, nvd_api_key: Option<&str>, cve: &str) -> anyhow::Result<()> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        cve
    );
    let mut req = client.get(&url);
    if let Some(k) = nvd_api_key {
        req = req.header("apiKey", k);
    }
    let resp = req.send()?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("nvd status={}", resp.status()));
    }
    let json: Value = resp.json()?;
    let cache_tag = format!("cveId:{}", cve);
    let key = cache::cache_key(&["nvd", &cache_tag, &url]);
    let cache_dir = resolve_cache_dir();
    cache::cache_put(Some(cache_dir.as_path()), &key, json.to_string().as_bytes());

    if let Some(mut pg) = vuln::pg_connect() {
        vuln::pg_init_schema(&mut pg);
        let _ = pg.execute(
            "INSERT INTO nvd_cve_cache (cve_id, payload, last_checked_at, nvd_last_modified)\
             VALUES ($1, $2, NOW(), NULL)\
             ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), nvd_last_modified = EXCLUDED.nvd_last_modified",
            &[&cve, &json],
        );
    }
    println!("db_update nvd seed={} cache_key={}", cve, key);
    Ok(())
}

fn update_osv_seed(client: &Client, id: &str) -> anyhow::Result<()> {
    let url = format!("https://api.osv.dev/v1/vulns/{}", id);
    let resp = client.get(&url).send()?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("osv status={}", resp.status()));
    }
    let json: Value = resp.json()?;
    let key = cache::cache_key(&["osv_vuln", id]);
    let cache_dir = resolve_cache_dir();
    cache::cache_put(Some(cache_dir.as_path()), &key, json.to_string().as_bytes());

    if let Some(mut pg) = vuln::pg_connect() {
        vuln::pg_init_schema(&mut pg);
        let _ = pg.execute(
            "INSERT INTO osv_vuln_cache (vuln_id, payload, last_checked_at, osv_last_modified)\
             VALUES ($1, $2, NOW(), NULL)\
             ON CONFLICT (vuln_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), osv_last_modified = EXCLUDED.osv_last_modified",
            &[&id, &json],
        );
    }
    println!("db_update osv seed={} cache_key={}", id, key);
    Ok(())
}

fn update_redhat_seed(client: &Client, cve: &str, errata: Option<&str>) -> anyhow::Result<()> {
    let cve_url = format!(
        "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json",
        cve
    );
    let cve_resp = client.get(&cve_url).send()?;
    if !cve_resp.status().is_success() {
        return Err(anyhow::anyhow!("redhat cve status={}", cve_resp.status()));
    }
    let cve_json: Value = cve_resp.json()?;
    let cve_key = cache::cache_key(&["redhat_cve", cve]);
    let cache_dir = resolve_cache_dir();
    cache::cache_put(
        Some(cache_dir.as_path()),
        &cve_key,
        cve_json.to_string().as_bytes(),
    );

    if let Some(mut pg) = vuln::pg_connect() {
        vuln::pg_init_schema(&mut pg);
        let _ = pg.execute(
            "INSERT INTO redhat_cve_cache (cve_id, payload, last_checked_at, redhat_last_modified)\
             VALUES ($1, $2, NOW(), NULL)\
             ON CONFLICT (cve_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), redhat_last_modified = EXCLUDED.redhat_last_modified",
            &[&cve, &cve_json],
        );
    }
    println!("db_update redhat_cve seed={} cache_key={}", cve, cve_key);

    if let Some(id) = errata {
        let csaf_url = format!(
            "https://access.redhat.com/hydra/rest/securitydata/csaf/{}.json?isCompressed=false",
            id
        );
        let csaf_resp = client.get(&csaf_url).send()?;
        if !csaf_resp.status().is_success() {
            return Err(anyhow::anyhow!("redhat csaf status={}", csaf_resp.status()));
        }
        let csaf_json: Value = csaf_resp.json()?;
        let csaf_key = cache::cache_key(&["redhat_csaf", id]);
        cache::cache_put(
            Some(cache_dir.as_path()),
            &csaf_key,
            csaf_json.to_string().as_bytes(),
        );
        if let Some(mut pg) = vuln::pg_connect() {
            vuln::pg_init_schema(&mut pg);
            let _ = pg.execute(
                "INSERT INTO redhat_csaf_cache (errata_id, payload, last_checked_at, redhat_last_modified)\
                 VALUES ($1, $2, NOW(), NULL)\
                 ON CONFLICT (errata_id) DO UPDATE SET payload = EXCLUDED.payload, last_checked_at = NOW(), redhat_last_modified = EXCLUDED.redhat_last_modified",
                &[&id, &csaf_json],
            );
        }
        println!("db_update redhat_csaf seed={} cache_key={}", id, csaf_key);
    }
    Ok(())
}

fn run_db(
    command: DbCommands,
    yara: Option<String>,
    nvd_api_key: Option<String>,
) -> anyhow::Result<()> {
    match command {
        DbCommands::Status => {
            let dir = resolve_cache_dir();
            let stats = collect_local_cache_stats(&dir);
            println!("cache_dir={}", dir.display());
            println!("entries={}", stats.entries);
            println!("bytes={}", stats.bytes);
            println!("latest_epoch={}", fmt_epoch(stats.latest));
        }
        DbCommands::Check => {
            run_db_check(nvd_api_key.as_deref())?;
        }
        DbCommands::Sources { json } => {
            print_db_sources(json);
        }
        DbCommands::Clear => {
            clear_scanrook_cache()?;
            println!("cache_cleared path={}", resolve_cache_dir().display());
        }
        DbCommands::Update {
            source,
            file,
            mode,
            cve,
            errata,
        } => {
            if let Some(file) = file.as_deref() {
                run_scan_warm(file, mode, yara, nvd_api_key)?;
            } else {
                let client = db_http_client()?;
                let seed_cve = cve.as_deref().unwrap_or("CVE-2021-25219").to_string();
                let seed_errata = errata
                    .as_deref()
                    .map(|s| s.to_string())
                    .or_else(|| Some("RHSA-2022:8162".to_string()));
                match source {
                    DbSource::All => {
                        update_nvd_seed(&client, nvd_api_key.as_deref(), &seed_cve)?;
                        update_osv_seed(&client, &seed_cve)?;
                        update_redhat_seed(&client, &seed_cve, seed_errata.as_deref())?;
                    }
                    DbSource::Nvd => {
                        update_nvd_seed(&client, nvd_api_key.as_deref(), &seed_cve)?;
                    }
                    DbSource::Osv => {
                        update_osv_seed(&client, &seed_cve)?;
                    }
                    DbSource::Redhat => {
                        update_redhat_seed(&client, &seed_cve, seed_errata.as_deref())?;
                    }
                }
            }
        }
        DbCommands::Download { file, mode } | DbCommands::Warm { file, mode } => {
            run_scan_warm(&file, mode, yara, nvd_api_key)?;
        }
        DbCommands::Seed {
            from_pg,
            debian,
            rhel,
            epss,
            nvd,
            osv,
            distro,
            all,
        } => {
            let cache_dir = resolve_cache_dir();
            std::fs::create_dir_all(&cache_dir)?;
            set_dir_permissions_0700(&cache_dir);
            let mut seeded = 0usize;

            // Seed from PostgreSQL
            if from_pg || all {
                progress("db.seed.pg.start", "");
                match seed_cache_from_pg(&cache_dir) {
                    Ok(n) => {
                        progress("db.seed.pg.done", &format!("entries={}", n));
                        seeded += n;
                    }
                    Err(e) => {
                        progress("db.seed.pg.error", &format!("{}", e));
                        eprintln!("PostgreSQL seed failed: {}", e);
                    }
                }
            }

            // Debian Security Tracker
            if debian || all {
                progress("db.seed.debian.start", "");
                match vuln::debian_tracker_enrich_seed(&cache_dir) {
                    Ok(()) => {
                        progress("db.seed.debian.done", "ok");
                        seeded += 1;
                    }
                    Err(e) => {
                        progress("db.seed.debian.error", &format!("{}", e));
                        eprintln!("Debian tracker seed failed: {}", e);
                    }
                }
            }

            // Red Hat OVAL
            if rhel.is_some() || all {
                let versions: Vec<u32> = if let Some(v) = rhel {
                    vec![v]
                } else {
                    vec![7, 8, 9]
                };
                for v in versions {
                    progress("db.seed.oval.start", &format!("rhel{}", v));
                    let pkgs = vec![container::PackageCoordinate {
                        ecosystem: "redhat".into(),
                        name: "seed".into(),
                        version: format!("0-0.el{}", v),
                    }];
                    match redhat::fetch_redhat_oval(&pkgs, Some(&cache_dir)) {
                        Some(path) => {
                            progress("db.seed.oval.done", &path);
                            seeded += 1;
                        }
                        None => {
                            eprintln!("OVAL download failed for RHEL {}", v);
                        }
                    }
                }
            }

            // EPSS and KEV
            if epss || all {
                progress("db.seed.epss.start", "");
                let mut dummy_findings = Vec::new();
                vuln::epss_enrich_findings(&mut dummy_findings, Some(&cache_dir));
                vuln::kev_enrich_findings(&mut dummy_findings, Some(&cache_dir));
                progress("db.seed.epss.done", "ok");
                seeded += 1;
            }

            // NVD warm-up with sample CVE
            if nvd || all {
                progress("db.seed.nvd.start", "");
                let sample_cves = ["CVE-2021-44228", "CVE-2023-44487", "CVE-2024-3094"];
                for cve in &sample_cves {
                    let mut findings = vec![report::Finding {
                        id: cve.to_string(),
                        source_ids: vec![],
                        package: None,
                        confidence_tier: report::ConfidenceTier::ConfirmedInstalled,
                        evidence_source: report::EvidenceSource::InstalledDb,
                        accuracy_note: None,
                        fixed: None,
                        fixed_in: None,
                        recommendation: None,
                        severity: None,
                        cvss: None,
                        description: None,
                        evidence: vec![],
                        references: vec![],
                        confidence: None,
                        epss_score: None,
                        epss_percentile: None,
                        in_kev: None,
                    }];
                    let mut pg = vuln::pg_connect();
                    vuln::enrich_findings_with_nvd(
                        &mut findings,
                        nvd_api_key.as_deref(),
                        &mut pg,
                    );
                }
                progress("db.seed.nvd.done", "ok");
                seeded += sample_cves.len();
            }

            // OSV warm-up with sample packages
            if osv || all {
                progress("db.seed.osv.start", "");
                let sample_pkgs = vec![
                    container::PackageCoordinate {
                        ecosystem: "deb".into(),
                        name: "openssl".into(),
                        version: "3.0.0".into(),
                    },
                    container::PackageCoordinate {
                        ecosystem: "npm".into(),
                        name: "lodash".into(),
                        version: "4.17.0".into(),
                    },
                    container::PackageCoordinate {
                        ecosystem: "PyPI".into(),
                        name: "requests".into(),
                        version: "2.25.0".into(),
                    },
                ];
                let _results = vuln::osv_batch_query(&sample_pkgs);
                progress("db.seed.osv.done", "ok");
                seeded += sample_pkgs.len();
            }

            // Ubuntu USN + Alpine SecDB advisory feeds
            if distro || all {
                progress("db.seed.distro.start", "");
                vuln::seed_distro_feeds();
                progress("db.seed.distro.done", "ok");
                seeded += 1;
            }

            println!("seed_complete items_seeded={}", seeded);
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

fn looks_like_sbom_input(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".spdx.json")
        || lower.ends_with(".cyclonedx.json")
        || lower.ends_with(".cdx.json")
        || lower.ends_with(".sbom.json")
    {
        return true;
    }
    if !lower.ends_with(".json") {
        return false;
    }

    let mut f = match File::open(path) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut head = vec![0u8; 8192];
    let n = match f.read(&mut head) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if n == 0 {
        return false;
    }
    let text = String::from_utf8_lossy(&head[..n]).to_lowercase();
    text.contains("\"bomformat\"")
        || text.contains("\"spdxversion\"")
        || text.contains("\"artifacts\"")
}
