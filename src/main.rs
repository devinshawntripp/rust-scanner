mod archive;
mod binary;
mod cache;
mod cli;
mod container;
mod iso;
mod license;
mod progress;
mod redhat;
mod report;
mod sbom;
mod usercli;
mod utils;
mod vuln;
mod vulndb;

use crate::cli::{
    build_scan_report_value, nudge_seed_if_empty, resolve_yara_rules,
    run_benchmark, run_db, run_diff, set_dir_permissions_0700, strip_references_in_findings,
};
use crate::utils::progress;
use clap::{Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;

/// Default YARA rules bundled with the scanner binary.
#[cfg(feature = "yara")]
const DEFAULT_YARA_RULES: &str = include_str!("../rules/default.yar");

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
    /// Check for updates and upgrade scanrook to the latest version
    Upgrade {
        /// Only check for updates without installing
        #[arg(long, default_value_t = false)]
        check: bool,
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
pub enum DbCommands {
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
    /// Build the pre-compiled SQLite vulnerability database from bulk sources
    Build {
        /// Output path for the SQLite database
        #[arg(long, default_value = "scanrook-db.sqlite")]
        output: String,
    },
    /// Fetch the latest pre-compiled vulndb from ScanRook servers
    Fetch {
        /// Force re-download even if local DB is up-to-date
        #[arg(long, default_value_t = false)]
        force: bool,
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
    // Set up progress file BEFORE anything that calls progress() — nudge_seed_if_empty()
    // triggers OnceLock initialization of PROGRESS_FILE_HANDLE via progress(). If the env
    // var isn't set yet, the OnceLock permanently resolves to None and the file stays empty.
    if let Some(p) = &cli.progress_file {
        std::env::set_var("SCANNER_PROGRESS_FILE", p);
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p);
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

    // Nudge user to run `db seed` if cache is empty on first scan.
    // Must come AFTER progress file setup so events are written to the file.
    if matches!(
        &cli.command,
        Commands::Scan { .. } | Commands::Container { .. }
    ) {
        nudge_seed_if_empty();
    }

    if cli.progress_file.is_some() {
        utils::progress("scanner.init", "initializing");
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

    if vuln::cluster_mode() {
        progress(
            "scanner.cluster_mode",
            "enabled -- using PostgreSQL enrichment, file cache disabled",
        );
    }

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
        },
        Commands::Upgrade { check } => {
            let current = env!("CARGO_PKG_VERSION");
            let repo = "devinshawntripp/rust-scanner";
            let url = format!("https://api.github.com/repos/{}/releases/latest", repo);
            let client = reqwest::blocking::Client::builder()
                .user_agent(format!("scanrook-cli/{}", current))
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("failed to build HTTP client");
            let resp = match client.get(&url).send() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to check for updates: {}", e);
                    std::process::exit(1);
                }
            };
            let body: serde_json::Value = match resp.json() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to parse release metadata: {}", e);
                    std::process::exit(1);
                }
            };
            let latest = body["tag_name"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches('v');
            if latest.is_empty() {
                eprintln!("No published release found for {}", repo);
                std::process::exit(1);
            }
            if latest == current {
                println!("scanrook {} is already up to date", current);
                std::process::exit(0);
            }
            println!("Current version: {}", current);
            println!("Latest version:  {}", latest);
            if check {
                println!("Update available. Run `scanrook upgrade` to install.");
                std::process::exit(0);
            }
            // Determine platform
            let os = if cfg!(target_os = "macos") {
                "darwin"
            } else {
                "linux"
            };
            let arch = if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "amd64"
            };
            let asset = format!("scanrook-{}-{}-{}.tar.gz", latest, os, arch);
            let asset_url = format!(
                "https://github.com/{}/releases/download/v{}/{}",
                repo, latest, asset
            );
            println!("Downloading {} ...", asset);
            let dl = match client.get(&asset_url).send() {
                Ok(r) if r.status().is_success() => r.bytes().unwrap_or_default(),
                Ok(r) => {
                    eprintln!("Download failed: HTTP {}", r.status());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Download failed: {}", e);
                    std::process::exit(1);
                }
            };
            // Extract tarball to temp dir
            let tmp = tempfile::tempdir().expect("failed to create temp dir");
            let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&dl));
            let mut archive = tar::Archive::new(gz);
            if let Err(e) = archive.unpack(tmp.path()) {
                eprintln!("Failed to extract archive: {}", e);
                std::process::exit(1);
            }
            let new_bin = tmp.path().join("scanrook");
            if !new_bin.exists() {
                eprintln!("Archive missing scanrook binary");
                std::process::exit(1);
            }
            // Replace current binary
            let current_exe =
                std::env::current_exe().expect("cannot determine current executable path");
            let backup = current_exe.with_extension("old");
            if let Err(e) = std::fs::rename(&current_exe, &backup) {
                eprintln!("Failed to backup current binary: {}", e);
                eprintln!("Try running with sudo: sudo scanrook upgrade");
                std::process::exit(1);
            }
            if let Err(e) = std::fs::copy(&new_bin, &current_exe) {
                // Restore backup
                let _ = std::fs::rename(&backup, &current_exe);
                eprintln!("Failed to install new binary: {}", e);
                eprintln!("Try running with sudo: sudo scanrook upgrade");
                std::process::exit(1);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755));
            }
            let _ = std::fs::remove_file(&backup);
            println!("Upgraded scanrook {} -> {}", current, latest);
        }
    }
}
