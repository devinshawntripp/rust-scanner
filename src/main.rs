mod archive;
mod binary;
mod cache;
mod cli;
mod container;
mod iso;
mod k8s;
mod license;
mod plan;
mod progress;
mod redhat;
mod report;
mod sbom;
mod usercli;
mod utils;
mod vuln;
mod vulndb;

use crate::cli::{
    build_scan_report_value, nudge_seed_if_empty, resolve_yara_rules, run_benchmark, run_db,
    run_diff, run_sbom, run_upgrade, set_dir_permissions_0700, strip_references_in_findings,
};
use crate::utils::progress;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
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
    Ndjson,
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

#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum SbomExportFormat {
    Cyclonedx,
    Spdx,
    Syft,
}

#[derive(Subcommand)]
pub(crate) enum SbomCommands {
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
    /// Export a scan report as a standard SBOM (CycloneDX, SPDX, or Syft JSON)
    Export {
        /// Path to the scanner report JSON
        #[arg(long)]
        report: String,
        /// Output SBOM format
        #[arg(long, value_enum)]
        sbom_format: SbomExportFormat,
        /// Output file path
        #[arg(long)]
        out: Option<String>,
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
        #[arg(short = 'f', long = "file", alias = "path")]
        file: String,
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
    /// Scan all container images running in a Kubernetes cluster
    K8s {
        /// Path to kubeconfig file (default: ~/.kube/config or KUBECONFIG env)
        #[arg(long)]
        kubeconfig: Option<String>,
        /// Kubernetes context to use
        #[arg(long)]
        context: Option<String>,
        /// Namespace to scan (default: all namespaces)
        #[arg(short, long)]
        namespace: Option<String>,
        /// Output format
        #[arg(long, default_value = "text")]
        format: String,
        /// Output file for JSON format
        #[arg(long)]
        out: Option<String>,
        /// Scan mode
        #[arg(long, default_value = "light")]
        mode: String,
        /// Only list images without scanning
        #[arg(long)]
        list_only: bool,
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

    // Fetch plan and apply enrichment gates for scan commands.
    // Skip plan enforcement in cluster mode (worker always has full access).
    let user_plan = if !vuln::cluster_mode() {
        let p = plan::get_plan();
        if matches!(
            &cli.command,
            Commands::Scan { .. } | Commands::Container { .. } | Commands::Sbom { .. }
        ) {
            plan::apply_plan_enrichment_gates(&p);
        }
        Some(p)
    } else {
        None
    };

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
            // Gate output format by plan tier
            if let Some(ref p) = user_plan {
                let fmt_name = match &format {
                    OutputFormat::Json => "json",
                    OutputFormat::Ndjson => "ndjson",
                    OutputFormat::Text => "text",
                };
                if let Err(msg) = plan::check_output_format(p, fmt_name) {
                    eprintln!("{}", msg);
                    std::process::exit(1);
                }
            }
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

                let text = match format {
                    OutputFormat::Json => serde_json::to_string_pretty(&v).unwrap(),
                    OutputFormat::Ndjson => crate::report::value_to_ndjson(&v),
                    OutputFormat::Text => crate::cli::text_report::render_text_report(&v),
                };
                print!("{}", text);
                utils::write_output_if_needed(&out, &text);
            } else {
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
        } => {
            // Gate output format by plan tier
            if let Some(ref p) = user_plan {
                let fmt_name = match &format {
                    OutputFormat::Json => "json",
                    OutputFormat::Ndjson => "ndjson",
                    OutputFormat::Text => "text",
                };
                if let Err(msg) = plan::check_output_format(p, fmt_name) {
                    eprintln!("{}", msg);
                    std::process::exit(1);
                }
            }
            match format {
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
            OutputFormat::Ndjson => {
                if let Some(report) =
                    binary::build_binary_report(&path, mode, None, nvd_api_key.clone())
                {
                    let mut buf = Vec::new();
                    report::NdjsonWriter::new(&mut buf)
                        .write_report(&report)
                        .unwrap();
                    let text = String::from_utf8(buf).unwrap();
                    print!("{}", text);
                    utils::write_output_if_needed(&out, &text);
                }
            }
        }},
        Commands::Container {
            tar,
            mode,
            format,
            out,
            sbom,
            oval_redhat,
        } => {
            // Gate output format by plan tier
            if let Some(ref p) = user_plan {
                let fmt_name = match &format {
                    OutputFormat::Json => "json",
                    OutputFormat::Ndjson => "ndjson",
                    OutputFormat::Text => "text",
                };
                if let Err(msg) = plan::check_output_format(p, fmt_name) {
                    eprintln!("{}", msg);
                    std::process::exit(1);
                }
            }
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
        Commands::License { file } => {
            license::detect_license(&file);
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
                // Refresh plan cache after successful login
                plan::refresh_plan_cache();
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
        Commands::Sbom { command } => {
            if let Err(e) = run_sbom(command, nvd_api_key.clone()) {
                eprintln!("sbom command failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Upgrade { check } => {
            if let Err(e) = run_upgrade(check) {
                eprintln!("upgrade failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::K8s {
            kubeconfig,
            context,
            namespace,
            format,
            out,
            mode,
            list_only,
        } => {
            progress("k8s.discover.start", "Connecting to cluster...");

            let workloads = k8s::discover_workloads(
                kubeconfig.as_deref(),
                context.as_deref(),
                namespace.as_deref(),
            )
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            });

            let images = k8s::unique_images(&workloads);

            progress(
                "k8s.discover.done",
                &format!(
                    "Found {} workloads with {} unique images",
                    workloads.len(),
                    images.len()
                ),
            );

            // Print workload summary
            for w in &workloads {
                for c in &w.containers {
                    println!("{}/{} {} -> {}", w.namespace, w.name, c.name, c.image);
                }
            }

            if list_only {
                if format == "json" {
                    let json = serde_json::json!({
                        "workloads": workloads,
                        "unique_images": images,
                    });
                    if let Some(path) = &out {
                        std::fs::write(path, serde_json::to_string_pretty(&json).unwrap())
                            .unwrap();
                    } else {
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    }
                }
                return;
            }

            // Scan each unique image
            let scan_mode = if mode == "deep" {
                ScanMode::Deep
            } else {
                ScanMode::Light
            };
            let mut image_results: Vec<k8s::ImageScanResult> = Vec::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let total_workloads = workloads.len();
            let total_images = images.len();

            for (idx, image) in images.iter().enumerate() {
                progress(
                    "k8s.scan.start",
                    &format!("{}/{} {}", idx + 1, total_images, image),
                );

                let tar_path = temp_dir.path().join(format!("image-{}.tar", idx));
                let tar_str = tar_path.to_string_lossy().to_string();

                match k8s::pull_and_save_image(image, &tar_str) {
                    Ok(()) => {
                        let report = build_scan_report_value(
                            &tar_str,
                            scan_mode.clone(),
                            None,
                            nvd_api_key.clone(),
                            None,
                        );

                        if let Some(r) = report {
                            let findings =
                                r["findings"].as_array().map(|a| a.len()).unwrap_or(0);
                            let summary = &r["summary"];
                            let sc = &summary["severity_counts"];

                            let using_workloads: Vec<String> = workloads
                                .iter()
                                .filter(|w| w.containers.iter().any(|c| c.image == *image))
                                .map(|w| format!("{}/{}", w.namespace, w.name))
                                .collect();

                            image_results.push(k8s::ImageScanResult {
                                image: image.clone(),
                                workloads: using_workloads,
                                total_findings: findings,
                                critical: sc["Critical"].as_u64().unwrap_or(0) as usize,
                                high: sc["High"].as_u64().unwrap_or(0) as usize,
                                medium: sc["Medium"].as_u64().unwrap_or(0) as usize,
                                low: sc["Low"].as_u64().unwrap_or(0) as usize,
                                scan_error: None,
                            });

                            progress(
                                "k8s.scan.done",
                                &format!("{} findings={}", image, findings),
                            );
                        } else {
                            image_results.push(k8s::ImageScanResult {
                                image: image.clone(),
                                workloads: vec![],
                                total_findings: 0,
                                critical: 0,
                                high: 0,
                                medium: 0,
                                low: 0,
                                scan_error: Some("Scan produced no report".to_string()),
                            });
                        }

                        // Clean up tar to save disk
                        let _ = std::fs::remove_file(&tar_path);
                    }
                    Err(e) => {
                        progress("k8s.scan.error", &format!("{}: {}", image, e));
                        image_results.push(k8s::ImageScanResult {
                            image: image.clone(),
                            workloads: vec![],
                            total_findings: 0,
                            critical: 0,
                            high: 0,
                            medium: 0,
                            low: 0,
                            scan_error: Some(e),
                        });
                    }
                }
            }

            // Build summary
            let total_findings: usize =
                image_results.iter().map(|r| r.total_findings).sum();
            let total_critical: usize = image_results.iter().map(|r| r.critical).sum();
            let total_high: usize = image_results.iter().map(|r| r.high).sum();
            let images_with_critical: Vec<String> = image_results
                .iter()
                .filter(|r| r.critical > 0)
                .map(|r| r.image.clone())
                .collect();

            let namespaces_scanned: Vec<String> = workloads
                .iter()
                .map(|w| w.namespace.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            let cluster_report = k8s::ClusterScanReport {
                cluster_context: context.unwrap_or_else(|| "default".to_string()),
                namespaces_scanned,
                workloads,
                unique_images: images,
                image_reports: image_results,
                summary: k8s::ClusterSummary {
                    total_workloads,
                    total_images,
                    total_findings,
                    critical: total_critical,
                    high: total_high,
                    images_with_critical,
                },
            };

            // Output
            if format == "json" {
                let json = serde_json::to_string_pretty(&cluster_report).unwrap();
                if let Some(path) = &out {
                    std::fs::write(path, &json).unwrap();
                    progress("k8s.report", &format!("Saved to {}", path));
                } else {
                    println!("{}", json);
                }
            } else {
                println!("\n=== Cluster Scan Summary ===");
                println!("Workloads: {}", cluster_report.summary.total_workloads);
                println!("Unique images: {}", cluster_report.summary.total_images);
                println!(
                    "Total findings: {}",
                    cluster_report.summary.total_findings
                );
                println!("  Critical: {}", cluster_report.summary.critical);
                println!("  High: {}", cluster_report.summary.high);
                if !cluster_report.summary.images_with_critical.is_empty() {
                    println!("\nImages with CRITICAL findings:");
                    for img in &cluster_report.summary.images_with_critical {
                        println!("  - {}", img);
                    }
                }
                println!("\nPer-image results:");
                for r in &cluster_report.image_reports {
                    if let Some(err) = &r.scan_error {
                        println!("  {} -- ERROR: {}", r.image, err);
                    } else {
                        println!(
                            "  {} -- {} findings (C:{} H:{} M:{} L:{})",
                            r.image,
                            r.total_findings,
                            r.critical,
                            r.high,
                            r.medium,
                            r.low
                        );
                        for w in &r.workloads {
                            println!("    used by: {}", w);
                        }
                    }
                }
            }
        }
    }
}
