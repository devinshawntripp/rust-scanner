mod binary;
mod container;
mod license;
mod vuln;
mod redhat;
mod utils;
mod cache;
mod report;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use crate::utils::progress;

#[derive(Parser)]
#[command(name = "scanner")]
#[command(about = "A Rust-powered security scanner", long_about = None)]
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

#[derive(Subcommand)]
enum Commands {
    /// Smart scan: detect type (container tar, source tar, or binary) and report
    Scan {
        /// Path to file (tar/tar.gz/tar.bz2/bin)
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
    }
}

#[derive(Serialize)]
struct BinReport {
    scanner: &'static str,
    version: &'static str,
    target_path: String,
    file_type: String,
    sha256: String,
}

fn main() {
    let cli = Cli::parse();

    if let Some(dir) = &cli.cache_dir {
        std::env::set_var("SCANNER_CACHE", dir);
    }
    if cli.progress { std::env::set_var("SCANNER_PROGRESS_STDERR", "1"); }
    if let Some(p) = &cli.progress_file { std::env::set_var("SCANNER_PROGRESS_FILE", p); }

    match cli.command {
        Commands::Scan { file, format, out, refs, mode } => {
            progress("scan.start", &file);
            // Heuristic: tar? → container or source; default to container, fallback to source if no manifest
            let lower = file.to_lowercase();
            let mut report_json = None;
            if lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") || lower.ends_with(".tbz") {
                if let Some(r) = container::build_container_report(&file, mode.clone(), false, cli.nvd_api_key.clone(), cli.yara.clone()) {
                    report_json = Some(serde_json::to_value(r).unwrap());
                } else if let Some(r) = container::build_source_report(&file, cli.nvd_api_key.clone()) {
                    report_json = Some(serde_json::to_value(r).unwrap());
                }
            } else if let Some(r) = binary::build_binary_report(&file, mode.clone(), cli.yara.clone(), cli.nvd_api_key.clone()) {
                report_json = Some(serde_json::to_value(r).unwrap());
            }

            if let Some(mut v) = report_json {
                if !refs {
                    // Strip references array from each finding when refs flag not set
                    if let Some(arr) = v.get_mut("findings").and_then(|f| f.as_array_mut()) {
                        for f in arr.iter_mut() { f.as_object_mut().map(|o| o.remove("references")); }
                    }
                }
                let text = if matches!(format, OutputFormat::Json) { serde_json::to_string_pretty(&v).unwrap() } else { format!("{}", v) };
                println!("{}", text);
                utils::write_output_if_needed(&out, &text);
                let summary = v.get("summary").and_then(|s| s.as_object()).and_then(|o| o.get("total_findings")).and_then(|n| n.as_u64()).unwrap_or(0);
                progress("scan.done", &format!("file={} findings={}", file, summary));
            } else {
                eprintln!("Failed to detect or scan file: {}", file);
                progress("scan.error", &format!("file={}", file));
            }
        }
        Commands::Bin { path, format, out, mode } => {
            match format {
                OutputFormat::Text => binary::scan_binary(&path),
                OutputFormat::Json => {
                    if let Some(report) = binary::build_binary_report(&path, mode, None, cli.nvd_api_key.clone()) {
                        let json = serde_json::to_string_pretty(&report).unwrap();
                        println!("{}", json);
                        utils::write_output_if_needed(&out, &json);
                    }
                }
            }
        }
        Commands::Container { tar, mode, format, out, sbom, oval_redhat } => {
            container::scan_container(&tar, mode, format, cli.cache_dir.clone(), cli.yara.clone(), out, sbom, cli.nvd_api_key.clone(), oval_redhat);
        }
        Commands::Source { tar, format, out } => {
            container::scan_source_tarball(&tar, format, cli.nvd_api_key.clone(), out);
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
    }
}
