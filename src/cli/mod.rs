pub mod benchmark;
pub mod db;
pub mod detect;
pub mod diff;
pub mod helpers;
pub mod sbom_cmd;
pub mod text_report;
pub mod upgrade;

// Re-export commonly used items so callers can use crate::cli::*
pub use benchmark::run_benchmark;
pub use db::run_db;
pub use detect::build_scan_report_value;
pub use diff::run_diff;
pub use helpers::{
    nudge_seed_if_empty, resolve_yara_rules, set_dir_permissions_0700,
    strip_references_in_findings,
};
pub use sbom_cmd::run_sbom;
pub use upgrade::run_upgrade;
