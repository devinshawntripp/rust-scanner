//! Pre-compiled SQLite vulnerability database for offline/fast scanning.
//!
//! The DB is downloaded via `scanrook db fetch` or built via `scanrook db build`.
//! During scans, the enrichment pipeline checks SQLite first, falling back to
//! live APIs for any misses.

mod build;
mod compress;
mod import;
mod schema;

pub use build::{build_full_db, fetch_db};
pub use schema::{
    db_build_date, get_metadata, has_dict_compression, open_vulndb, validate_vulndb, vulndb_path,
    query_alpine, query_debian, query_epss, query_kev, query_nvd_cve, query_osv_by_package,
    query_ubuntu,
};
