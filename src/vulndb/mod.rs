//! Pre-compiled SQLite vulnerability database for offline/fast scanning.
//!
//! The DB is downloaded via `scanrook db fetch` or built via `scanrook db build`.
//! During scans, the enrichment pipeline checks SQLite first, falling back to
//! live APIs for any misses.

mod build;
pub(crate) mod compress;
mod import;
pub(crate) mod schema;

pub use build::{build_full_db, fetch_db};
pub use schema::{
    db_build_date, get_metadata, has_dict_compression, has_osv_package,
    has_osv_package_any_version, open_vulndb,
    query_osv_payload_by_id, validate_vulndb, vulndb_path,
    query_alpine, query_debian, query_epss, query_kev, query_nvd_cve, query_osv_by_package,
    query_osv_by_package_any_version, query_ubuntu,
};
