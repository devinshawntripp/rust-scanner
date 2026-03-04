//! SQLite vulndb schema, path helpers, and DB lifecycle functions.

use rusqlite::{params, Connection, OpenFlags};
use std::path::PathBuf;

/// Current schema version -- bump when adding tables or changing columns.
pub(super) const SCHEMA_VERSION: &str = "2";

// --- Path helpers ---

/// Default vulndb path: `~/.scanrook/db/scanrook.db`
pub fn vulndb_path() -> PathBuf {
    if let Ok(p) = std::env::var("SCANROOK_DB") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".scanrook")
        .join("db")
        .join("scanrook.db")
}

/// Open the vulndb if it exists on disk. Returns None if absent or corrupt.
pub fn open_vulndb() -> Option<Connection> {
    let path = vulndb_path();
    if !path.exists() {
        return None;
    }
    Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
}

// --- Schema ---

pub(super) const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS osv_packages (ecosystem TEXT, name TEXT, PRIMARY KEY (ecosystem, name));

CREATE TABLE IF NOT EXISTS osv_vulns (
    id TEXT, ecosystem TEXT, name TEXT,
    modified TEXT,
    PRIMARY KEY (id, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_osv_eco_name ON osv_vulns (ecosystem, name);

CREATE TABLE IF NOT EXISTS osv_payloads (
    id TEXT PRIMARY KEY,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id TEXT PRIMARY KEY,
    payload BLOB NOT NULL,
    last_modified TEXT
);

CREATE TABLE IF NOT EXISTS epss_scores (cve_id TEXT PRIMARY KEY, score REAL, percentile REAL);

CREATE TABLE IF NOT EXISTS kev_entries (cve_id TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS debian_tracker (
    cve_id TEXT, package TEXT, release TEXT,
    status TEXT, urgency TEXT, fixed_version TEXT,
    PRIMARY KEY (cve_id, package, release)
);
CREATE INDEX IF NOT EXISTS idx_debian_pkg_release ON debian_tracker (package, release);

CREATE TABLE IF NOT EXISTS ubuntu_usn (
    cve_id TEXT NOT NULL, package TEXT NOT NULL, release TEXT NOT NULL,
    status TEXT, priority TEXT,
    PRIMARY KEY (cve_id, package, release)
);
CREATE INDEX IF NOT EXISTS idx_ubuntu_pkg_release ON ubuntu_usn (package, release);

CREATE TABLE IF NOT EXISTS alpine_secdb (
    cve_id TEXT NOT NULL, package TEXT NOT NULL, branch TEXT NOT NULL,
    repo TEXT NOT NULL, fixed_version TEXT,
    PRIMARY KEY (cve_id, package, branch, repo)
);
CREATE INDEX IF NOT EXISTS idx_alpine_pkg_branch ON alpine_secdb (package, branch);
"#;

// --- Query functions ---

/// Get the build date from metadata.
pub fn db_build_date(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = 'build_date'",
        [],
        |row| row.get(0),
    )
    .ok()
}

// --- DB creation & metadata ---

/// Create a new empty vulndb at the given path with the full schema.
pub fn create_db(path: &std::path::Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove existing file to start fresh
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let conn = Connection::open(path)?;
    // Use DELETE journal mode for bulk builds -- WAL creates a separate file that can grow to 20GB+.
    // After build completes, optimize_db() will switch to WAL for read performance.
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-64000;")?;
    conn.execute_batch(CREATE_SCHEMA)?;
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?1)",
        params![SCHEMA_VERSION],
    )?;
    Ok(conn)
}

/// Set metadata key/value pair.
pub fn set_metadata(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

/// VACUUM and optimize the database after bulk imports.
pub fn optimize_db(conn: &Connection) -> anyhow::Result<()> {
    // Skip VACUUM -- it rewrites the entire multi-GB DB and can OOM nodes.
    // The DB works fine without it, just slightly larger on disk.
    conn.execute_batch("PRAGMA optimize; PRAGMA journal_mode=WAL;")?;
    Ok(())
}

/// Validate the vulndb after download. Checks for required metadata and table existence.
pub fn validate_vulndb(conn: &Connection) -> anyhow::Result<()> {
    // Check schema_version exists
    let schema_version: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .ok();
    if schema_version.is_none() {
        anyhow::bail!("vulndb missing 'schema_version' in metadata table");
    }

    // Check build_date exists
    let build_date: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'build_date'",
            [],
            |row| row.get(0),
        )
        .ok();
    if build_date.is_none() {
        anyhow::bail!("vulndb missing 'build_date' in metadata table");
    }

    Ok(())
}
