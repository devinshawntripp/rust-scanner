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

pub(crate) const CREATE_SCHEMA: &str = r#"
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
    get_metadata(conn, "build_date")
}

/// Generic metadata lookup by key.
pub fn get_metadata(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .ok()
}

/// Load a zstd dictionary blob from the metadata table.
/// Dict values are stored as BLOBs by Python's sqlite3.Binary() — read directly as Vec<u8>.
/// Used for keys like `nvd_zstd_dict` and `osv_zstd_dict`.
pub fn get_dict(conn: &Connection, key: &str) -> Option<Vec<u8>> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .ok()
}

/// Check if the database uses dictionary compression for payloads.
pub fn has_dict_compression(conn: &Connection) -> bool {
    get_metadata(conn, "dict_compression")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Look up a single NVD CVE by ID. Decompresses the payload blob and returns parsed JSON.
/// Uses dictionary decompression if `dict_compression=1` in metadata.
pub fn query_nvd_cve(conn: &Connection, cve_id: &str) -> Option<serde_json::Value> {
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM nvd_cves WHERE cve_id = ?1",
            params![cve_id],
            |row| row.get(0),
        )
        .ok()?;

    let json_bytes = decompress_nvd_payload(conn, &payload)?;
    serde_json::from_slice(&json_bytes).ok()
}

/// Query OSV vulnerabilities by package ecosystem and name.
/// Joins osv_vulns with osv_payloads, decompresses each payload, returns parsed JSON array.
pub fn query_osv_by_package(conn: &Connection, ecosystem: &str, name: &str) -> Vec<serde_json::Value> {
    let mut stmt = match conn.prepare(
        "SELECT p.payload FROM osv_vulns v
         JOIN osv_payloads p ON v.id = p.id
         WHERE v.ecosystem = ?1 AND v.name = ?2",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let use_dict = has_dict_compression(conn);
    let dict = if use_dict {
        get_dict(conn, "osv_zstd_dict")
    } else {
        None
    };

    let rows = stmt
        .query_map(params![ecosystem, name], |row| {
            let payload: Vec<u8> = row.get(0)?;
            Ok(payload)
        })
        .ok();

    let Some(rows) = rows else {
        return Vec::new();
    };

    rows.filter_map(|r| r.ok())
        .filter_map(|payload| {
            let json_bytes = if use_dict {
                if let Some(ref d) = dict {
                    super::compress::decompress_payload_with_dict(&payload, d)
                } else {
                    super::compress::decompress_payload(&payload)
                }
            } else {
                super::compress::decompress_payload(&payload)
            };
            json_bytes.and_then(|b| serde_json::from_slice(&b).ok())
        })
        .collect()
}

/// Look up EPSS score and percentile for a CVE. Returns (score, percentile).
pub fn query_epss(conn: &Connection, cve_id: &str) -> Option<(f32, f32)> {
    conn.query_row(
        "SELECT score, percentile FROM epss_scores WHERE cve_id = ?1",
        params![cve_id],
        |row| {
            let score: f64 = row.get(0)?;
            let percentile: f64 = row.get(1)?;
            Ok((score as f32, percentile as f32))
        },
    )
    .ok()
}

/// Check if a CVE exists in the Known Exploited Vulnerabilities catalog.
pub fn query_kev(conn: &Connection, cve_id: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM kev_entries WHERE cve_id = ?1",
        params![cve_id],
        |_| Ok(()),
    )
    .is_ok()
}

/// Check if a package (ecosystem, name) is indexed in the vulndb.
/// Returns true if the package exists in osv_packages, even if it has zero vulnerabilities.
/// This distinguishes "package not in DB" from "package has no known vulns."
pub fn has_osv_package(conn: &Connection, ecosystem: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM osv_packages WHERE ecosystem = ?1 AND name = ?2",
        params![ecosystem, name],
        |_| Ok(()),
    )
    .is_ok()
}

/// Look up a single OSV advisory/vulnerability by ID from osv_payloads.
/// Decompresses the payload blob (using dict if available) and returns parsed JSON.
/// Used by the enrichment pipeline to avoid HTTP fetches for advisories already in the vulndb.
pub fn query_osv_payload_by_id(conn: &Connection, id: &str) -> Option<serde_json::Value> {
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM osv_payloads WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .ok()?;

    let use_dict = has_dict_compression(conn);
    let json_bytes = if use_dict {
        if let Some(dict) = get_dict(conn, "osv_zstd_dict") {
            super::compress::decompress_payload_with_dict(&payload, &dict)
        } else {
            super::compress::decompress_payload(&payload)
        }
    } else {
        super::compress::decompress_payload(&payload)
    };
    json_bytes.and_then(|b| serde_json::from_slice(&b).ok())
}

/// Query Debian security tracker for a package in a specific release.
/// Returns Vec of (cve_id, status, fixed_version).
pub fn query_debian(conn: &Connection, package: &str, release: &str) -> Vec<(String, String, String)> {
    let mut stmt = match conn.prepare(
        "SELECT cve_id, status, COALESCE(fixed_version, '') FROM debian_tracker
         WHERE package = ?1 AND release = ?2",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    stmt.query_map(params![package, release], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })
    .ok()
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Query Ubuntu USN data for a package in a specific release.
/// Returns Vec of (cve_id, priority).
pub fn query_ubuntu(conn: &Connection, package: &str, release: &str) -> Vec<(String, String)> {
    let mut stmt = match conn.prepare(
        "SELECT cve_id, COALESCE(priority, '') FROM ubuntu_usn
         WHERE package = ?1 AND release = ?2",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    stmt.query_map(params![package, release], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
        ))
    })
    .ok()
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Query Alpine SecDB for a package in a specific branch.
/// Returns Vec of (cve_id, fixed_version).
pub fn query_alpine(conn: &Connection, package: &str, branch: &str) -> Vec<(String, String)> {
    let mut stmt = match conn.prepare(
        "SELECT cve_id, COALESCE(fixed_version, '') FROM alpine_secdb
         WHERE package = ?1 AND branch = ?2",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    stmt.query_map(params![package, branch], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
        ))
    })
    .ok()
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Helper: decompress an NVD payload blob, using dict if available.
fn decompress_nvd_payload(conn: &Connection, payload: &[u8]) -> Option<Vec<u8>> {
    if has_dict_compression(conn) {
        if let Some(dict) = get_dict(conn, "nvd_zstd_dict") {
            return super::compress::decompress_payload_with_dict(payload, &dict);
        }
    }
    super::compress::decompress_payload(payload)
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

/// Validate the vulndb after download. Checks for required metadata, table existence,
/// dictionary availability (if dict_compression enabled), and sample payload decompression.
pub fn validate_vulndb(conn: &Connection) -> anyhow::Result<()> {
    // Check schema_version exists
    if get_metadata(conn, "schema_version").is_none() {
        anyhow::bail!("vulndb missing 'schema_version' in metadata table");
    }

    // Check build_date exists
    if get_metadata(conn, "build_date").is_none() {
        anyhow::bail!("vulndb missing 'build_date' in metadata table");
    }

    // If dict_compression is enabled, verify dictionaries are present
    if has_dict_compression(conn) {
        if get_dict(conn, "nvd_zstd_dict").is_none() {
            anyhow::bail!("vulndb has dict_compression=1 but missing 'nvd_zstd_dict' dictionary");
        }
        if get_dict(conn, "osv_zstd_dict").is_none() {
            anyhow::bail!("vulndb has dict_compression=1 but missing 'osv_zstd_dict' dictionary");
        }
    }

    // Try decompressing a sample NVD payload if any exist
    let nvd_sample: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM nvd_cves LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();
    if let Some(payload) = nvd_sample {
        if decompress_nvd_payload(conn, &payload).is_none() {
            anyhow::bail!("vulndb validation: failed to decompress sample NVD payload");
        }
    }

    // Try decompressing a sample OSV payload if any exist
    let osv_sample: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM osv_payloads LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();
    if let Some(payload) = osv_sample {
        let use_dict = has_dict_compression(conn);
        let decompressed = if use_dict {
            if let Some(dict) = get_dict(conn, "osv_zstd_dict") {
                super::compress::decompress_payload_with_dict(&payload, &dict)
            } else {
                super::compress::decompress_payload(&payload)
            }
        } else {
            super::compress::decompress_payload(&payload)
        };
        if decompressed.is_none() {
            anyhow::bail!("vulndb validation: failed to decompress sample OSV payload");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that get_dict reads a BLOB value stored in metadata table directly as Vec<u8>.
    /// Python's sqlite3.Binary() stores the dict as raw binary, not as a hex-encoded string.
    #[test]
    fn test_get_dict_reads_blob() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();

        let raw_bytes: Vec<u8> = vec![0x01, 0x02, 0xAB, 0xCD, 0xFF, 0x00, 0x7F];
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            rusqlite::params!["test_dict", rusqlite::types::Value::Blob(raw_bytes.clone())],
        )
        .unwrap();

        let result = get_dict(&conn, "test_dict");
        assert!(result.is_some(), "get_dict should return Some for a BLOB value");
        assert_eq!(result.unwrap(), raw_bytes, "get_dict should return exact bytes stored as BLOB");
    }

    /// Test that validate_vulndb passes on a DB with dict_compression=0
    /// and that the pipeline works end-to-end with zstd-compressed payloads.
    #[test]
    fn test_validate_vulndb_with_dict_compression_0() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();

        // Set required metadata
        set_metadata(&conn, "schema_version", "2").unwrap();
        set_metadata(&conn, "build_date", "2026-03-05").unwrap();
        set_metadata(&conn, "dict_compression", "0").unwrap();

        // Insert a sample NVD payload (plain zstd-compressed JSON)
        let sample_json = br#"{"id": "CVE-2024-0001", "cvssMetricV31": []}"#;
        let compressed = super::super::compress::compress_json(sample_json);
        conn.execute(
            "INSERT OR REPLACE INTO nvd_cves (cve_id, payload, last_modified) VALUES (?1, ?2, ?3)",
            rusqlite::params!["CVE-2024-0001", compressed, "2026-03-05"],
        )
        .unwrap();

        // Insert a sample OSV payload (plain zstd-compressed JSON)
        let osv_json = br#"{"id": "GHSA-xxxx-yyyy-zzzz"}"#;
        let osv_compressed = super::super::compress::compress_json(osv_json);
        conn.execute(
            "INSERT OR REPLACE INTO osv_payloads (id, payload) VALUES (?1, ?2)",
            rusqlite::params!["GHSA-xxxx-yyyy-zzzz", osv_compressed],
        )
        .unwrap();

        let result = validate_vulndb(&conn);
        assert!(result.is_ok(), "validate_vulndb should pass on dict_compression=0 DB: {:?}", result.err());
    }

    #[test]
    fn test_has_osv_package_returns_true_for_indexed_package() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO osv_packages (ecosystem, name) VALUES (?1, ?2)",
            params!["PyPI", "requests"],
        ).unwrap();
        assert!(has_osv_package(&conn, "PyPI", "requests"));
    }

    #[test]
    fn test_has_osv_package_returns_false_for_unknown_package() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();
        assert!(!has_osv_package(&conn, "PyPI", "nonexistent-pkg"));
    }

    #[test]
    fn test_has_osv_package_distinguishes_ecosystem() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO osv_packages (ecosystem, name) VALUES (?1, ?2)",
            params!["npm", "lodash"],
        ).unwrap();
        assert!(has_osv_package(&conn, "npm", "lodash"));
        assert!(!has_osv_package(&conn, "PyPI", "lodash"));
    }

    #[test]
    fn test_query_osv_payload_by_id_returns_decompressed_json() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();
        set_metadata(&conn, "schema_version", "2").unwrap();
        set_metadata(&conn, "dict_compression", "0").unwrap();

        let osv_json = br#"{"id": "GHSA-1234-5678-abcd", "summary": "Test vuln"}"#;
        let compressed = super::super::compress::compress_json(osv_json);
        conn.execute(
            "INSERT INTO osv_payloads (id, payload) VALUES (?1, ?2)",
            params!["GHSA-1234-5678-abcd", compressed],
        ).unwrap();

        let result = query_osv_payload_by_id(&conn, "GHSA-1234-5678-abcd");
        assert!(result.is_some());
        let json = result.unwrap();
        assert_eq!(json["id"].as_str().unwrap(), "GHSA-1234-5678-abcd");
        assert_eq!(json["summary"].as_str().unwrap(), "Test vuln");
    }

    #[test]
    fn test_query_osv_payload_by_id_returns_none_for_missing() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();
        set_metadata(&conn, "dict_compression", "0").unwrap();
        assert!(query_osv_payload_by_id(&conn, "GHSA-nonexistent").is_none());
    }

    #[test]
    fn test_query_osv_payload_by_id_with_debian_advisory() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();
        set_metadata(&conn, "dict_compression", "0").unwrap();

        let dla_json = br#"{"id": "DLA-3879-1", "aliases": ["CVE-2024-1234", "CVE-2024-5678"], "summary": "Debian advisory"}"#;
        let compressed = super::super::compress::compress_json(dla_json);
        conn.execute(
            "INSERT INTO osv_payloads (id, payload) VALUES (?1, ?2)",
            params!["DLA-3879-1", compressed],
        ).unwrap();

        let result = query_osv_payload_by_id(&conn, "DLA-3879-1");
        assert!(result.is_some());
        let json = result.unwrap();
        let aliases = json["aliases"].as_array().unwrap();
        assert_eq!(aliases.len(), 2);
    }

    /// Simulates the batch.rs scenario: package IS indexed in osv_packages
    /// but has zero vulnerabilities. query_osv_by_package returns empty vec,
    /// but has_osv_package returns true — this is a valid "clean" result.
    #[test]
    fn test_indexed_package_with_no_vulns_is_distinguishable() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();

        // Package is indexed (exists in osv_packages)...
        conn.execute(
            "INSERT INTO osv_packages (ecosystem, name) VALUES (?1, ?2)",
            params!["Debian:11", "zlib"],
        ).unwrap();
        // ...but has no vulnerability entries in osv_vulns

        // has_osv_package should return true (it's indexed)
        assert!(has_osv_package(&conn, "Debian:11", "zlib"),
            "indexed package should be found even with zero vulns");

        // query_osv_by_package should return empty vec (no vulns)
        let vulns = query_osv_by_package(&conn, "Debian:11", "zlib");
        assert!(vulns.is_empty(),
            "package with no vulns should return empty vec");
    }
}
