//! Build and fetch functions for downloading bulk data sources and creating the vulndb.

use super::import::*;
use super::schema::*;
use crate::utils::progress;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::io::{IsTerminal, Read, Write};

/// Known OSV ecosystem GCS zip names mapped to our ecosystem identifiers.
pub fn osv_ecosystem_zips() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Alpine", "Alpine"),
        ("Debian", "Debian"),
        ("Ubuntu", "Ubuntu"),
        ("AlmaLinux", "AlmaLinux"),
        ("Rocky Linux", "Rocky Linux"),
        ("SUSE", "SUSE"),
        ("Red Hat", "Red Hat"),
        ("crates.io", "crates.io"),
        ("Go", "Go"),
        ("npm", "npm"),
        ("PyPI", "PyPI"),
        ("Maven", "Maven"),
        ("NuGet", "NuGet"),
        ("Packagist", "Packagist"),
        ("RubyGems", "RubyGems"),
        ("Hex", "Hex"),
        ("Pub", "Pub"),
        ("SwiftURL", "SwiftURL"),
        ("Linux", "Linux"),
        ("OSS-Fuzz", "OSS-Fuzz"),
        ("GSD", "GSD"),
        ("GitHub Actions", "GitHub Actions"),
        ("Chainguard", "Chainguard"),
        ("Wolfi", "Wolfi"),
    ]
}

/// Alpine SecDB branches to fetch.
pub fn alpine_branches() -> Vec<&'static str> {
    vec!["v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "edge"]
}

/// Download all OSV ecosystems from GCS and import them.
pub fn build_osv(conn: &rusqlite::Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let mut total = 0usize;
    for (eco_name, eco_id) in osv_ecosystem_zips() {
        let url = format!(
            "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip",
            urlencoding::encode(eco_name)
        );
        progress(
            "vulndb.build.osv.download",
            &format!("ecosystem={}", eco_name),
        );
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes()?;
                match import_osv_ecosystem(conn, eco_id, &bytes) {
                    Ok(n) => {
                        progress(
                            "vulndb.build.osv.imported",
                            &format!("ecosystem={} vulns={}", eco_name, n),
                        );
                        total += n;
                    }
                    Err(e) => {
                        progress(
                            "vulndb.build.osv.error",
                            &format!("ecosystem={} err={}", eco_name, e),
                        );
                    }
                }
            }
            Ok(resp) => {
                progress(
                    "vulndb.build.osv.skip",
                    &format!("ecosystem={} status={}", eco_name, resp.status()),
                );
            }
            Err(e) => {
                progress(
                    "vulndb.build.osv.error",
                    &format!("ecosystem={} err={}", eco_name, e),
                );
            }
        }
    }
    Ok(total)
}

/// Download all NVD CVEs via paginated API and import them.
pub fn build_nvd(
    conn: &rusqlite::Connection,
    client: &reqwest::blocking::Client,
    api_key: Option<&str>,
) -> anyhow::Result<usize> {
    let mut total = 0usize;
    let mut start_index = 0u64;
    let results_per_page = 2000u64;
    loop {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={}&resultsPerPage={}",
            start_index, results_per_page
        );
        let mut req = client.get(&url);
        if let Some(key) = api_key {
            req = req.header("apiKey", key);
        }
        progress(
            "vulndb.build.nvd.page",
            &format!("start_index={}", start_index),
        );
        match req.send() {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes()?;
                let page_count = import_nvd_page(conn, &bytes)?;
                total += page_count;
                let val: Value = serde_json::from_slice(&bytes)?;
                let total_results = val
                    .get("totalResults")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                start_index += results_per_page;
                if start_index >= total_results {
                    break;
                }
                let sleep_ms = if api_key.is_some() { 600 } else { 6000 };
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            }
            Ok(resp) => {
                let status = resp.status();
                if status.as_u16() == 403 || status.as_u16() == 429 {
                    progress(
                        "vulndb.build.nvd.rate_limit",
                        &format!("status={} sleeping 30s", status),
                    );
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    continue;
                }
                progress("vulndb.build.nvd.error", &format!("status={}", status));
                break;
            }
            Err(e) => {
                progress("vulndb.build.nvd.error", &format!("{}", e));
                break;
            }
        }
    }
    Ok(total)
}

/// Download EPSS CSV and import.
pub fn build_epss(conn: &rusqlite::Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let url = "https://epss.cyentia.com/epss_scores-current.csv.gz";
    progress("vulndb.build.epss.download", url);
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("EPSS download failed: {}", resp.status());
    }
    let gz_bytes = resp.bytes()?;
    let mut decoder = GzDecoder::new(&gz_bytes[..]);
    let mut csv_bytes = Vec::new();
    decoder.read_to_end(&mut csv_bytes)?;
    let count = import_epss_csv(conn, &csv_bytes)?;
    progress("vulndb.build.epss.done", &format!("scores={}", count));
    Ok(count)
}

/// Download KEV catalog and import.
pub fn build_kev(conn: &rusqlite::Connection, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    progress("vulndb.build.kev.download", url);
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("KEV download failed: {}", resp.status());
    }
    let bytes = resp.bytes()?;
    let count = import_kev_json(conn, &bytes)?;
    progress("vulndb.build.kev.done", &format!("entries={}", count));
    Ok(count)
}

/// Download Debian Security Tracker and import.
pub fn build_debian(
    conn: &rusqlite::Connection,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<usize> {
    let url = "https://security-tracker.debian.org/tracker/data/json";
    progress("vulndb.build.debian.download", url);
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("Debian tracker download failed: {}", resp.status());
    }
    let bytes = resp.bytes()?;
    let count = import_debian_tracker(conn, &bytes)?;
    progress("vulndb.build.debian.done", &format!("entries={}", count));
    Ok(count)
}

/// Download Ubuntu USN data and import.
pub fn build_ubuntu(
    conn: &rusqlite::Connection,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<usize> {
    let mut total = 0usize;
    let mut offset = 0u64;
    loop {
        let page_url = format!(
            "https://ubuntu.com/security/notices.json?limit=500&offset={}",
            offset
        );
        match client.get(&page_url).send() {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes()?;
                let val: Value = serde_json::from_slice(&bytes)?;
                let notices = val.get("notices").and_then(|n| n.as_array());
                if let Some(notices_arr) = notices {
                    if notices_arr.is_empty() {
                        break;
                    }
                    let tx = conn.unchecked_transaction()?;
                    for notice in notices_arr {
                        let cves = notice
                            .get("cves")
                            .and_then(|c| c.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let priority = notice
                            .get("priority")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let packages = notice
                            .get("packages")
                            .and_then(|p| p.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let releases = notice
                            .get("releases")
                            .and_then(|r| r.as_array())
                            .cloned()
                            .unwrap_or_default();
                        for cve_val in &cves {
                            let cve_id = cve_val
                                .get("id")
                                .and_then(|v| v.as_str())
                                .or_else(|| cve_val.as_str())
                                .unwrap_or_default();
                            if cve_id.is_empty() || !cve_id.starts_with("CVE-") {
                                continue;
                            }
                            for pkg_val in &packages {
                                let pkg_name = pkg_val
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .or_else(|| pkg_val.as_str())
                                    .unwrap_or_default();
                                if pkg_name.is_empty() {
                                    continue;
                                }
                                for rel_val in &releases {
                                    let release = rel_val
                                        .get("codename")
                                        .and_then(|c| c.as_str())
                                        .or_else(|| rel_val.as_str())
                                        .unwrap_or_default();
                                    if release.is_empty() {
                                        continue;
                                    }
                                    tx.execute(
                                        "INSERT OR REPLACE INTO ubuntu_usn (cve_id, package, release, status, priority) VALUES (?1, ?2, ?3, ?4, ?5)",
                                        rusqlite::params![cve_id, pkg_name, release, "fixed", priority],
                                    )?;
                                    total += 1;
                                }
                            }
                        }
                    }
                    tx.commit()?;
                    offset += 500;
                    let total_results = val
                        .get("total_results")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if offset >= total_results {
                        break;
                    }
                } else {
                    break;
                }
            }
            _ => break,
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    progress("vulndb.build.ubuntu.done", &format!("entries={}", total));
    Ok(total)
}

/// Download Alpine SecDB and import.
pub fn build_alpine(
    conn: &rusqlite::Connection,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<usize> {
    let mut total = 0usize;
    for branch in alpine_branches() {
        for repo in &["main", "community"] {
            let url = format!("https://secdb.alpinelinux.org/{}/{}.json", branch, repo);
            progress(
                "vulndb.build.alpine.download",
                &format!("branch={} repo={}", branch, repo),
            );
            match client.get(&url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes()?;
                    match import_alpine_secdb(conn, branch, repo, &bytes) {
                        Ok(n) => {
                            total += n;
                        }
                        Err(e) => {
                            progress(
                                "vulndb.build.alpine.error",
                                &format!("branch={} repo={} err={}", branch, repo, e),
                            );
                        }
                    }
                }
                _ => {
                    progress(
                        "vulndb.build.alpine.skip",
                        &format!("branch={} repo={}", branch, repo),
                    );
                }
            }
        }
    }
    progress("vulndb.build.alpine.done", &format!("entries={}", total));
    Ok(total)
}

/// Build the full vulndb -- downloads all bulk sources and creates the SQLite file.
pub fn build_full_db(output: &str, nvd_api_key: Option<&str>) -> anyhow::Result<()> {
    let path = std::path::Path::new(output);
    let conn = create_db(path)?;
    let started = std::time::Instant::now();

    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("scanrook-db-builder/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(300))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()?;

    // OSV ecosystems
    let osv_count = build_osv(&conn, &client)?;
    progress("vulndb.build.osv.total", &format!("vulns={}", osv_count));

    // NVD
    let nvd_count = build_nvd(&conn, &client, nvd_api_key)?;
    progress("vulndb.build.nvd.total", &format!("cves={}", nvd_count));

    // EPSS
    let epss_count = build_epss(&conn, &client)?;
    progress("vulndb.build.epss.total", &format!("scores={}", epss_count));

    // KEV
    let kev_count = build_kev(&conn, &client)?;
    progress("vulndb.build.kev.total", &format!("entries={}", kev_count));

    // Debian
    let deb_count = build_debian(&conn, &client)?;
    progress(
        "vulndb.build.debian.total",
        &format!("entries={}", deb_count),
    );

    // Ubuntu
    let ubuntu_count = build_ubuntu(&conn, &client)?;
    progress(
        "vulndb.build.ubuntu.total",
        &format!("entries={}", ubuntu_count),
    );

    // Alpine
    let alpine_count = build_alpine(&conn, &client)?;
    progress(
        "vulndb.build.alpine.total",
        &format!("entries={}", alpine_count),
    );

    // Set metadata
    let build_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    set_metadata(&conn, "build_date", &build_date)?;
    set_metadata(&conn, "schema_version", super::schema::SCHEMA_VERSION)?;
    set_metadata(&conn, "osv_count", &osv_count.to_string())?;
    set_metadata(&conn, "nvd_count", &nvd_count.to_string())?;
    set_metadata(&conn, "epss_count", &epss_count.to_string())?;
    set_metadata(&conn, "kev_count", &kev_count.to_string())?;
    set_metadata(&conn, "debian_count", &deb_count.to_string())?;
    set_metadata(&conn, "ubuntu_count", &ubuntu_count.to_string())?;
    set_metadata(&conn, "alpine_count", &alpine_count.to_string())?;

    // Optimize
    progress("vulndb.build.optimize", "vacuuming database");
    optimize_db(&conn)?;

    let elapsed = started.elapsed();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    progress(
        "vulndb.build.done",
        &format!(
            "path={} size_mb={:.1} elapsed_secs={:.0} osv={} nvd={} epss={} kev={} debian={} ubuntu={} alpine={}",
            output,
            size as f64 / 1_048_576.0,
            elapsed.as_secs_f64(),
            osv_count,
            nvd_count,
            epss_count,
            kev_count,
            deb_count,
            ubuntu_count,
            alpine_count,
        ),
    );
    println!(
        "vulndb built: {} ({:.1} MB) in {:.0}s",
        output,
        size as f64 / 1_048_576.0,
        elapsed.as_secs_f64()
    );
    println!("  OSV:     {} vulns", osv_count);
    println!("  NVD:     {} CVEs", nvd_count);
    println!("  EPSS:    {} scores", epss_count);
    println!("  KEV:     {} entries", kev_count);
    println!("  Debian:  {} entries", deb_count);
    println!("  Ubuntu:  {} entries", ubuntu_count);
    println!("  Alpine:  {} entries", alpine_count);
    Ok(())
}

/// Fetch the latest vulndb release from the API and install it.
pub fn fetch_db(force: bool) -> anyhow::Result<()> {
    let db_path = vulndb_path();

    // Check current DB build date
    if !force {
        if let Some(conn) = open_vulndb() {
            if let Some(date) = db_build_date(&conn) {
                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                if date == today {
                    println!("vulndb already up-to-date (build_date={})", date);
                    return Ok(());
                }
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("scanrook-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    // Determine API base URL (default: scanrook.io, overridable for dev)
    let api_base =
        std::env::var("SCANROOK_API_BASE").unwrap_or_else(|_| "https://scanrook.io".to_string());
    let meta_url = format!("{}/api/db/latest", api_base);

    progress("vulndb.fetch.check", &format!("querying {}", meta_url));
    let resp = client.get(&meta_url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "failed to query vulndb metadata from {}: HTTP {}",
            meta_url,
            resp.status()
        );
    }
    let meta: Value = resp.json()?;
    let download_url = meta
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'url' in API response"))?;
    let build_date = meta
        .get("build_date")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let asset_size = meta.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

    // Skip download if local DB matches the remote build date
    if !force {
        if let Some(conn) = open_vulndb() {
            if let Some(local_date) = db_build_date(&conn) {
                if local_date == build_date {
                    println!("vulndb already up-to-date (build_date={})", local_date);
                    return Ok(());
                }
            }
        }
    }

    println!(
        "Downloading vulndb {} ({:.1} MB)...",
        build_date,
        asset_size as f64 / 1_048_576.0
    );
    progress(
        "vulndb.fetch.download",
        &format!(
            "build_date={} size_mb={:.1}",
            build_date,
            asset_size as f64 / 1_048_576.0
        ),
    );

    // The API returns a presigned S3 URL -- follow redirect and download
    let mut dl_resp = client.get(download_url).send()?;
    if !dl_resp.status().is_success() {
        anyhow::bail!("download failed: HTTP {}", dl_resp.status());
    }
    let total_bytes = dl_resp.content_length().unwrap_or(asset_size);
    let is_tty = std::io::stderr().is_terminal();

    // Stream download with progress bar
    let mut gz_bytes = Vec::with_capacity(total_bytes as usize);
    let mut downloaded: u64 = 0;
    let mut last_pct: u8 = 0;
    let mut buf = [0u8; 65536];
    loop {
        let n = dl_resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        gz_bytes.extend_from_slice(&buf[..n]);
        downloaded += n as u64;
        let pct = if total_bytes > 0 {
            ((downloaded as f64 / total_bytes as f64) * 100.0).min(100.0) as u8
        } else {
            0
        };
        if pct > last_pct || n == 0 {
            last_pct = pct;
            if is_tty {
                let filled = (pct as usize) / 3;
                let empty = 33usize.saturating_sub(filled);
                eprint!(
                    "\r  [\x1b[36m{}\x1b[0m{}] {}% \u{2014} {:.0}/{:.0} MB",
                    "\u{2588}".repeat(filled),
                    "\u{2591}".repeat(empty),
                    pct,
                    downloaded as f64 / 1_048_576.0,
                    total_bytes as f64 / 1_048_576.0,
                );
            }
        }
    }
    if is_tty {
        eprintln!(); // newline after progress bar
    }

    // Detect format via magic bytes
    let is_gzip = gz_bytes.len() >= 2 && gz_bytes[0] == 0x1f && gz_bytes[1] == 0x8b;
    let is_sqlite = gz_bytes.len() >= 4 && &gz_bytes[0..4] == b"SQLi";

    let parent = db_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid db path"))?;
    std::fs::create_dir_all(parent)?;
    let tmp_path = parent.join(".scanrook.db.tmp");

    if is_sqlite {
        // Raw SQLite file -- write directly to disk, no decompression needed
        progress("vulndb.fetch.format", "raw_sqlite");
        if is_tty {
            eprint!("  Writing raw SQLite...");
        }
        std::fs::write(&tmp_path, &gz_bytes)?;
        if is_tty {
            eprintln!(" done");
        }
    } else {
        // Gzip compressed (or unknown -- try gzip, fall back to raw)
        if is_gzip {
            progress("vulndb.fetch.format", "gzip");
        } else {
            progress("vulndb.fetch.format", "unknown (trying gzip)");
        }

        let gz_len = gz_bytes.len() as u64;
        if is_tty {
            eprint!("  Decompressing...");
        }
        progress("vulndb.fetch.decompress", "decompressing vulndb");

        let gzip_result: Result<(), std::io::Error> = (|| {
            let mut decoder = GzDecoder::new(std::io::Cursor::new(&gz_bytes));
            let mut tmp_file = std::fs::File::create(&tmp_path)?;
            let mut decompressed: u64 = 0;
            let mut last_dpct: u8 = 0;
            let mut dbuf = [0u8; 131072];
            loop {
                let n = decoder.read(&mut dbuf)?;
                if n == 0 {
                    break;
                }
                tmp_file.write_all(&dbuf[..n])?;
                decompressed += n as u64;
                let consumed = decoder.get_ref().position();
                let dpct = if gz_len > 0 {
                    ((consumed as f64 / gz_len as f64) * 100.0).min(100.0) as u8
                } else {
                    0
                };
                if dpct > last_dpct {
                    last_dpct = dpct;
                    if is_tty {
                        let filled = (dpct as usize) / 3;
                        let empty = 33usize.saturating_sub(filled);
                        eprint!(
                            "\r  [\x1b[33m{}\x1b[0m{}] {}% \u{2014} {:.0} MB decompressed",
                            "\u{2588}".repeat(filled),
                            "\u{2591}".repeat(empty),
                            dpct,
                            decompressed as f64 / 1_048_576.0,
                        );
                    }
                }
            }
            tmp_file.flush()?;
            Ok(())
        })();

        if let Err(e) = gzip_result {
            if !is_gzip {
                // Unknown format and gzip failed -- try writing raw bytes as SQLite fallback
                progress("vulndb.fetch.format", "gzip_failed_fallback_raw");
                std::fs::write(&tmp_path, &gz_bytes)?;
            } else {
                // Was identified as gzip but decompression failed
                let _ = std::fs::remove_file(&tmp_path);
                anyhow::bail!("gzip decompression failed: {}", e);
            }
        }

        if is_tty {
            eprintln!();
        }
    }

    // Atomic rename
    std::fs::rename(&tmp_path, &db_path)?;

    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);

    // Validate the downloaded database
    match open_vulndb() {
        Some(conn) => {
            if let Err(e) = validate_vulndb(&conn) {
                // Validation failed -- remove corrupt DB and bail
                let _ = std::fs::remove_file(&db_path);
                anyhow::bail!("vulndb validation failed after download: {}", e);
            }
            let build_date = db_build_date(&conn).unwrap_or_default();
            println!(
                "vulndb installed: {} ({:.1} MB, build_date={})",
                db_path.display(),
                db_size as f64 / 1_048_576.0,
                build_date,
            );
        }
        None => {
            let _ = std::fs::remove_file(&db_path);
            anyhow::bail!("vulndb file could not be opened after download -- corrupt or invalid format");
        }
    }
    Ok(())
}
