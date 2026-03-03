use crate::cli::detect::build_scan_report_value;
use crate::cli::helpers::{
    clear_scanrook_cache, collect_local_cache_stats, env_bool_default, fmt_epoch,
    resolve_cache_dir, set_dir_permissions_0700, SCANROOK_DATA_SOURCES,
};
use crate::utils::progress;
use crate::{cache, container, redhat, report, vuln, vulndb, DbCommands, DbSource, ScanMode};
use reqwest::blocking::Client;
use serde_json::Value;
use std::time::{Duration, Instant};

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

pub fn print_db_sources(json: bool) {
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

pub fn print_pg_cache_check() {
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

/// Seed local file cache by copying CVE data from PostgreSQL.
///
/// Handles multiple table shapes gracefully — if a table doesn't exist,
/// it's skipped rather than failing the whole seed operation.
pub fn seed_cache_from_pg(cache_dir: &std::path::Path) -> anyhow::Result<usize> {
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

pub fn run_db(
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
        DbCommands::Build { output } => {
            vulndb::build_full_db(&output, nvd_api_key.as_deref())?;
        }
        DbCommands::Fetch { force } => {
            vulndb::fetch_db(force)?;
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
                        source_name: None,
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
                vuln::epss_enrich_findings(&mut dummy_findings, &mut None, Some(&cache_dir));
                vuln::kev_enrich_findings(&mut dummy_findings, &mut None, Some(&cache_dir));
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
                    vuln::enrich_findings_with_nvd(&mut findings, nvd_api_key.as_deref(), &mut pg);
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
                        source_name: None,
                    },
                    container::PackageCoordinate {
                        ecosystem: "npm".into(),
                        name: "lodash".into(),
                        version: "4.17.0".into(),
                        source_name: None,
                    },
                    container::PackageCoordinate {
                        ecosystem: "PyPI".into(),
                        name: "requests".into(),
                        version: "2.25.0".into(),
                        source_name: None,
                    },
                ];
                let _results = vuln::osv_batch_query(&sample_pkgs, &mut None);
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
