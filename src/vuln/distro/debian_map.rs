use std::collections::HashSet;

use postgres::Client as PgClient;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::utils::progress;

use super::super::http::build_http_client;
use super::super::pg::{pg_get_osv, resolve_enrich_cache_dir};

pub(in crate::vuln) fn map_debian_advisory_to_cves(
    advisory_id: &str,
    pg: &mut Option<PgClient>,
) -> Option<Vec<String>> {
    // 1. Check PG osv_vuln_cache for aliases (populated by bulk import)
    if let Some(client_pg) = pg.as_mut() {
        if let Some((payload, _last_checked, _last_mod)) = pg_get_osv(client_pg, advisory_id) {
            let mut cves: HashSet<String> = HashSet::new();
            if let Some(arr) = payload["aliases"].as_array() {
                for a in arr.iter().filter_map(|x| x.as_str()) {
                    if a.starts_with("CVE-") {
                        cves.insert(a.to_string());
                    }
                }
            }
            if let Ok(re) = regex::Regex::new(r"CVE-\d{4}-\d+") {
                if let Some(arr) = payload["references"].as_array() {
                    for r in arr {
                        if let Some(u) = r["url"].as_str() {
                            for m in re.find_iter(u) {
                                cves.insert(m.as_str().to_string());
                            }
                        }
                    }
                }
                for field in ["summary", "details"] {
                    if let Some(text) = payload[field].as_str() {
                        for m in re.find_iter(text) {
                            cves.insert(m.as_str().to_string());
                        }
                    }
                }
            }
            if !cves.is_empty() {
                progress(
                    "osv.debian.map.pg_hit",
                    &format!("{} -> {} CVEs", advisory_id, cves.len()),
                );
                return Some(cves.into_iter().collect());
            }
        }
    }

    // 2. Cross-reference via debian_tracker_cache in PG
    if let Some(client_pg) = pg.as_mut() {
        let mut pkg_names: Vec<String> = Vec::new();
        if let Some((payload, _, _)) = pg_get_osv(client_pg, advisory_id) {
            if let Some(affected) = payload["affected"].as_array() {
                for aff in affected {
                    if let Some(name) = aff["package"]["name"].as_str() {
                        if !name.is_empty() && !pkg_names.contains(&name.to_string()) {
                            pkg_names.push(name.to_string());
                        }
                    }
                }
            }
        }
        if !pkg_names.is_empty() {
            let mut cves: HashSet<String> = HashSet::new();
            for pkg in &pkg_names {
                if let Ok(rows) = client_pg.query(
                    "SELECT DISTINCT cve_id FROM debian_tracker_cache WHERE package = $1",
                    &[pkg],
                ) {
                    for row in &rows {
                        let cve_id: String = row.get(0);
                        cves.insert(cve_id);
                    }
                }
            }
            if !cves.is_empty() {
                let result: Vec<String> = cves.into_iter().collect();
                progress(
                    "osv.debian.map.tracker_cache",
                    &format!("{} ({}) -> {} CVEs", advisory_id, pkg_names.join(","), result.len()),
                );
                if let Some((mut payload, _, _)) = pg_get_osv(client_pg, advisory_id) {
                    let aliases_arr: Vec<serde_json::Value> = result
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect();
                    payload["aliases"] = serde_json::Value::Array(aliases_arr);
                    let _ = client_pg.execute(
                        "UPDATE osv_vuln_cache SET payload = $1::jsonb WHERE vuln_id = $2",
                        &[&payload.to_string(), &advisory_id],
                    );
                }
                return Some(result);
            }
        }
    }

    // 3. Check file cache
    let cache_dir = resolve_enrich_cache_dir();
    let cache_key_str = cache_key(&["debian_advisory_map", advisory_id]);
    if let Some(bytes) = cache_get(cache_dir.as_deref(), &cache_key_str) {
        if let Ok(arr) = serde_json::from_slice::<Vec<String>>(&bytes) {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
    }

    // 4. Last resort: fetch Debian tracker HTML page
    let url = format!(
        "https://security-tracker.debian.org/tracker/{}",
        advisory_id
    );
    let client = build_http_client(10);
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().ok()?;
    let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok()?;
    let mut set: HashSet<String> = HashSet::new();
    for m in re.find_iter(&body) {
        set.insert(m.as_str().to_string());
    }
    let result: Vec<String> = set.into_iter().collect();

    if !result.is_empty() {
        if let Ok(json_bytes) = serde_json::to_vec(&result) {
            cache_put(cache_dir.as_deref(), &cache_key_str, &json_bytes);
        }
    }

    Some(result)
}
