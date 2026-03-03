use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use postgres::Client as PgClient;
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::report::{Finding, ReferenceInfo};
use crate::utils::{progress, progress_timing};

use super::super::cvss::normalize_redhat_severity;
use super::super::env_bool;
use super::super::http::build_http_client;
use super::super::pg::{
    compute_dynamic_ttl_days, parse_redhat_last_modified, pg_get_redhat, pg_init_schema,
    pg_put_redhat,
};
use super::helpers::{
    is_redhat_errata_id, normalize_redhat_errata_id, normalize_reference_url,
    redhat_cvss_from_vuln, redhat_note_text,
};

pub(in crate::vuln) fn redhat_enrich_findings(findings: &mut Vec<Finding>, pg: &mut Option<PgClient>) {
    if !env_bool("SCANNER_REDHAT_ENRICH", true) {
        progress("redhat.fetch.skip", "disabled by SCANNER_REDHAT_ENRICH");
        return;
    }
    if findings.is_empty() {
        return;
    }

    for f in findings.iter_mut() {
        let norm = normalize_redhat_errata_id(&f.id);
        if norm != f.id && is_redhat_errata_id(&norm) {
            f.id = norm;
        }
    }

    let mut ids: Vec<String> = findings
        .iter()
        .map(|f| normalize_redhat_errata_id(&f.id))
        .filter(|id| is_redhat_errata_id(id))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    if ids.is_empty() {
        return;
    }
    ids.sort();

    let max_ids = std::env::var("SCANNER_REDHAT_ENRICH_MAX_IDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0);
    if let Some(max_ids) = max_ids {
        if ids.len() > max_ids {
            progress(
                "redhat.fetch.limit",
                &format!("processing {} of {} errata", max_ids, ids.len()),
            );
            ids.truncate(max_ids);
        }
    }

    let timeout_secs: u64 = std::env::var("SCANNER_REDHAT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let ttl_days: i64 = std::env::var("SCANNER_REDHAT_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let sleep_ms: u64 = std::env::var("SCANNER_REDHAT_SLEEP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let client = build_http_client(timeout_secs);
    let total = ids.len();
    if let Some(c) = pg.as_mut() {
        pg_init_schema(c);
    }

    let redhat_started = std::time::Instant::now();
    for (idx, id) in ids.into_iter().enumerate() {
        progress(
            "redhat.fetch.start",
            &format!("{}/{} {}", idx + 1, total, id),
        );

        let cache_tag = cache_key(&["redhat_csaf", &id]);
        let mut json: Option<Value> = None;

        if let Some(client_pg) = pg.as_mut() {
            if let Some((payload, last_checked, last_mod)) = pg_get_redhat(client_pg, &id) {
                let ttl_dyn_days = compute_dynamic_ttl_days(last_mod, ttl_days);
                if Utc::now() - last_checked < ChronoDuration::days(ttl_dyn_days) {
                    json = Some(payload);
                    progress("redhat.cache.pg.hit", &id);
                }
            }
        }

        if json.is_none() {
            if let Some(bytes) = cache_get(
                std::env::var_os("SCANNER_CACHE")
                    .as_deref()
                    .map(PathBuf::from)
                    .as_deref(),
                &cache_tag,
            ) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    json = Some(v);
                    progress("redhat.cache.hit", &id);
                }
            }
        }

        if json.is_none() {
            if sleep_ms > 0 {
                sleep(Duration::from_millis(sleep_ms));
            }
            let url = format!(
                "https://access.redhat.com/hydra/rest/securitydata/csaf/{}.json?isCompressed=false",
                id
            );
            match client.get(&url).send() {
                Ok(r) if r.status().is_success() => match r.json::<Value>() {
                    Ok(v) => {
                        cache_put(
                            std::env::var_os("SCANNER_CACHE")
                                .as_deref()
                                .map(PathBuf::from)
                                .as_deref(),
                            &cache_tag,
                            v.to_string().as_bytes(),
                        );
                        json = Some(v);
                    }
                    Err(e) => {
                        progress("redhat.fetch.err", &format!("{} json {}", id, e));
                    }
                },
                Ok(r) => {
                    progress("redhat.fetch.err", &format!("{} status={}", id, r.status()));
                }
                Err(e) => {
                    progress("redhat.fetch.err", &format!("{} {}", id, e));
                }
            }
        }

        let Some(doc_json) = json else {
            continue;
        };
        if let Some(client_pg) = pg.as_mut() {
            let last_mod = parse_redhat_last_modified(&doc_json);
            pg_put_redhat(client_pg, &id, &doc_json, last_mod);
        }
        progress("redhat.fetch.ok", &id);

        let document = &doc_json["document"];
        let description = redhat_note_text(document).or_else(|| {
            document
                .get("title")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        });
        let severity = document
            .get("aggregate_severity")
            .and_then(|s| s.get("text"))
            .and_then(|s| s.as_str())
            .and_then(normalize_redhat_severity);

        let mut references: Vec<ReferenceInfo> = Vec::new();
        if let Some(refs) = document.get("references").and_then(|r| r.as_array()) {
            for r in refs {
                if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                    let normalized = normalize_reference_url(url);
                    if normalized.is_empty() {
                        continue;
                    }
                    references.push(ReferenceInfo {
                        reference_type: "redhat".into(),
                        url: normalized,
                    });
                }
            }
        }
        if references.is_empty() {
            references.push(ReferenceInfo {
                reference_type: "redhat".into(),
                url: format!("https://access.redhat.com/errata/{}", id),
            });
        }

        let mut best_cvss: Option<crate::report::CvssInfo> = None;
        if let Some(vulns) = doc_json.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulns {
                if let Some(cvss) = redhat_cvss_from_vuln(v) {
                    let replace = best_cvss
                        .as_ref()
                        .map(|existing| cvss.base > existing.base)
                        .unwrap_or(true);
                    if replace {
                        best_cvss = Some(cvss);
                    }
                }
            }
        }

        for f in findings
            .iter_mut()
            .filter(|f| f.id.eq_ignore_ascii_case(&id))
        {
            if f.description.is_none() {
                f.description = description.clone();
            }
            if f.severity.is_none() {
                f.severity = severity.clone();
            }
            if f.cvss.is_none() {
                f.cvss = best_cvss.clone();
            }
            if f.references.is_empty() && !references.is_empty() {
                f.references = references.clone();
            }
            if f.confidence.is_none() {
                f.confidence = Some("MEDIUM".into());
            }
        }
    }
    progress_timing("redhat.fetch", redhat_started);
}
