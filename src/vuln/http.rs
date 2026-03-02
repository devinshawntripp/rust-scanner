use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::Duration;

use chrono::Utc;
use rand::Rng;
use reqwest::blocking::{Client, Response};
use serde_json::Value;

use crate::cache::{cache_get, cache_key, cache_put};
use crate::utils::progress;

fn scanner_force_ipv4() -> bool {
    std::env::var("SCANNER_FORCE_IPV4")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true)
}

pub(super) fn build_http_client(timeout_secs: u64) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent(format!("scanrook/{}", env!("CARGO_PKG_VERSION")));
    if scanner_force_ipv4() {
        // Worker pods on many homelab clusters have no usable IPv6 egress.
        // Pin outbound sockets to IPv4 to avoid long OSV/NVD timeouts.
        builder = builder.local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    builder.build().unwrap()
}

static NVD_HTTP_CLIENT: OnceLock<Client> = OnceLock::new();
static ENRICH_HTTP_CLIENT: OnceLock<Client> = OnceLock::new();
static REDIS_CLIENT: OnceLock<Option<redis::Client>> = OnceLock::new();

fn nvd_timeout_secs() -> u64 {
    std::env::var("SCANNER_NVD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
}

fn nvd_retry_max() -> usize {
    std::env::var("SCANNER_NVD_RETRY_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

fn nvd_retry_base_ms() -> u64 {
    std::env::var("SCANNER_NVD_RETRY_BASE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
}

pub(super) fn nvd_http_client() -> &'static Client {
    NVD_HTTP_CLIENT.get_or_init(|| build_http_client(nvd_timeout_secs()))
}

pub(super) fn enrich_http_client() -> &'static Client {
    ENRICH_HTTP_CLIENT.get_or_init(|| build_http_client(30))
}

pub(super) fn redis_client() -> Option<&'static redis::Client> {
    REDIS_CLIENT
        .get_or_init(|| {
            let url = std::env::var("SCANNER_REDIS_URL")
                .ok()
                .or_else(|| std::env::var("REDIS_URL").ok())
                .unwrap_or_default();
            if url.trim().is_empty() {
                return None;
            }
            redis::Client::open(url).ok()
        })
        .as_ref()
}

fn nvd_scope_key(api_key: Option<&str>) -> String {
    if let Some(key) = api_key {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        let full = format!("key:{:x}", digest);
        return full.chars().take(20).collect();
    }
    "anon".to_string()
}

fn wait_for_global_nvd_rate_slot(api_key: Option<&str>) {
    let per_minute: i64 = std::env::var("SCANNER_NVD_GLOBAL_RATE_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if per_minute <= 0 {
        return;
    }
    let Some(client) = redis_client() else {
        return;
    };

    loop {
        let now = Utc::now();
        let minute = now.timestamp() / 60;
        let scope = nvd_scope_key(api_key);
        let key = format!("scanner:nvd:rate:{}:{}", scope, minute);
        let mut conn = match client.get_connection() {
            Ok(c) => c,
            Err(e) => {
                progress("nvd.rate.redis.err", &format!("{}", e));
                return;
            }
        };

        let count: i64 = redis::cmd("INCR").arg(&key).query(&mut conn).unwrap_or(1);
        let _: redis::RedisResult<()> = redis::cmd("EXPIRE").arg(&key).arg(70).query(&mut conn);
        if count <= per_minute {
            return;
        }

        let sec = now.timestamp().rem_euclid(60);
        let wait_ms = ((60 - sec).max(1) as u64) * 1000;
        progress(
            "nvd.rate.wait",
            &format!(
                "scope={} count={} limit={} wait_ms={}",
                scope, count, per_minute, wait_ms
            ),
        );
        sleep(Duration::from_millis(wait_ms));
    }
}

fn parse_retry_after_ms(resp: &Response) -> Option<u64> {
    let value = resp.headers().get("Retry-After")?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1000));
    }
    None
}

fn retry_backoff_with_jitter_ms(attempt: usize) -> u64 {
    let capped_exp = (attempt.saturating_sub(1)).min(7);
    let exp = 1u64 << capped_exp;
    let max_backoff = nvd_retry_base_ms().saturating_mul(exp);
    if max_backoff == 0 {
        return 0;
    }
    rand::thread_rng().gen_range(0..=max_backoff)
}

pub(super) fn cached_http_json(
    url: &str,
    tag: &str,
    ttl_secs: i64,
    timeout_secs: u64,
) -> Option<Value> {
    let cache_dir = super::resolve_enrich_cache_dir();
    let key = cache_key(&["distro_feed", tag, url]);
    if let Some(bytes) = cache_get(cache_dir.as_deref(), &key) {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            // New wrapper format: {"fetched_at": <unix>, "payload": {...}}
            if let (Some(fetched_at), Some(payload)) = (
                v.get("fetched_at").and_then(|x| x.as_i64()),
                v.get("payload"),
            ) {
                if Utc::now().timestamp().saturating_sub(fetched_at) <= ttl_secs {
                    return Some(payload.clone());
                }
            } else if v.is_object() || v.is_array() {
                // Backward compatibility if older cache writes raw JSON.
                return Some(v);
            }
        }
    }

    let client = build_http_client(timeout_secs);
    let resp = client.get(url).send().ok()?;
    if !resp.status().is_success() {
        progress(
            "distro.feed.http.err",
            &format!("tag={} status={} url={}", tag, resp.status(), url),
        );
        return None;
    }
    let payload: Value = resp.json().ok()?;
    let wrapped = serde_json::json!({
        "fetched_at": Utc::now().timestamp(),
        "payload": payload
    });
    cache_put(cache_dir.as_deref(), &key, wrapped.to_string().as_bytes());
    wrapped.get("payload").cloned()
}

pub(super) fn nvd_get_json(
    url: &str,
    api_key: Option<&str>,
    cache_tag: &str,
    sleep_ms: u64,
) -> Option<Value> {
    let skip_cache = super::env_bool("SCANNER_SKIP_CACHE", false);
    let key = cache_key(&["nvd", cache_tag, url]);
    if !skip_cache {
        if let Some(bytes) = cache_get(
            std::env::var_os("SCANNER_CACHE")
                .as_deref()
                .map(PathBuf::from)
                .as_deref(),
            &key,
        ) {
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                return Some(v);
            }
        }
    }

    let client = nvd_http_client();
    let attempts = nvd_retry_max().max(1);
    for attempt in 1..=attempts {
        if sleep_ms > 0 {
            sleep(Duration::from_millis(sleep_ms));
        }
        wait_for_global_nvd_rate_slot(api_key);

        let mut req = client.get(url).header("Accept", "application/json");
        if let Some(k) = api_key {
            req = req.header("apiKey", k).header("X-Api-Key", k);
        }

        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                let retry_ms = retry_backoff_with_jitter_ms(attempt);
                progress(
                    "nvd.http.err",
                    &format!(
                        "attempt={} err={} retry_ms={} url={}",
                        attempt, e, retry_ms, url
                    ),
                );
                if attempt >= attempts {
                    return None;
                }
                if retry_ms > 0 {
                    sleep(Duration::from_millis(retry_ms));
                }
                continue;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let rem = resp
                .headers()
                .get("X-RateLimit-Remaining")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let lim = resp
                .headers()
                .get("X-RateLimit-Limit")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let retryable =
                status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            let retry_after_ms = parse_retry_after_ms(&resp).unwrap_or(0);
            let jitter_ms = retry_backoff_with_jitter_ms(attempt);
            let wait_ms = retry_after_ms.max(jitter_ms);
            progress(
                "nvd.http.err",
                &format!(
                    "attempt={} status={} remaining={} limit={} retryable={} wait_ms={} url={}",
                    attempt, status, rem, lim, retryable, wait_ms, url
                ),
            );

            if retryable && attempt < attempts {
                if wait_ms > 0 {
                    sleep(Duration::from_millis(wait_ms));
                }
                continue;
            }
            return None;
        }

        adjust_rate_limits(&resp);
        let v: Value = match resp.json() {
            Ok(j) => j,
            Err(e) => {
                let retry_ms = retry_backoff_with_jitter_ms(attempt);
                progress(
                    "nvd.json.err",
                    &format!(
                        "attempt={} err={} retry_ms={} url={}",
                        attempt, e, retry_ms, url
                    ),
                );
                if attempt >= attempts {
                    return None;
                }
                if retry_ms > 0 {
                    sleep(Duration::from_millis(retry_ms));
                }
                continue;
            }
        };

        if !skip_cache {
            cache_put(
                std::env::var_os("SCANNER_CACHE")
                    .as_deref()
                    .map(PathBuf::from)
                    .as_deref(),
                &key,
                v.to_string().as_bytes(),
            );
        }
        return Some(v);
    }

    None
}

fn adjust_rate_limits(resp: &Response) {
    if let Some(rem) = resp.headers().get("X-RateLimit-Remaining") {
        if let Ok(rem_str) = rem.to_str() {
            if let Ok(remaining) = rem_str.parse::<i64>() {
                if remaining <= 1 {
                    // back off hard if we are at the edge
                    std::env::set_var("SCANNER_NVD_SLEEP_MS", "7000");
                } else if remaining < 10 {
                    std::env::set_var("SCANNER_NVD_SLEEP_MS", "3000");
                }
            }
        }
    }
}
