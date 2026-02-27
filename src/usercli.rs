use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanRookConfig {
    pub api_base: Option<String>,
    pub api_key: Option<String>,
    pub telemetry_opt_in: bool,
}

fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("SCANROOK_CONFIG") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".scanrook").join("config.json")
}

fn sanitize_base_url(v: &str) -> String {
    let mut out = v.trim().to_string();
    while out.ends_with('/') {
        out.pop();
    }
    out
}

pub fn load_config() -> ScanRookConfig {
    let path = config_path();
    let Ok(raw) = fs::read_to_string(path) else {
        return ScanRookConfig::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_config(cfg: &ScanRookConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    let encoded = serde_json::to_string_pretty(cfg)?;
    let mut f = fs::File::create(&path).context("failed to write config file")?;
    f.write_all(encoded.as_bytes())?;
    Ok(())
}

fn resolved_api_base(cli_api_base: Option<String>, cfg: &ScanRookConfig) -> String {
    if let Some(v) = cli_api_base {
        let s = sanitize_base_url(&v);
        if !s.is_empty() {
            return s;
        }
    }
    if let Ok(v) = std::env::var("SCANROOK_API_BASE") {
        let s = sanitize_base_url(&v);
        if !s.is_empty() {
            return s;
        }
    }
    if let Some(v) = &cfg.api_base {
        let s = sanitize_base_url(v);
        if !s.is_empty() {
            return s;
        }
    }
    "https://scanrook.io".to_string()
}

fn resolved_api_key(cli_api_key: Option<String>, cfg: &ScanRookConfig) -> Option<String> {
    if let Some(v) = cli_api_key {
        let s = v.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    if let Ok(v) = std::env::var("SCANROOK_API_KEY") {
        let s = v.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    cfg.api_key.clone().filter(|v| !v.trim().is_empty())
}

fn auth_headers(
    mut req: reqwest::blocking::RequestBuilder,
    api_key: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    let ua = format!("scanrook-cli/{}", env!("CARGO_PKG_VERSION"));
    req = req.header("user-agent", ua);
    if let Some(key) = api_key {
        req = req.header("authorization", format!("Bearer {}", key));
    }
    req
}

fn pretty_json(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

pub fn set_config_value(key: &str, value: &str) -> Result<()> {
    let mut cfg = load_config();
    match key.trim() {
        "telemetry.opt_in" => {
            let parsed = match value.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => return Err(anyhow!("value must be true or false")),
            };
            cfg.telemetry_opt_in = parsed;
            save_config(&cfg)?;
            println!("telemetry.opt_in={}", parsed);
            Ok(())
        }
        "api.base" => {
            let sanitized = sanitize_base_url(value);
            if sanitized.is_empty() {
                return Err(anyhow!("api.base cannot be empty"));
            }
            cfg.api_base = Some(sanitized.clone());
            save_config(&cfg)?;
            println!("api.base={}", sanitized);
            Ok(())
        }
        _ => Err(anyhow!(
            "unsupported key '{}'. supported keys: telemetry.opt_in, api.base",
            key
        )),
    }
}

pub fn logout() -> Result<()> {
    let mut cfg = load_config();
    cfg.api_key = None;
    save_config(&cfg)?;
    println!("logged out");
    Ok(())
}

fn set_logged_in_key(api_key: &str, api_base: Option<String>) -> Result<()> {
    if api_key.trim().is_empty() {
        return Err(anyhow!("api key is empty"));
    }
    let mut cfg = load_config();
    cfg.api_key = Some(api_key.trim().to_string());
    if let Some(base) = api_base {
        let sanitized = sanitize_base_url(&base);
        if !sanitized.is_empty() {
            cfg.api_base = Some(sanitized);
        }
    }
    save_config(&cfg)?;
    Ok(())
}

pub fn login(api_base: Option<String>, api_key: Option<String>) -> Result<()> {
    let cfg = load_config();
    let base = resolved_api_base(api_base.clone(), &cfg);
    let client = Client::new();

    if let Some(key) = api_key {
        set_logged_in_key(&key, Some(base.clone()))?;
        println!("api key saved for {}", base);
        return Ok(());
    }

    let start_url = format!("{}/api/cli/auth/device/start", base);
    let start_resp = auth_headers(client.post(&start_url), None)
        .send()
        .context("device start request failed")?;
    if !start_resp.status().is_success() {
        return Err(anyhow!("device start failed with status {}", start_resp.status()));
    }
    let start_json: Value = start_resp.json().context("invalid device start response")?;

    let device_code = start_json
        .get("device_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let user_code = start_json
        .get("user_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let interval = start_json
        .get("interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(5)
        .max(1);
    let expires_in = start_json
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(600)
        .max(interval);

    if device_code.is_empty() {
        return Err(anyhow!("device start response missing device_code"));
    }

    let approve_example = format!(
        "curl -sS -X POST '{}/api/cli/auth/device/complete' \\\n  -H 'Authorization: Bearer <API_KEY>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"device_code\":\"{}\",\"approve\":true,\"name\":\"scanrook-cli\"}}'",
        base, device_code
    );

    println!("device login started");
    if !user_code.is_empty() {
        println!("user code: {}", user_code);
    }
    if let Some(uri) = start_json.get("verification_uri").and_then(|v| v.as_str()) {
        println!("verification uri: {}", uri);
    }
    if let Some(uri) = start_json
        .get("verification_uri_complete")
        .and_then(|v| v.as_str())
    {
        println!("verification uri complete: {}", uri);
    }
    println!("approve command:\n{}", approve_example);
    println!("polling for approval...");

    let poll_url = format!("{}/api/cli/auth/device/complete", base);
    let mut elapsed = 0u64;
    while elapsed <= expires_in {
        let poll_resp = auth_headers(
            client
                .post(&poll_url)
                .header("content-type", "application/json")
                .body(json!({ "device_code": device_code }).to_string()),
            None,
        )
        .send()
        .context("device poll request failed")?;

        if poll_resp.status().is_success() {
            let json: Value = poll_resp.json().context("invalid device poll response")?;
            let status = json.get("status").and_then(|v| v.as_str()).unwrap_or("");
            if status == "authorized" {
                if let Some(key) = json.get("api_key").and_then(|v| v.as_str()) {
                    set_logged_in_key(key, Some(base.clone()))?;
                    println!("login complete for {}", base);
                    return Ok(());
                }
                return Err(anyhow!("device authorized but no api_key returned"));
            }
            if status == "expired_or_invalid" {
                return Err(anyhow!("device code expired or invalid"));
            }
        }

        thread::sleep(Duration::from_secs(interval));
        elapsed += interval;
    }

    Err(anyhow!("device login timed out"))
}

pub fn whoami(api_base: Option<String>, api_key: Option<String>, json_output: bool) -> Result<()> {
    let cfg = load_config();
    let base = resolved_api_base(api_base, &cfg);
    let key = resolved_api_key(api_key, &cfg);
    let client = Client::new();
    let url = format!("{}/api/cli/limits", base);
    let resp = auth_headers(client.get(&url), key.as_deref())
        .send()
        .context("whoami request failed")?;
    let status = resp.status();
    let body: Value = resp.json().unwrap_or_else(|_| json!({}));
    if json_output {
        println!("{}", pretty_json(&body));
        return Ok(());
    }
    if status == StatusCode::UNAUTHORIZED {
        println!("unauthenticated");
        return Ok(());
    }
    let actor = body
        .get("actor_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let org = body.get("org_id").and_then(|v| v.as_str()).unwrap_or("-");
    let plan = body
        .get("plan_code")
        .and_then(|v| v.as_str())
        .unwrap_or("FREE");
    println!("actor_kind: {}", actor);
    println!("org_id: {}", org);
    println!("plan_code: {}", plan);
    Ok(())
}

pub fn show_limits(api_base: Option<String>, api_key: Option<String>, json_output: bool) -> Result<()> {
    let cfg = load_config();
    let base = resolved_api_base(api_base, &cfg);
    let key = resolved_api_key(api_key, &cfg);
    let client = Client::new();
    let url = format!("{}/api/cli/limits", base);
    let resp = auth_headers(client.get(&url), key.as_deref())
        .send()
        .context("limits request failed")?;
    let status = resp.status();
    let body: Value = resp.json().unwrap_or_else(|_| json!({}));
    if json_output {
        println!("{}", pretty_json(&body));
        return Ok(());
    }

    if status.is_client_error() || status.is_server_error() {
        println!("limits request failed (status {})", status);
        println!("{}", pretty_json(&body));
        return Ok(());
    }

    println!("{}", pretty_json(&body));
    Ok(())
}

pub fn consume_cloud_enrich_token(api_base: Option<String>, api_key: Option<String>) -> bool {
    let cfg = load_config();
    let base = resolved_api_base(api_base, &cfg);
    let key = resolved_api_key(api_key, &cfg);
    let client = Client::new();
    let url = format!("{}/api/cli/enrich", base);

    let resp = auth_headers(
        client
            .post(&url)
            .header("content-type", "application/json")
            .body("{}"),
        key.as_deref(),
    )
    .send();

    let Ok(resp) = resp else {
        eprintln!("cloud-enrichment quota check unavailable; continuing scan");
        return true;
    };

    if resp.status() == StatusCode::TOO_MANY_REQUESTS {
        let body: Value = resp.json().unwrap_or_else(|_| json!({}));
        let limit_type = body
            .get("limit_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let reset_at = body.get("reset_at").and_then(|v| v.as_str()).unwrap_or("-");
        let upgrade = body
            .get("upgrade_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://scanrook.io/dashboard/settings/billing");
        eprintln!(
            "cloud enrichment limit reached ({}). local scan will continue without cloud enrich. reset_at={} upgrade={}",
            limit_type, reset_at, upgrade
        );
        return false;
    }

    if !resp.status().is_success() {
        eprintln!(
            "cloud-enrichment quota check returned {}; continuing scan",
            resp.status()
        );
    }
    true
}
