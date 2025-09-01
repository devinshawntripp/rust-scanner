use std::collections::HashSet;
use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::Value;

/// Queries the NVD API for a given component + version
pub fn match_vuln(component: &str, version: &str) {
    let keyword = format!("{} {}", component, version);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=10",
        urlencoding::encode(&keyword)
    );

    println!("Querying NVD: {}", url);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let resp = match client.get(&url).send() {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to reach NVD API: {}", e);
            return;
        }
    };

    if !resp.status().is_success() {
        eprintln!("NVD API returned error: {}", resp.status());
        return;
    }

    let json: Value = match resp.json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to parse NVD response: {}", e);
            return;
        }
    };

    let mut found = false;
    let mut seen = HashSet::new();

    if let Some(items) = json["vulnerabilities"].as_array() {
        for item in items {
            let id = item["cve"]["id"].as_str().unwrap_or("unknown");
            let description = item["cve"]["descriptions"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .find(|d| d["lang"] == "en")
                .and_then(|d| d["value"].as_str())
                .unwrap_or("");

            if seen.insert(id.to_string()) {
                println!("🔹 {}: {}", id, description);
                found = true;
            }
        }
    }

    if !found {
        println!("✅ No CVEs found for: {} {}", component, version);
    }
}
