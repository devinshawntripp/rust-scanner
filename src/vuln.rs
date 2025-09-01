use std::fs;
use serde_json::Value;

/// Match simple CVE entries from JSON file
pub fn match_vuln(component: &str, version: &str) {
    let data = fs::read_to_string("data/nvd_cves.json").expect("CVE DB missing");
    let json: Value = serde_json::from_str(&data).expect("Invalid JSON");
    for item in json["CVE_Items"].as_array().unwrap() {
        let desc = &item["cve"]["description"]["description_data"][0]["value"];
        if desc.as_str().unwrap_or("").contains(component) && desc.as_str().unwrap_or("").contains(version) {
            let cve_id = item["cve"]["CVE_data_meta"]["ID"].as_str().unwrap_or("UNKNOWN");
            println!("Matched CVE: {}", cve_id);
        }
    }
}
