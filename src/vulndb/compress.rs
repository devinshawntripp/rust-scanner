//! Compression and data stripping helpers for vulndb payloads.

use serde_json::Value;

/// Strip unused fields from OSV advisory JSON to reduce storage.
/// Keeps: id, modified, summary, details, aliases, severity, references, affected, database_specific.severity
/// Drops: published, withdrawn, schema_version, related, credits, affected[].versions,
///        affected[].ecosystem_specific, affected[].database_specific, affected[].ranges[].repo, etc.
pub(super) fn strip_osv_unused_fields(val: &Value) -> Value {
    let obj = match val.as_object() {
        Some(o) => o,
        None => return val.clone(),
    };
    let mut out = serde_json::Map::new();
    // Keep only the fields the scanner actually reads
    for key in &[
        "id",
        "modified",
        "summary",
        "details",
        "aliases",
        "severity",
        "references",
    ] {
        if let Some(v) = obj.get(*key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    // Keep database_specific.severity only
    if let Some(db_spec) = obj.get("database_specific").and_then(|d| d.as_object()) {
        if let Some(sev) = db_spec.get("severity") {
            out.insert(
                "database_specific".to_string(),
                serde_json::json!({ "severity": sev }),
            );
        }
    }
    // Strip affected[] -- keep package, ranges (with only type + events.fixed), drop versions/ecosystem_specific/etc
    if let Some(affected) = obj.get("affected").and_then(|a| a.as_array()) {
        let stripped_affected: Vec<Value> = affected
            .iter()
            .map(|aff| {
                let mut stripped = serde_json::Map::new();
                if let Some(pkg) = aff.get("package") {
                    stripped.insert("package".to_string(), pkg.clone());
                }
                if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
                    let stripped_ranges: Vec<Value> = ranges
                        .iter()
                        .map(|range| {
                            let mut sr = serde_json::Map::new();
                            if let Some(t) = range.get("type") {
                                sr.insert("type".to_string(), t.clone());
                            }
                            if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                                let stripped_events: Vec<Value> = events
                                    .iter()
                                    .filter_map(|e| {
                                        if e.get("fixed").is_some() {
                                            Some(e.clone())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();
                                if !stripped_events.is_empty() {
                                    sr.insert("events".to_string(), Value::Array(stripped_events));
                                }
                            }
                            Value::Object(sr)
                        })
                        .collect();
                    stripped.insert("ranges".to_string(), Value::Array(stripped_ranges));
                }
                Value::Object(stripped)
            })
            .collect();
        out.insert("affected".to_string(), Value::Array(stripped_affected));
    }
    Value::Object(out)
}

pub(super) fn compress_json(data: &[u8]) -> Vec<u8> {
    // Use zstd level 3 -- 30-40% smaller than gzip with faster compression
    zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
}

/// Decompress a plain zstd-compressed payload blob.
/// Returns None on decompression failure (corrupt data, wrong format, etc).
pub(super) fn decompress_payload(data: &[u8]) -> Option<Vec<u8>> {
    zstd::decode_all(data).ok()
}

/// Decompress a zstd payload that was compressed with a shared dictionary.
/// Caps output at 10 MB to prevent memory exhaustion on corrupt data.
/// Returns None on decompression failure.
pub(super) fn decompress_payload_with_dict(data: &[u8], dict: &[u8]) -> Option<Vec<u8>> {
    let mut decompressor = zstd::bulk::Decompressor::with_dictionary(dict).ok()?;
    decompressor.decompress(data, 10 * 1024 * 1024).ok()
}
