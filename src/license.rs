use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Serialize, Clone)]
pub struct LicenseDetection {
    pub spdx_id: String,
    pub name: String,
    pub file: String,
    pub confidence: f32,
}

#[derive(Debug, Serialize)]
pub struct LicenseReport {
    pub detections: Vec<LicenseDetection>,
    pub summary: LicenseSummary,
}

#[derive(Debug, Serialize)]
pub struct LicenseSummary {
    pub total_files_scanned: usize,
    pub total_licenses_found: usize,
    pub unique_licenses: Vec<String>,
}

static LICENSE_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "MIT",
        "MIT License",
        r"(?i)Permission is hereby granted,?\s+free of charge",
    ),
    (
        "Apache-2.0",
        "Apache License 2.0",
        r"(?i)Apache License,?\s+Version 2\.0",
    ),
    (
        "GPL-2.0-only",
        "GNU General Public License v2.0",
        r"(?i)GNU General Public License\s.*?version 2(?!\.|\d)",
    ),
    (
        "GPL-3.0-only",
        "GNU General Public License v3.0",
        r"(?i)GNU General Public License\s.*?version 3",
    ),
    (
        "LGPL-2.1-only",
        "GNU Lesser General Public License v2.1",
        r"(?i)GNU Lesser General Public License\s.*?version 2\.1",
    ),
    (
        "LGPL-3.0-only",
        "GNU Lesser General Public License v3.0",
        r"(?i)GNU Lesser General Public License\s.*?version 3",
    ),
    (
        "AGPL-3.0-only",
        "GNU Affero General Public License v3.0",
        r"(?i)GNU Affero General Public License\s.*?version 3",
    ),
    (
        "BSD-2-Clause",
        "BSD 2-Clause License",
        r"(?i)Redistribution and use in source and binary forms.*?2\s*(?:conditions|clauses)",
    ),
    (
        "BSD-3-Clause",
        "BSD 3-Clause License",
        r"(?i)Redistribution and use in source and binary forms.*?(?:3\s*(?:conditions|clauses)|Neither the name)",
    ),
    (
        "ISC",
        "ISC License",
        r"(?i)Permission to use,?\s+copy,?\s+modify,?\s+and(?:/or)?\s+distribute",
    ),
    (
        "MPL-2.0",
        "Mozilla Public License 2.0",
        r"(?i)Mozilla Public License,?\s+(?:Version|v\.?)\s*2\.0",
    ),
    (
        "Unlicense",
        "The Unlicense",
        r"(?i)This is free and unencumbered software released into the public domain",
    ),
    (
        "CC0-1.0",
        "Creative Commons Zero v1.0",
        r"(?i)CC0 1\.0 Universal|Creative Commons.*?CC0",
    ),
    (
        "0BSD",
        "Zero-Clause BSD",
        r"(?i)Permission to use,?\s+copy,?\s+modify.*?0-clause BSD",
    ),
    (
        "Zlib",
        "zlib License",
        r"(?i)This software is provided 'as-is'.*?freely",
    ),
];

static LICENSE_FILE_NAMES: &[&str] = &[
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENSE.rst",
    "LICENCE",
    "LICENCE.md",
    "LICENCE.txt",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
    "NOTICE",
    "NOTICE.md",
    "NOTICE.txt",
];

/// Detect license from a single file and print human-readable output
pub fn detect_license(path: &str) {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            println!("License not detected.");
            return;
        }
    };
    let detections = detect_licenses_in_text(&content, path);
    if detections.is_empty() {
        println!("License not detected.");
    } else {
        for d in &detections {
            println!(
                "Detected license: {} ({}) confidence={:.0}%",
                d.spdx_id,
                d.name,
                d.confidence * 100.0
            );
        }
    }
}

/// Scan a directory tree for license files and return structured detections
pub fn scan_licenses_in_tree(root: &Path) -> Vec<LicenseDetection> {
    let mut all = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_name = entry
            .file_name()
            .to_str()
            .unwrap_or_default()
            .to_uppercase();
        let is_license_file = LICENSE_FILE_NAMES
            .iter()
            .any(|n| n.to_uppercase() == file_name);
        if !is_license_file {
            continue;
        }
        if let Ok(content) = fs::read_to_string(entry.path()) {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string();
            let detections = detect_licenses_in_text(&content, &rel);
            all.extend(detections);
        }
    }
    all
}

/// Build a full license report as JSON value
pub fn build_license_report(root: &Path) -> LicenseReport {
    let detections = scan_licenses_in_tree(root);
    let mut unique: Vec<String> = detections.iter().map(|d| d.spdx_id.clone()).collect();
    unique.sort();
    unique.dedup();
    let scanned = WalkDir::new(root)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_str().unwrap_or_default().to_uppercase();
            LICENSE_FILE_NAMES.iter().any(|n| n.to_uppercase() == name)
        })
        .count();
    LicenseReport {
        summary: LicenseSummary {
            total_files_scanned: scanned,
            total_licenses_found: detections.len(),
            unique_licenses: unique,
        },
        detections,
    }
}

fn detect_licenses_in_text(content: &str, file_path: &str) -> Vec<LicenseDetection> {
    let mut detections = Vec::new();
    for &(spdx, name, pattern) in LICENSE_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(content) {
                // Higher confidence for exact SPDX header matches
                let confidence = if content.contains(&format!("SPDX-License-Identifier: {}", spdx))
                {
                    1.0
                } else {
                    0.85
                };
                detections.push(LicenseDetection {
                    spdx_id: spdx.to_string(),
                    name: name.to_string(),
                    file: file_path.to_string(),
                    confidence,
                });
            }
        }
    }
    // Check for SPDX headers even if no pattern matched
    if detections.is_empty() {
        if let Some(caps) = Regex::new(r"SPDX-License-Identifier:\s*(\S+)")
            .ok()
            .and_then(|re| re.captures(content))
        {
            if let Some(id) = caps.get(1) {
                detections.push(LicenseDetection {
                    spdx_id: id.as_str().to_string(),
                    name: id.as_str().to_string(),
                    file: file_path.to_string(),
                    confidence: 1.0,
                });
            }
        }
    }
    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_mit() {
        let text = "Permission is hereby granted, free of charge, to any person obtaining a copy";
        let d = detect_licenses_in_text(text, "LICENSE");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].spdx_id, "MIT");
    }

    #[test]
    fn test_detect_apache2() {
        let text = "Licensed under the Apache License, Version 2.0";
        let d = detect_licenses_in_text(text, "LICENSE");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].spdx_id, "Apache-2.0");
    }

    #[test]
    fn test_detect_spdx_header() {
        let text = "// SPDX-License-Identifier: MPL-2.0\nsome code";
        let d = detect_licenses_in_text(text, "lib.rs");
        assert!(d.iter().any(|x| x.spdx_id == "MPL-2.0"));
    }

    #[test]
    fn test_no_match() {
        let text = "This is just some random text with no license.";
        let d = detect_licenses_in_text(text, "README.md");
        assert!(d.is_empty());
    }
}
