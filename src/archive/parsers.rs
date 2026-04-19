//! Lock file and manifest parsers for application-level package detection.

use crate::container::PackageCoordinate;
use super::push_if_new;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// --- npm ---

pub(super) fn parse_npm_lockfile(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let json: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return };
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            if key.is_empty() { continue; }
            let name = key.strip_prefix("node_modules/").unwrap_or(key).to_string();
            let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let license = val.get("license").and_then(|l| l.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
            super::push_if_new_with_license(pkgs, seen, "npm", &name, &version, license);
        }
    } else if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        parse_npm_v1_deps(deps, pkgs, seen);
    }
}

fn parse_npm_v1_deps(deps: &serde_json::Map<String, serde_json::Value>, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    for (name, val) in deps {
        let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("");
        push_if_new(pkgs, seen, "npm", name, version);
        if let Some(sub) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_deps(sub, pkgs, seen);
        }
    }
}

pub(super) fn parse_yarn_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut current_name = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(_at) = trimmed.find('@') {
                let rest = &trimmed[..trimmed.len().saturating_sub(1)];
                let name = if rest.starts_with('"') {
                    let unquoted = rest.trim_matches('"');
                    if let Some(last_at) = unquoted.rfind('@') {
                        if last_at > 0 { &unquoted[..last_at] } else { unquoted }
                    } else { unquoted }
                } else if let Some(comma) = rest.find(',') {
                    let first = &rest[..comma];
                    if let Some(last_at) = first.rfind('@') { &first[..last_at] } else { first }
                } else if let Some(last_at) = rest.rfind('@') {
                    &rest[..last_at]
                } else { rest };
                current_name = name.trim_matches('"').to_string();
            }
        } else if trimmed.starts_with("version ") {
            let version = trimmed.strip_prefix("version ").unwrap_or("").trim().trim_matches('"');
            if !current_name.is_empty() {
                push_if_new(pkgs, seen, "npm", &current_name, version);
            }
        }
    }
}

pub(super) fn parse_pnpm_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    for line in text.lines() {
        let trimmed = line.trim().trim_start_matches('\'').trim_end_matches('\'');
        if let Some(rest) = trimmed.strip_prefix('/') {
            let entry = rest.trim_end_matches(':');
            if let Some((name, version)) = entry.rsplit_once('@') {
                let version = version.split('(').next().unwrap_or(version);
                push_if_new(pkgs, seen, "npm", name, version);
            } else if let Some((name, version)) = entry.rsplit_once('/') {
                if !version.is_empty() && version.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    push_if_new(pkgs, seen, "npm", name, version);
                }
            }
        }
        if !trimmed.starts_with('/') && !trimmed.starts_with('#') && !trimmed.starts_with(' ') {
            let entry = trimmed.trim_end_matches(':');
            if let Some((name, version)) = entry.rsplit_once('@') {
                if !name.is_empty() && !version.is_empty() && version.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    let version = version.split('(').next().unwrap_or(version);
                    push_if_new(pkgs, seen, "npm", name, version);
                }
            }
        }
    }
}

// --- Python ---

pub(super) fn parse_requirements_txt(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') { continue; }
        if let Some(idx) = trimmed.find("==") {
            let name = trimmed[..idx].trim();
            let version = trimmed[idx + 2..].trim().split(';').next().unwrap_or("").trim();
            push_if_new(pkgs, seen, "PyPI", name, version);
        }
    }
}

pub(super) fn parse_pipfile_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let json: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return };
    for section in &["default", "develop"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (name, val) in deps {
                let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("").strip_prefix("==").unwrap_or("");
                push_if_new(pkgs, seen, "PyPI", name, version);
            }
        }
    }
}

pub(super) fn parse_poetry_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut current_name = String::new();
    let mut current_version = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if !current_name.is_empty() && !current_version.is_empty() {
                push_if_new(pkgs, seen, "PyPI", &current_name, &current_version);
            }
            current_name.clear(); current_version.clear();
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = rest.trim_matches('"').to_string();
        }
    }
    if !current_name.is_empty() && !current_version.is_empty() {
        push_if_new(pkgs, seen, "PyPI", &current_name, &current_version);
    }
}

pub(super) fn path_contains_dist_info(path: &Path) -> bool {
    path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).map_or(false, |n| n.ends_with(".dist-info"))
}

pub(super) fn parse_dist_info_metadata(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut name = String::new();
    let mut version = String::new();
    let mut license: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() || line.starts_with(' ') {
            if !line.starts_with(' ') { break; }
            continue;
        }
        if let Some(rest) = line.strip_prefix("Name: ") { name = rest.trim().to_string(); }
        else if let Some(rest) = line.strip_prefix("Version: ") { version = rest.trim().to_string(); }
        else if license.is_none() {
            if let Some(rest) = line.strip_prefix("License: ") {
                let l = rest.trim();
                if !l.is_empty() && l != "UNKNOWN" {
                    license = Some(l.to_string());
                }
            }
        }
    }
    super::push_if_new_with_license(pkgs, seen, "PyPI", &name, &version, license);
}

// --- Ruby ---

pub(super) fn parse_gemfile_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut in_specs = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "specs:" { in_specs = true; continue; }
        if in_specs {
            if !line.starts_with(' ') && !line.starts_with('\t') { in_specs = false; continue; }
            let parts = trimmed.trim();
            if let Some(paren) = parts.find('(') {
                let name = parts[..paren].trim();
                let version = parts[paren + 1..].trim_end_matches(')').trim();
                if !name.contains(' ') { push_if_new(pkgs, seen, "RubyGems", name, version); }
            }
        }
    }
}

// --- Go ---

pub(super) fn parse_go_sum(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let module = parts[0];
            let version_with_v = parts[1].strip_suffix("/go.mod").unwrap_or(parts[1]);
            push_if_new(pkgs, seen, "Go", module, version_with_v);
        }
    }
}

pub(super) fn parse_go_mod(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut in_require = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "require (" { in_require = true; continue; }
        if trimmed == ")" { in_require = false; continue; }
        if in_require {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && !parts[0].starts_with("//") { push_if_new(pkgs, seen, "Go", parts[0], parts[1]); }
        }
        if let Some(rest) = trimmed.strip_prefix("require ") {
            if !rest.starts_with('(') {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 { push_if_new(pkgs, seen, "Go", parts[0], parts[1]); }
            }
        }
    }
}

// --- Rust ---

pub(super) fn parse_cargo_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut current_name = String::new();
    let mut current_version = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if !current_name.is_empty() && !current_version.is_empty() {
                push_if_new(pkgs, seen, "crates.io", &current_name, &current_version);
            }
            current_name.clear(); current_version.clear();
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = rest.trim_matches('"').to_string();
        }
    }
    if !current_name.is_empty() && !current_version.is_empty() {
        push_if_new(pkgs, seen, "crates.io", &current_name, &current_version);
    }
}

// --- Java / Maven / Gradle ---

pub(super) fn parse_pom_xml(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let re = regex::Regex::new(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?"
    ).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let group = cap.get(1).map_or("", |m| m.as_str());
            let artifact = cap.get(2).map_or("", |m| m.as_str());
            let version = cap.get(3).map_or("", |m| m.as_str());
            let name = format!("{}:{}", group, artifact);
            push_if_new(pkgs, seen, "Maven", &name, version);
        }
    }
}

pub(super) fn parse_gradle_lockfile(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        let entry = trimmed.split('=').next().unwrap_or(trimmed);
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() >= 3 {
            let name = format!("{}:{}", parts[0], parts[1]);
            push_if_new(pkgs, seen, "Maven", &name, parts[2]);
        }
    }
}

// --- NuGet / .NET ---

pub(super) fn parse_nuget_packages_config(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let re = regex::Regex::new(r#"<package\s+id="([^"]+)"\s+version="([^"]+)""#).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());
            push_if_new(pkgs, seen, "NuGet", name, version);
        }
    }
}

pub(super) fn parse_csproj(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let re = regex::Regex::new(r#"<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)""#).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());
            push_if_new(pkgs, seen, "NuGet", name, version);
        }
    }
}

// --- PHP ---

pub(super) fn parse_composer_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let json: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return };
    for section in &["packages", "packages-dev"] {
        if let Some(arr) = json.get(section).and_then(|p| p.as_array()) {
            for pkg in arr {
                let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("").trim_start_matches('v');
                push_if_new(pkgs, seen, "Packagist", name, version);
            }
        }
    }
}

// --- Dart / Flutter ---

pub(super) fn parse_pubspec_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut in_packages = false;
    let mut current_name = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "packages:" { in_packages = true; continue; }
        if in_packages {
            if line.starts_with("  ") && !line.starts_with("    ") {
                current_name = trimmed.trim_end_matches(':').to_string();
            }
            if line.starts_with("      version:") || line.starts_with("    version:") {
                if let Some(rest) = trimmed.strip_prefix("version:") {
                    let version = rest.trim().trim_matches('"');
                    if !current_name.is_empty() { push_if_new(pkgs, seen, "Pub", &current_name, version); }
                }
            }
            if !line.starts_with(' ') && !trimmed.is_empty() && trimmed != "packages:" { in_packages = false; }
        }
    }
}

// --- Swift ---

pub(super) fn parse_swift_resolved(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let json: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return };
    let pins = json.get("pins").or_else(|| json.get("object").and_then(|o| o.get("pins")));
    if let Some(pins) = pins.and_then(|p| p.as_array()) {
        for pin in pins {
            let name = pin.get("identity").or_else(|| pin.get("package")).and_then(|n| n.as_str()).unwrap_or("");
            let version = pin.get("state").and_then(|s| s.get("version").or_else(|| s.get("checkoutState").and_then(|c| c.get("version")))).and_then(|v| v.as_str()).unwrap_or("");
            push_if_new(pkgs, seen, "SwiftURL", name, version);
        }
    }
}

// --- CocoaPods ---

pub(super) fn parse_podfile_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let mut in_pods = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "PODS:" { in_pods = true; continue; }
        if in_pods {
            if !line.starts_with(' ') && !line.starts_with('\t') { in_pods = false; continue; }
            if let Some(rest) = trimmed.strip_prefix("- ") {
                if let Some(paren) = rest.find('(') {
                    let name = rest[..paren].trim();
                    let version = rest[paren + 1..].split(')').next().unwrap_or("").trim();
                    push_if_new(pkgs, seen, "CocoaPods", name, version);
                }
            }
        }
    }
}

// --- Elixir ---

pub(super) fn parse_mix_lock(path: &Path, pkgs: &mut Vec<PackageCoordinate>, seen: &mut HashSet<String>) {
    let text = match fs::read_to_string(path) { Ok(t) => t, Err(_) => return };
    let re = regex::Regex::new(r#""([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)""#).ok();
    if let Some(re) = re {
        for cap in re.captures_iter(&text) {
            let name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());
            push_if_new(pkgs, seen, "Hex", name, version);
        }
    }
}
