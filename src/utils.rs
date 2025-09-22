use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;
use std::path::PathBuf;
use std::fs::OpenOptions;
use std::io::Write;

pub fn run() {
    println!("Module running...");
}

/// Compute SHA-256 hash of a file using a streaming reader
pub fn hash_file_stream(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read_count = file.read(&mut buffer)?;
        if read_count == 0 {
            break;
        }
        hasher.update(&buffer[..read_count]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn write_output_if_needed(out: &Option<String>, json: &str) {
    if let Some(path) = out {
        if let Err(e) = std::fs::write(path, json) {
            eprintln!("Failed to write output to {}: {}", path, e);
        }
    }
}

pub fn run_syft_generate_sbom(target_dir: &str, out_path: &str) -> io::Result<()> {
    // Requires syft to be installed and on PATH
    let status = Command::new("syft")
        .arg(target_dir)
        .arg("-o")
        .arg("cyclonedx-json")
        .arg("-q")
        .arg("--file")
        .arg(out_path)
        .status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "syft failed"));
    }
    Ok(())
}

pub fn parse_name_version_from_filename(filename: &str) -> Option<(String, String)> {
    // Strip common archive extensions
    let mut name = filename.to_string();
    for ext in [".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz", ".zip", ".tar"] {
        if name.ends_with(ext) {
            name.truncate(name.len() - ext.len());
            break;
        }
    }
    // Take basename
    let base = std::path::Path::new(&name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&name);

    // Find last '-' and assume version starts with a digit after it
    if let Some(idx) = base.rfind('-') {
        let (n, v) = base.split_at(idx);
        let ver = v.trim_start_matches('-');
        if ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Some((n.to_string(), ver.to_string()));
        }
    }
    None
}

pub fn progress(stage: &str, detail: &str) {
    let event = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "stage": stage,
        "detail": detail,
    });
    let line = format!("{}\n", event.to_string());
    if std::env::var("SCANNER_PROGRESS_STDERR").ok().as_deref() == Some("1") {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    if let Ok(path) = std::env::var("SCANNER_PROGRESS_FILE") {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}
