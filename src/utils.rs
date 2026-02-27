use sha2::{Digest, Sha256};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use walkdir::WalkDir;

/// Global cached file handle for progress output.
/// Initialized on first call to `progress()` when SCANNER_PROGRESS_FILE is set.
static PROGRESS_FILE_HANDLE: OnceLock<Option<Mutex<BufWriter<File>>>> = OnceLock::new();
static PROGRESS_TTY_STATE: OnceLock<Mutex<ProgressTtyState>> = OnceLock::new();

#[derive(Default)]
struct ProgressTtyState {
    total_events: usize,
    lines: Vec<String>,
    rendered_lines: usize,
    max_lines: usize,
}

fn level_rank(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        "debug" => 3,
        _ => 2,
    }
}

fn configured_level() -> String {
    std::env::var("SCANNER_LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .to_lowercase()
}

fn configured_format() -> String {
    std::env::var("SCANNER_LOG_FORMAT")
        .unwrap_or_else(|_| "text".to_string())
        .to_lowercase()
}

fn stage_level(stage: &str) -> &'static str {
    let s = stage.to_lowercase();
    if s.ends_with(".err") || s.ends_with(".error") {
        return "error";
    }
    if s.ends_with(".warn") || s.contains(".warn.") {
        return "warn";
    }
    if s.ends_with(".timing") {
        return "debug";
    }
    "info"
}

fn stage_component(stage: &str) -> String {
    stage
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("scanner")
        .to_string()
}

fn sanitize_detail(detail: &str) -> String {
    detail
        .replace('\n', " ")
        .replace('\r', " ")
        .trim()
        .to_string()
}

fn as_text_line(ts: &str, level: &str, component: &str, stage: &str, detail: &str) -> String {
    let level_up = level.to_uppercase();
    if detail.is_empty() {
        format!("{}\t{}\t[{}]\t{}", ts, level_up, component, stage)
    } else {
        format!(
            "{}\t{}\t[{}]\t{}\t{}",
            ts, level_up, component, stage, detail
        )
    }
}

fn compact_progress_enabled() -> bool {
    std::env::var("SCANNER_PROGRESS_COMPACT")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        && std::io::stderr().is_terminal()
}

fn compact_progress_max_lines() -> usize {
    std::env::var("SCANNER_PROGRESS_MAX_LINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|n| n.clamp(4, 24))
        .unwrap_or(8)
}

fn compact_trim_line(line: &str, max: usize) -> String {
    let mut out = line.trim().to_string();
    if out.chars().count() <= max {
        return out;
    }
    out = out.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn panel_state() -> &'static Mutex<ProgressTtyState> {
    PROGRESS_TTY_STATE.get_or_init(|| {
        Mutex::new(ProgressTtyState {
            total_events: 0,
            lines: Vec::new(),
            rendered_lines: 0,
            max_lines: compact_progress_max_lines(),
        })
    })
}

fn clear_rendered_panel_lines(stderr: &mut std::io::Stderr, count: usize) {
    if count == 0 {
        return;
    }
    let _ = write!(stderr, "\x1b[{}F", count);
    for _ in 0..count {
        let _ = write!(stderr, "\x1b[2K\x1b[1E");
    }
    let _ = write!(stderr, "\x1b[{}F", count);
}

fn render_compact_progress_line(line: &str) {
    let state_lock = panel_state();
    if let Ok(mut state) = state_lock.lock() {
        state.total_events = state.total_events.saturating_add(1);
        if state.max_lines == 0 {
            state.max_lines = compact_progress_max_lines();
        }
        state.lines.push(compact_trim_line(line, 140));
        if state.lines.len() > state.max_lines {
            let drop_n = state.lines.len().saturating_sub(state.max_lines);
            state.lines.drain(0..drop_n);
        }

        let mut panel_lines: Vec<String> = Vec::with_capacity(state.lines.len() + 2);
        panel_lines.push(format!(
            "┌ ScanRook workflow events={} showing_last={}",
            state.total_events,
            state.lines.len()
        ));
        for row in &state.lines {
            panel_lines.push(format!("│ {}", row));
        }
        panel_lines.push("└ scanning...".to_string());

        let mut stderr = std::io::stderr();
        clear_rendered_panel_lines(&mut stderr, state.rendered_lines);
        for row in &panel_lines {
            let _ = writeln!(stderr, "{}", row);
        }
        let _ = stderr.flush();
        state.rendered_lines = panel_lines.len();
    }
}

pub fn progress_panel_finish(summary: &str) {
    if !compact_progress_enabled() {
        return;
    }
    let state_lock = panel_state();
    if let Ok(mut state) = state_lock.lock() {
        let mut stderr = std::io::stderr();
        clear_rendered_panel_lines(&mut stderr, state.rendered_lines);
        let _ = writeln!(
            stderr,
            "✓ {} ({})",
            summary.trim(),
            chrono::Local::now().format("%H:%M:%S")
        );
        let _ = stderr.flush();
        state.rendered_lines = 0;
        state.total_events = 0;
        state.lines.clear();
    }
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
    for ext in [
        ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz", ".zip", ".tar",
    ] {
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
        if ver
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            return Some((n.to_string(), ver.to_string()));
        }
    }
    None
}

pub fn progress(stage: &str, detail: &str) {
    let ts = chrono::Local::now().to_rfc3339();
    let level = stage_level(stage).to_string();
    let component = stage_component(stage);
    let event_name = stage.to_string();
    let detail_clean = sanitize_detail(detail);
    let event = serde_json::json!({
        "ts": ts,
        "level": level,
        "component": component,
        "event": event_name,
        "stage": stage,
        "detail": detail_clean,
    });
    let json_line = format!("{}\n", event);
    if std::env::var("SCANNER_PROGRESS_STDERR").ok().as_deref() == Some("1") {
        let desired = configured_level();
        if level_rank(stage_level(stage)) <= level_rank(&desired) {
            if compact_progress_enabled() {
                let text_line = as_text_line(
                    event["ts"].as_str().unwrap_or(""),
                    event["level"].as_str().unwrap_or("info"),
                    event["component"].as_str().unwrap_or("scanner"),
                    event["stage"].as_str().unwrap_or(stage),
                    event["detail"].as_str().unwrap_or(""),
                );
                render_compact_progress_line(&text_line);
            } else if configured_format() == "json" {
                let _ = std::io::stderr().write_all(json_line.as_bytes());
            } else {
                let text_line = as_text_line(
                    event["ts"].as_str().unwrap_or(""),
                    event["level"].as_str().unwrap_or("info"),
                    event["component"].as_str().unwrap_or("scanner"),
                    event["stage"].as_str().unwrap_or(stage),
                    event["detail"].as_str().unwrap_or(""),
                );
                let _ = std::io::stderr().write_all(format!("{}\n", text_line).as_bytes());
            }
        }
    }
    // Use cached file handle to avoid re-opening on every progress event.
    let handle = PROGRESS_FILE_HANDLE.get_or_init(|| {
        if let Ok(path) = std::env::var("SCANNER_PROGRESS_FILE") {
            if let Ok(f) = OpenOptions::new().create(true).append(true).open(&path) {
                return Some(Mutex::new(BufWriter::new(f)));
            }
        }
        None
    });
    if let Some(mutex) = handle {
        if let Ok(mut writer) = mutex.lock() {
            let _ = writer.write_all(json_line.as_bytes());
            let _ = writer.flush();
        }
    }
}

pub fn progress_timing(stage: &str, started: Instant) {
    progress(
        &format!("{}.timing", stage),
        &format!("ms={}", started.elapsed().as_millis()),
    );
}

pub fn collect_file_tree(root: &Path, limit: usize) -> Vec<crate::report::FileEntry> {
    let cap = if limit == 0 { 20_000 } else { limit };
    let hash_max_bytes: u64 = std::env::var("SCANNER_TREE_HASH_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut out: Vec<crate::report::FileEntry> = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if out.len() >= cap {
            break;
        }
        if entry.path() == root {
            continue;
        }
        let rel = match entry.path().strip_prefix(root) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str.is_empty() {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let file_type = entry.file_type();
        let entry_type = if file_type.is_dir() {
            "dir"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };

        let size_bytes = if file_type.is_file() {
            Some(metadata.len())
        } else {
            None
        };

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(format!("{:o}", metadata.permissions().mode() & 0o7777))
        };
        #[cfg(not(unix))]
        let mode = None;

        let mtime = metadata
            .modified()
            .ok()
            .map(|m| chrono::DateTime::<chrono::Utc>::from(m).to_rfc3339());

        let sha256 =
            if file_type.is_file() && hash_max_bytes > 0 && metadata.len() <= hash_max_bytes {
                hash_file_stream(entry.path().to_string_lossy().as_ref()).ok()
            } else {
                None
            };

        let parent_path = rel
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .filter(|p| !p.is_empty());

        out.push(crate::report::FileEntry {
            path: rel_str,
            entry_type: entry_type.to_string(),
            size_bytes,
            mode,
            mtime,
            sha256,
            parent_path,
        });
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}
