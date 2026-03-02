//! Container image pull and save via docker/podman.

use crate::utils::progress;
use std::fs;
use tempfile::{tempdir, TempDir};

/// Pull and save a container image to a temporary tar file using docker or podman.
///
/// Returns (TempDir, path_string) — the TempDir must be kept alive for the duration
/// of scanning; it is cleaned up when dropped.
pub fn pull_and_save_image(image_ref: &str) -> anyhow::Result<(TempDir, String)> {
    use std::process::Command;

    let tmpdir = tempdir()?;
    let tar_path = tmpdir.path().join("image.tar");
    let tar_str = tar_path.to_string_lossy().to_string();

    // Try docker first, then podman
    for runtime in &["docker", "podman"] {
        // Check if runtime exists
        let exists = Command::new(runtime)
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if exists.is_err() || !exists.unwrap().success() {
            continue;
        }

        progress("image.runtime", runtime);

        // Try to save directly (image may already be pulled)
        let save = Command::new(runtime)
            .arg("save")
            .arg(image_ref)
            .arg("-o")
            .arg(&tar_str)
            .output()?;

        if save.status.success() && tar_path.exists() {
            let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
            if size > 0 {
                progress("image.saved", &format!("runtime={} size={}", runtime, size));
                return Ok((tmpdir, tar_str));
            }
        }

        // Image not pulled yet — pull first, then save
        progress(
            "image.pull.start",
            &format!("{} pull {}", runtime, image_ref),
        );
        let pull = Command::new(runtime).arg("pull").arg(image_ref).output()?;

        if !pull.status.success() {
            let stderr = String::from_utf8_lossy(&pull.stderr);
            progress(
                "image.pull.error",
                &format!("{}: {}", runtime, stderr.trim()),
            );
            continue;
        }

        // Now save
        let save = Command::new(runtime)
            .arg("save")
            .arg(image_ref)
            .arg("-o")
            .arg(&tar_str)
            .output()?;

        if save.status.success() && tar_path.exists() {
            let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
            if size > 0 {
                progress("image.saved", &format!("runtime={} size={}", runtime, size));
                return Ok((tmpdir, tar_str));
            }
        }

        let stderr = String::from_utf8_lossy(&save.stderr);
        progress(
            "image.save.error",
            &format!("{}: {}", runtime, stderr.trim()),
        );
    }

    Err(anyhow::anyhow!(
        "No container runtime (docker/podman) available or failed to save image '{}'. \
         Install docker or podman, or use --file with a pre-saved tar.",
        image_ref
    ))
}
