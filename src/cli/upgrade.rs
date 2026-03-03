//! Self-update functionality for the scanrook CLI binary.

pub fn run_upgrade(check: bool) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let repo = "devinshawntripp/rust-scanner";
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("scanrook-cli/{}", current))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let resp = client.get(&url).send()?;
    let body: serde_json::Value = resp.json()?;
    let latest = body["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v');
    if latest.is_empty() {
        anyhow::bail!("No published release found for {}", repo);
    }
    if latest == current {
        println!("scanrook {} is already up to date", current);
        return Ok(());
    }
    println!("Current version: {}", current);
    println!("Latest version:  {}", latest);
    if check {
        println!("Update available. Run `scanrook upgrade` to install.");
        return Ok(());
    }
    // Determine platform
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    let asset = format!("scanrook-{}-{}-{}.tar.gz", latest, os, arch);
    let asset_url = format!(
        "https://github.com/{}/releases/download/v{}/{}",
        repo, latest, asset
    );
    println!("Downloading {} ...", asset);
    let dl = match client.get(&asset_url).send() {
        Ok(r) if r.status().is_success() => r.bytes()?,
        Ok(r) => {
            anyhow::bail!("Download failed: HTTP {}", r.status());
        }
        Err(e) => {
            anyhow::bail!("Download failed: {}", e);
        }
    };
    // Extract tarball to temp dir
    let tmp = tempfile::tempdir()?;
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&dl));
    let mut archive = tar::Archive::new(gz);
    archive.unpack(tmp.path())?;
    let new_bin = tmp.path().join("scanrook");
    if !new_bin.exists() {
        anyhow::bail!("Archive missing scanrook binary");
    }
    // Replace current binary
    let current_exe = std::env::current_exe()?;
    let backup = current_exe.with_extension("old");
    if let Err(e) = std::fs::rename(&current_exe, &backup) {
        anyhow::bail!(
            "Failed to backup current binary: {}. Try running with sudo: sudo scanrook upgrade",
            e
        );
    }
    if let Err(e) = std::fs::copy(&new_bin, &current_exe) {
        // Restore backup
        let _ = std::fs::rename(&backup, &current_exe);
        anyhow::bail!(
            "Failed to install new binary: {}. Try running with sudo: sudo scanrook upgrade",
            e
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::remove_file(&backup);
    println!("Upgraded scanrook {} -> {}", current, latest);
    Ok(())
}
