use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};

pub fn cache_key(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p.as_bytes());
        hasher.update(&[0u8]);
    }
    format!("{:x}", hasher.finalize())
}

pub fn cache_get(cache_dir: Option<&Path>, key: &str) -> Option<Vec<u8>> {
    let dir = cache_dir?;
    let path = dir.join(key);
    match fs::File::open(&path) {
        Ok(mut f) => {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() { Some(buf) } else { None }
        }
        Err(_) => None,
    }
}

pub fn cache_put(cache_dir: Option<&Path>, key: &str, data: &[u8]) {
    if let Some(dir) = cache_dir {
        let _ = fs::create_dir_all(dir);
        let path = dir.join(key);
        if let Ok(mut f) = fs::File::create(path) {
            let _ = f.write_all(data);
        }
    }
}

