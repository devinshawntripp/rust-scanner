use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

/// Compute and print SHA256 hash of a binary file
pub fn scan_binary(path: &str) {
    match File::open(path) {
        Ok(mut file) => {
            let mut buffer = Vec::new();
            if let Err(e) = file.read_to_end(&mut buffer) {
                eprintln!("Error reading file: {}", e);
                return;
            }
            let mut hasher = Sha256::new();
            hasher.update(buffer);
            let result = hasher.finalize();
            println!("SHA256: {:x}", result);
        }
        Err(e) => eprintln!("Failed to open {}: {}", path, e),
    }
}
