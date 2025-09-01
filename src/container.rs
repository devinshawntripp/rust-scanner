use std::fs::File;
use tar::Archive;
use flate2::read::GzDecoder;

/// Extracts a tar archive (optionally gzipped) to ./extracted
pub fn extract_tar(tar_path: &str) {
    let file = File::open(tar_path).expect("Could not open tar file");

    let mut archive: Archive<Box<dyn std::io::Read>> = if tar_path.ends_with(".gz") {
        Archive::new(Box::new(GzDecoder::new(file)))
    } else {
        Archive::new(Box::new(file))
    };

    match archive.unpack("extracted") {
        Ok(_) => println!("Extracted to ./extracted"),
        Err(e) => eprintln!("Failed to extract: {}", e),
    }
}
