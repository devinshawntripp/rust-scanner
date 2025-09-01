use std::fs;
use regex::Regex;

/// Detect common OSS license text patterns
pub fn detect_license(path: &str) {
    let content = fs::read_to_string(path).expect("Cannot read license file");
    let licenses = vec![
        ("MIT", r"Permission is hereby granted, free of charge"),
        ("GPL", r"This program is free software.*?General Public License"),
    ];
    for (name, pattern) in licenses {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(&content) {
            println!("Detected license: {}", name);
            return;
        }
    }
    println!("License not detected.");
}
