use regex::Regex;
use std::fs;

/// Detect common OSS license text patterns
pub fn detect_license(path: &str) {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            println!("License not detected.");
            return;
        }
    };
    let licenses = vec![
        ("MIT", r"Permission is hereby granted, free of charge"),
        (
            "GPL",
            r"This program is free software.*?General Public License",
        ),
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
