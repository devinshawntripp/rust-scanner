use xmltree::Element;
use std::fs::File;
use std::io::BufReader;

/// Parse RedHat OVAL XML and check for a CVE fix
pub fn check_redhat_cve(cve: &str, oval_path: &str) {
    let file = File::open(oval_path).expect("Cannot open OVAL file");
    let reader = BufReader::new(file);
    let root = Element::parse(reader).expect("Invalid XML");
    for def in root.get_child("definitions").and_then(|d| d.get_child("definition")) {
        let title = def.get_child("metadata").and_then(|m| m.get_child("title")).map(|e| e.text.clone().unwrap_or_default()).unwrap_or_default();
        if title.contains(cve) {
            println!("{} is mentioned: {}", cve, title);
            return;
        }
    }
    println!("{} not found in Red Hat OVAL DB", cve);
}
