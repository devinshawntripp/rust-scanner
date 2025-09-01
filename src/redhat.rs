use xmltree::{Element, XMLNode};
use std::fs::File;
use std::io::BufReader;

/// Helper function to extract text from an element node
fn get_text(element: &Element) -> String {
    for child in &element.children {
        if let XMLNode::Text(text) = child {
            return text.trim().to_string();
        }
    }
    String::new()
}

/// Check if a CVE exists in a Red Hat OVAL XML file
pub fn check_redhat_cve(cve: &str, oval_path: &str) {
    let file = match File::open(oval_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Could not open OVAL file: {}", e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let root = match Element::parse(reader) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse XML: {}", e);
            return;
        }
    };

    if let Some(defs) = root.get_child("definitions") {
        for child in &defs.children {
            if let XMLNode::Element(def_el) = child {
                if let Some(metadata) = def_el.get_child("metadata") {
                    if let Some(title) = metadata.get_child("title") {
                        let title_text = get_text(title);
                        if title_text.contains(cve) {
                            println!("✅ Found in Red Hat OVAL: {}", title_text);
                            return;
                        }
                    }
                }
            }
        }
    }

    println!("❌ {} not found in Red Hat OVAL definitions.", cve);
}
