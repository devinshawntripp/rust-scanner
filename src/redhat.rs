use xmltree::Element;
use std::fs::File;
use std::io::BufReader;

/// Extract text content of an XML node
fn get_text(element: &Element) -> String {
    for child in &element.children {
        if let xmltree::XMLNode::Text(txt) = child {
            return txt.clone();
        }
    }
    String::new()
}

/// Parse RedHat OVAL XML and check for a CVE fix
pub fn check_redhat_cve(cve: &str, oval_path: &str) {
    let file = File::open(oval_path).expect("Cannot open OVAL file");
    let reader = BufReader::new(file);
    let root = Element::parse(reader).expect("Invalid XML");

    if let Some(defs) = root.get_child("definitions") {
        for def in &defs.children {
            if let xmltree::XMLNode::Element(def_el) = def {
                if let Some(metadata) = def_el.get_child("metadata") {
                    if let Some(title_el) = metadata.get_child("title") {
                        let title = get_text(title_el);
                        if title.contains(cve) {
                            println!("✅ {} is mentioned in Red Hat OVAL: {}", cve, title);
                            return;
                        }
                    }
                }
            }
        }
    }

    println!("❌ {} not found in Red Hat OVAL DB", cve);
}
