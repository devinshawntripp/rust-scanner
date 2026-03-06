//! comps.xml parser for ISO package group detection.
//!
//! Parses the comps.xml format used in RPM-based Linux distributions to define
//! package groups and installation environments. Used in deep mode to filter
//! available packages down to those that would be installed by default.

use std::collections::HashSet;
use xmltree::{Element, XMLNode};

/// Parsed representation of a comps.xml file.
pub struct CompsData {
    pub environments: Vec<CompsEnvironment>,
    pub groups: Vec<CompsGroup>,
}

/// An installation environment (e.g. "Server", "Workstation").
pub struct CompsEnvironment {
    pub id: String,
    pub name: String,
    pub mandatory_groups: Vec<String>,
    pub optional_groups: Vec<String>,
}

/// A package group (e.g. "core", "base").
pub struct CompsGroup {
    pub id: String,
    pub name: String,
    pub mandatory_packages: Vec<String>,
    pub default_packages: Vec<String>,
    pub optional_packages: Vec<String>,
}

impl CompsData {
    /// Get package names for the default install of the largest environment.
    /// Includes mandatory + default packages from all mandatory groups.
    /// Returns (environment_name, package_set).
    pub fn default_install_packages(&self) -> (Option<String>, HashSet<String>) {
        // Find environment with most mandatory groups (broadest default install)
        let env = self
            .environments
            .iter()
            .max_by_key(|e| e.mandatory_groups.len());

        let Some(env) = env else {
            return (None, HashSet::new());
        };

        let mandatory_group_ids: HashSet<&str> =
            env.mandatory_groups.iter().map(|s| s.as_str()).collect();

        let mut packages = HashSet::new();
        for group in &self.groups {
            if mandatory_group_ids.contains(group.id.as_str()) {
                for pkg in &group.mandatory_packages {
                    packages.insert(pkg.clone());
                }
                for pkg in &group.default_packages {
                    packages.insert(pkg.clone());
                }
            }
        }

        (Some(env.name.clone()), packages)
    }
}

/// Parse comps.xml data into a `CompsData` structure.
pub fn parse_comps_xml(data: &[u8]) -> anyhow::Result<CompsData> {
    let root = Element::parse(data)?;

    let mut environments = Vec::new();
    let mut groups = Vec::new();

    let mut env_nodes = Vec::new();
    collect_descendants_by_local(&root, "environment", &mut env_nodes);
    for env_el in env_nodes {
        let id = child_text_by_local(env_el, "id").unwrap_or_default();
        let name = child_text_by_local(env_el, "name").unwrap_or_default();

        let mut mandatory_groups = Vec::new();
        let mut optional_groups = Vec::new();

        // Parse <grouplist> for mandatory groups
        if let Some(grouplist) = child_by_local(env_el, "grouplist") {
            let mut gids = Vec::new();
            collect_descendants_by_local(grouplist, "groupid", &mut gids);
            for gid in gids {
                let text = element_text(gid);
                if !text.is_empty() {
                    mandatory_groups.push(text);
                }
            }
        }

        // Parse <optionlist> for optional groups
        if let Some(optionlist) = child_by_local(env_el, "optionlist") {
            let mut gids = Vec::new();
            collect_descendants_by_local(optionlist, "groupid", &mut gids);
            for gid in gids {
                let text = element_text(gid);
                if !text.is_empty() {
                    optional_groups.push(text);
                }
            }
        }

        environments.push(CompsEnvironment {
            id,
            name,
            mandatory_groups,
            optional_groups,
        });
    }

    let mut group_nodes = Vec::new();
    collect_descendants_by_local(&root, "group", &mut group_nodes);
    for group_el in group_nodes {
        let id = child_text_by_local(group_el, "id").unwrap_or_default();
        let name = child_text_by_local(group_el, "name").unwrap_or_default();

        let mut mandatory_packages = Vec::new();
        let mut default_packages = Vec::new();
        let mut optional_packages = Vec::new();

        if let Some(packagelist) = child_by_local(group_el, "packagelist") {
            let mut pkg_nodes = Vec::new();
            collect_descendants_by_local(packagelist, "packagereq", &mut pkg_nodes);
            for pkg in pkg_nodes {
                let pkg_type = attr_value(pkg, "type").unwrap_or("default");
                let pkg_name = element_text(pkg);
                if pkg_name.is_empty() {
                    continue;
                }
                match pkg_type {
                    "mandatory" => mandatory_packages.push(pkg_name),
                    "optional" => optional_packages.push(pkg_name),
                    _ => default_packages.push(pkg_name), // "default" or unspecified
                }
            }
        }

        groups.push(CompsGroup {
            id,
            name,
            mandatory_packages,
            default_packages,
            optional_packages,
        });
    }

    Ok(CompsData {
        environments,
        groups,
    })
}

// --- XML helpers (same namespace-stripping pattern as repodata.rs) ---

fn child_by_local<'a>(el: &'a Element, target: &str) -> Option<&'a Element> {
    el.children.iter().find_map(|node| {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                return Some(child);
            }
        }
        None
    })
}

fn child_text_by_local(el: &Element, target: &str) -> Option<String> {
    child_by_local(el, target).map(element_text)
}

fn attr_value<'a>(el: &'a Element, key: &str) -> Option<&'a str> {
    if let Some(v) = el.attributes.get(key) {
        return Some(v);
    }
    for (k, v) in &el.attributes {
        if local_name(k).eq_ignore_ascii_case(key) {
            return Some(v);
        }
    }
    None
}

fn collect_descendants_by_local<'a>(el: &'a Element, target: &str, out: &mut Vec<&'a Element>) {
    for node in &el.children {
        if let XMLNode::Element(child) = node {
            if local_name(&child.name) == target {
                out.push(child);
            }
            collect_descendants_by_local(child, target, out);
        }
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn element_text(el: &Element) -> String {
    let mut out = String::new();
    append_text(el, &mut out);
    out.trim().to_string()
}

fn append_text(el: &Element, out: &mut String) {
    for node in &el.children {
        match node {
            XMLNode::Element(child) => append_text(child, out),
            XMLNode::Text(text) | XMLNode::CData(text) => {
                let t = text.trim();
                if t.is_empty() {
                    continue;
                }
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(t);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_comps_xml() {
        let xml = r#"
<comps>
  <environment>
    <id>server-product-environment</id>
    <name>Server</name>
    <grouplist>
      <groupid>core</groupid>
      <groupid>base</groupid>
    </grouplist>
    <optionlist>
      <groupid>debugging</groupid>
    </optionlist>
  </environment>
  <environment>
    <id>minimal-environment</id>
    <name>Minimal Install</name>
    <grouplist>
      <groupid>core</groupid>
    </grouplist>
    <optionlist/>
  </environment>
  <group>
    <id>core</id>
    <name>Core</name>
    <packagelist>
      <packagereq type="mandatory">bash</packagereq>
      <packagereq type="default">openssh-server</packagereq>
      <packagereq type="optional">vim-enhanced</packagereq>
    </packagelist>
  </group>
  <group>
    <id>base</id>
    <name>Base</name>
    <packagelist>
      <packagereq type="mandatory">coreutils</packagereq>
      <packagereq type="mandatory">glibc</packagereq>
      <packagereq type="default">tar</packagereq>
    </packagelist>
  </group>
  <group>
    <id>debugging</id>
    <name>Debugging Tools</name>
    <packagelist>
      <packagereq type="mandatory">gdb</packagereq>
      <packagereq type="default">strace</packagereq>
    </packagelist>
  </group>
</comps>
"#;
        let comps = parse_comps_xml(xml.as_bytes()).unwrap();

        // Verify environments
        assert_eq!(comps.environments.len(), 2);
        assert_eq!(comps.environments[0].id, "server-product-environment");
        assert_eq!(comps.environments[0].name, "Server");
        assert_eq!(comps.environments[0].mandatory_groups, vec!["core", "base"]);
        assert_eq!(comps.environments[0].optional_groups, vec!["debugging"]);

        assert_eq!(comps.environments[1].id, "minimal-environment");
        assert_eq!(comps.environments[1].name, "Minimal Install");
        assert_eq!(comps.environments[1].mandatory_groups, vec!["core"]);
        assert!(comps.environments[1].optional_groups.is_empty());

        // Verify groups
        assert_eq!(comps.groups.len(), 3);

        let core = &comps.groups[0];
        assert_eq!(core.id, "core");
        assert_eq!(core.name, "Core");
        assert_eq!(core.mandatory_packages, vec!["bash"]);
        assert_eq!(core.default_packages, vec!["openssh-server"]);
        assert_eq!(core.optional_packages, vec!["vim-enhanced"]);

        let base = &comps.groups[1];
        assert_eq!(base.id, "base");
        assert_eq!(base.mandatory_packages, vec!["coreutils", "glibc"]);
        assert_eq!(base.default_packages, vec!["tar"]);
        assert!(base.optional_packages.is_empty());
    }

    #[test]
    fn test_default_install_packages() {
        let comps = CompsData {
            environments: vec![
                CompsEnvironment {
                    id: "server".into(),
                    name: "Server".into(),
                    mandatory_groups: vec!["core".into(), "base".into()],
                    optional_groups: vec!["debugging".into()],
                },
                CompsEnvironment {
                    id: "minimal".into(),
                    name: "Minimal Install".into(),
                    mandatory_groups: vec!["core".into()],
                    optional_groups: vec![],
                },
            ],
            groups: vec![
                CompsGroup {
                    id: "core".into(),
                    name: "Core".into(),
                    mandatory_packages: vec!["bash".into()],
                    default_packages: vec!["openssh-server".into()],
                    optional_packages: vec!["vim-enhanced".into()],
                },
                CompsGroup {
                    id: "base".into(),
                    name: "Base".into(),
                    mandatory_packages: vec!["coreutils".into(), "glibc".into()],
                    default_packages: vec!["tar".into()],
                    optional_packages: vec![],
                },
                CompsGroup {
                    id: "debugging".into(),
                    name: "Debugging Tools".into(),
                    mandatory_packages: vec!["gdb".into()],
                    default_packages: vec!["strace".into()],
                    optional_packages: vec![],
                },
            ],
        };

        let (env_name, packages) = comps.default_install_packages();

        // Should pick "Server" (2 mandatory groups > 1 for Minimal)
        assert_eq!(env_name, Some("Server".to_string()));

        // Should include mandatory + default from core and base
        assert!(packages.contains("bash"));
        assert!(packages.contains("openssh-server"));
        assert!(packages.contains("coreutils"));
        assert!(packages.contains("glibc"));
        assert!(packages.contains("tar"));

        // Should NOT include optional packages
        assert!(!packages.contains("vim-enhanced"));

        // Should NOT include packages from optional groups (debugging)
        assert!(!packages.contains("gdb"));
        assert!(!packages.contains("strace"));

        assert_eq!(packages.len(), 5);
    }
}
