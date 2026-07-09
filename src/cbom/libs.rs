//! Crypto-library classifier for the CBOM module.
//!
//! Matches the existing package inventory and ELF dynamic-library sonames against
//! a curated token list, links CVE ids from the scan's existing findings, and
//! merges package + dynlib hits for the same library (package wins).

use super::CryptoLibrary;
use crate::container::PackageCoordinate;
use crate::report::Finding;
use std::collections::BTreeMap;

/// (substring token, canonical library name). Case-insensitive `contains` match,
/// per the CBOM design.
const CRYPTO_TOKENS: &[(&str, &str)] = &[
    ("openssl", "openssl"),
    ("libssl", "openssl"),
    ("libcrypto", "openssl"),
    ("boringssl", "boringssl"),
    ("gnutls", "gnutls"),
    ("libsodium", "libsodium"),
    ("mbedtls", "mbedtls"),
    ("wolfssl", "wolfssl"),
    ("libgcrypt", "libgcrypt"),
    ("nss", "nss"),
    ("bouncycastle", "bouncycastle"),
    ("cryptography", "cryptography"),
    ("golang.org/x/crypto", "golang.org/x/crypto"),
    ("ring", "ring"),
    ("rustls", "rustls"),
    ("pycryptodome", "pycryptodome"),
    ("openssh", "openssh"),
];

/// Return the canonical crypto-library name for a package/soname, if it matches.
fn canonical_for(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    for (token, canon) in CRYPTO_TOKENS {
        if n.contains(token) {
            return Some(canon);
        }
    }
    None
}

/// Extract a version from a shared-object soname, e.g. `libssl.so.3` -> `3`.
fn soname_version(soname: &str) -> Option<String> {
    if let Some(idx) = soname.find(".so.") {
        let v = &soname[idx + 4..];
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

struct Acc {
    name: String,
    version: Option<String>,
    source: String,
    paths: Vec<String>,
    cve_ids: Vec<String>,
}

pub(super) fn classify_crypto_libraries(
    packages: &[PackageCoordinate],
    dynlibs: &[String],
    findings: &[Finding],
) -> Vec<CryptoLibrary> {
    // BTreeMap keyed by canonical name -> deterministic ordering, natural dedup.
    let mut map: BTreeMap<&'static str, Acc> = BTreeMap::new();

    // Packages first so that package hits take precedence (source = "package").
    for pkg in packages {
        if let Some(canon) = canonical_for(&pkg.name) {
            let entry = map.entry(canon).or_insert_with(|| Acc {
                name: pkg.name.clone(),
                version: None,
                source: "package".to_string(),
                paths: Vec::new(),
                cve_ids: Vec::new(),
            });
            entry.source = "package".to_string();
            entry.name = pkg.name.clone();
            if entry.version.is_none() && !pkg.version.is_empty() {
                entry.version = Some(pkg.version.clone());
            }
        }
    }

    // ELF dynamic libraries. Merge into an existing package entry when present.
    for soname in dynlibs {
        if let Some(canon) = canonical_for(soname) {
            let entry = map.entry(canon).or_insert_with(|| Acc {
                name: canon.to_string(),
                version: soname_version(soname),
                source: "elf-dynlib".to_string(),
                paths: Vec::new(),
                cve_ids: Vec::new(),
            });
            if !entry.paths.contains(soname) {
                entry.paths.push(soname.clone());
            }
            if entry.version.is_none() {
                entry.version = soname_version(soname);
            }
        }
    }

    // Link finding ids whose package name maps to the same canonical library.
    for f in findings {
        let pkg_name = match f.package.as_ref() {
            Some(p) => &p.name,
            None => continue,
        };
        if let Some(canon) = canonical_for(pkg_name) {
            if let Some(entry) = map.get_mut(canon) {
                if !entry.cve_ids.contains(&f.id) {
                    entry.cve_ids.push(f.id.clone());
                }
            }
        }
    }

    map.into_values()
        .map(|mut a| {
            a.cve_ids.sort();
            a.cve_ids.dedup();
            a.paths.sort();
            CryptoLibrary {
                name: a.name,
                version: a.version,
                source: a.source,
                paths: a.paths,
                cve_ids: a.cve_ids,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ConfidenceTier, EvidenceSource, Finding, PackageInfo};

    fn pkg(name: &str, version: &str) -> PackageCoordinate {
        PackageCoordinate {
            ecosystem: "deb".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source_name: None,
            license: None,
        }
    }

    fn finding(id: &str, pkg_name: &str) -> Finding {
        Finding {
            id: id.to_string(),
            source_ids: Vec::new(),
            package: Some(PackageInfo {
                name: pkg_name.to_string(),
                ecosystem: "deb".to_string(),
                version: "0".to_string(),
                license: None,
            }),
            confidence_tier: ConfidenceTier::ConfirmedInstalled,
            evidence_source: EvidenceSource::InstalledDb,
            accuracy_note: None,
            fixed: None,
            fixed_in: None,
            recommendation: None,
            severity: Some("HIGH".to_string()),
            cvss: None,
            description: None,
            evidence: Vec::new(),
            references: Vec::new(),
            confidence: None,
            epss_score: None,
            epss_percentile: None,
            in_kev: None,
        }
    }

    #[test]
    fn classifies_packages_and_merges_dynlibs() {
        let packages = vec![
            pkg("openssl", "3.0.11-1"),
            pkg("libgcrypt20", "1.10.1-3"),
            pkg("coreutils", "9.1-1"),
        ];
        let dynlibs = vec![
            "libssl.so.3".to_string(),
            "libcrypto.so.3".to_string(),
            "libc.so.6".to_string(),
        ];
        let findings = vec![
            finding("CVE-2023-0464", "openssl"),
            finding("CVE-2022-0000", "coreutils"),
        ];

        let libs = classify_crypto_libraries(&packages, &dynlibs, &findings);

        // openssl + libgcrypt classified; coreutils excluded.
        assert!(libs.iter().any(|l| l.name == "libgcrypt20"));
        assert!(!libs.iter().any(|l| l.name == "coreutils"));

        // openssl merged (package + two dynlibs) into a single entry, source = package.
        assert_eq!(
            libs.iter().filter(|l| l.name == "openssl").count(),
            1,
            "openssl must not be duplicated across package/dynlib sources"
        );
        let ossl = libs.iter().find(|l| l.name == "openssl").unwrap();
        assert_eq!(ossl.source, "package");
        assert_eq!(ossl.version.as_deref(), Some("3.0.11-1"));
        assert!(ossl.cve_ids.contains(&"CVE-2023-0464".to_string()));
        // The coreutils CVE must not attach to openssl.
        assert!(!ossl.cve_ids.contains(&"CVE-2022-0000".to_string()));
    }

    #[test]
    fn dynlib_only_library_records_soname_and_version() {
        let libs = classify_crypto_libraries(&[], &["libgnutls.so.30".to_string()], &[]);
        assert_eq!(libs.len(), 1);
        assert_eq!(libs[0].name, "gnutls");
        assert_eq!(libs[0].source, "elf-dynlib");
        assert_eq!(libs[0].version.as_deref(), Some("30"));
        assert_eq!(libs[0].paths, vec!["libgnutls.so.30".to_string()]);
    }
}
