//! Cryptography Bill of Materials (CBOM) collectors.
//!
//! Hooks the container-extract rootfs and package inventory to emit a
//! CycloneDX 1.6-shaped crypto inventory: crypto libraries, certificates,
//! private keys and best-effort protocol hints. The `cbom` section is embedded
//! in the report JSON (worker passes it through untouched); `--cbom-out`
//! additionally writes a standalone CycloneDX 1.6 document.

mod certs;
mod libs;
mod protocols;

use crate::container::PackageCoordinate;
use crate::report::{ConfidenceTier, EvidenceItem, EvidenceSource, Finding};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

/// Report-JSON `spec` marker and the finding id used for private-key material.
pub const CBOM_SPEC: &str = "cyclonedx-1.6-crypto";
pub const PRIVATE_KEY_FINDING_ID: &str = "SCANROOK-CBOM-PRIVATE-KEY";

/// Maximum number of cert/key candidate files inspected before truncating.
const DEFAULT_CANDIDATE_CAP: usize = 10_000;
/// Maximum ELF files parsed for dynamic-library sonames.
const MAX_ELF_SCAN: usize = 4_000;
/// Per-file read cap for candidate cert/key/config files.
const MAX_FILE_READ: usize = 1_048_576;

// ─── Report-JSON contract (Track-U boundary) ──────────────────────────
// Field names below are the binding JSON keys the UI track builds against.

#[derive(Debug, Serialize, Clone)]
pub struct CbomSection {
    pub spec: &'static str,
    pub crypto_libraries: Vec<CryptoLibrary>,
    pub certificates: Vec<CertificateAsset>,
    pub private_keys: Vec<PrivateKeyAsset>,
    pub protocol_hints: Vec<ProtocolHint>,
    pub summary: CbomSummary,
    pub truncated: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CryptoLibrary {
    pub name: String,
    pub version: Option<String>,
    /// "package" | "elf-dynlib"
    pub source: String,
    pub paths: Vec<String>,
    pub cve_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateAsset {
    pub path: String,
    pub subject: String,
    pub issuer: String,
    /// RFC3339 notAfter timestamp.
    pub not_after: String,
    pub sig_algorithm: String,
    pub key_algorithm: String,
    pub key_bits: Option<u32>,
    /// "expired" | "expires-soon" | "sha1-signature" | "weak-rsa" | "weak-ec"
    pub flags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrivateKeyAsset {
    pub path: String,
    /// "rsa" | "ec" | "openssh" | "pkcs8" | "encrypted-pkcs12"
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolHint {
    pub path: String,
    pub protocol: String,
    pub setting: String,
    /// Always "heuristic".
    pub confidence: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CbomSummary {
    pub crypto_libs: usize,
    pub certificates: usize,
    pub expired_certs: usize,
    pub weak_certs: usize,
    pub private_keys: usize,
}

// ─── Collection ───────────────────────────────────────────────────────

/// Collect the CBOM section from an extracted rootfs, the detected package
/// inventory, ELF dynamic-library sonames, and the scan's existing findings.
pub fn collect_cbom(
    root: &Path,
    packages: &[PackageCoordinate],
    elf_dynlibs: &[String],
    findings: &[Finding],
) -> CbomSection {
    collect_cbom_inner(
        root,
        packages,
        elf_dynlibs,
        findings,
        DEFAULT_CANDIDATE_CAP,
        chrono::Utc::now().timestamp(),
    )
}

fn is_cert_key_ext(ext: Option<&str>) -> bool {
    matches!(
        ext,
        Some("pem")
            | Some("crt")
            | Some("cer")
            | Some("der")
            | Some("key")
            | Some("p12")
            | Some("pfx")
    )
}

fn in_crypto_config_dir(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    [
        "/etc/",
        "/ssl",
        "/tls",
        "/pki",
        "/certs",
        "/ssh",
        "openssl.cnf",
        "sshd_config",
        "nginx",
    ]
    .iter()
    .any(|m| s.contains(m))
}

fn is_protocol_config(base: &str, ext: Option<&str>, path: &Path) -> bool {
    matches!(base, "nginx.conf" | "openssl.cnf" | "sshd_config")
        || (ext == Some("conf")
            && path
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("nginx"))
}

fn rel_path(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(p) => format!("/{}", p.display()),
        Err(_) => path.display().to_string(),
    }
}

fn read_bounded(path: &Path, max: usize) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(max as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn collect_cbom_inner(
    root: &Path,
    packages: &[PackageCoordinate],
    elf_dynlibs: &[String],
    findings: &[Finding],
    cap: usize,
    now_ts: i64,
) -> CbomSection {
    let mut certificates: Vec<CertificateAsset> = Vec::new();
    let mut private_keys: Vec<PrivateKeyAsset> = Vec::new();
    let mut protocol_hints: Vec<ProtocolHint> = Vec::new();
    let mut candidates = 0usize;
    let mut truncated = false;

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase());
        let base = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let cert_ext = is_cert_key_ext(ext.as_deref());
        let proto = is_protocol_config(&base, ext.as_deref(), path);
        let config_dir = in_crypto_config_dir(path);
        if !cert_ext && !proto && !config_dir {
            continue;
        }

        candidates += 1;
        if candidates > cap {
            truncated = true;
            break;
        }

        let bytes = match read_bounded(path, MAX_FILE_READ) {
            Some(b) => b,
            None => continue,
        };
        let rel = rel_path(root, path);
        certs::scan_bytes(
            &rel,
            ext.as_deref(),
            &bytes,
            now_ts,
            &mut certificates,
            &mut private_keys,
        );
        if proto {
            protocols::parse_config(&base, &rel, &bytes, &mut protocol_hints);
        }
    }

    let crypto_libraries = libs::classify_crypto_libraries(packages, elf_dynlibs, findings);

    // Deterministic ordering + de-dup of exact key repeats.
    certificates.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.subject.cmp(&b.subject)));
    private_keys.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.kind.cmp(&b.kind)));
    private_keys.dedup_by(|a, b| a.path == b.path && a.kind == b.kind);
    protocol_hints.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.setting.cmp(&b.setting)));
    protocol_hints.dedup_by(|a, b| a.path == b.path && a.setting == b.setting);

    let expired_certs = certificates
        .iter()
        .filter(|c| c.flags.iter().any(|f| f == "expired"))
        .count();
    let weak_certs = certificates
        .iter()
        .filter(|c| {
            c.flags
                .iter()
                .any(|f| f == "weak-rsa" || f == "weak-ec" || f == "sha1-signature")
        })
        .count();

    let summary = CbomSummary {
        crypto_libs: crypto_libraries.len(),
        certificates: certificates.len(),
        expired_certs,
        weak_certs,
        private_keys: private_keys.len(),
    };

    CbomSection {
        spec: CBOM_SPEC,
        crypto_libraries,
        certificates,
        private_keys,
        protocol_hints,
        summary,
        truncated,
    }
}

/// Walk the rootfs and collect ELF dynamic-library sonames (DT_NEEDED entries).
pub fn gather_elf_dynlibs(root: &Path) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut scanned = 0usize;

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        // Cheap ELF-magic gate before reading the whole file.
        let mut magic = [0u8; 4];
        match std::fs::File::open(path).and_then(|mut f| f.read(&mut magic)) {
            Ok(4) => {}
            _ => continue,
        }
        if magic != [0x7f, b'E', b'L', b'F'] {
            continue;
        }
        scanned += 1;
        if scanned > MAX_ELF_SCAN {
            break;
        }
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 300 * 1024 * 1024 {
                continue;
            }
        }
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&bytes) {
                for lib in elf.libraries.iter() {
                    out.insert(lib.to_string());
                }
            }
        }
    }

    out.into_iter().collect()
}

/// Build HIGH-severity findings for private-key material discovered in the image.
pub fn cbom_findings(section: &CbomSection) -> Vec<Finding> {
    section
        .private_keys
        .iter()
        .map(|k| Finding {
            id: PRIVATE_KEY_FINDING_ID.to_string(),
            source_ids: Vec::new(),
            package: None,
            confidence_tier: ConfidenceTier::ConfirmedInstalled,
            evidence_source: EvidenceSource::FilenameHeuristic,
            accuracy_note: None,
            fixed: None,
            fixed_in: None,
            recommendation: Some(
                "Remove private key material from the image; inject secrets at runtime or use a secrets manager."
                    .to_string(),
            ),
            severity: Some("HIGH".to_string()),
            cvss: None,
            description: Some(format!(
                "Private key material ({}) found in image at {}",
                k.kind, k.path
            )),
            evidence: vec![EvidenceItem {
                evidence_type: "file".to_string(),
                path: Some(k.path.clone()),
                detail: Some(k.kind.clone()),
            }],
            references: Vec::new(),
            confidence: Some("HIGH".to_string()),
            epss_score: None,
            epss_percentile: None,
            in_kev: None,
        })
        .collect()
}

/// Render a standalone CycloneDX 1.6 document from a CBOM section (for `--cbom-out`).
pub fn to_cyclonedx(section: &CbomSection) -> serde_json::Value {
    use serde_json::json;
    let mut components: Vec<serde_json::Value> = Vec::new();

    // Crypto libraries -> plain library components (no cryptoProperties).
    for lib in &section.crypto_libraries {
        components.push(json!({
            "type": "library",
            "name": lib.name,
            "version": lib.version,
        }));
    }
    // Certificates -> cryptographic-asset / certificate.
    for cert in &section.certificates {
        components.push(json!({
            "type": "cryptographic-asset",
            "name": cert.subject,
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": cert.subject,
                    "issuerName": cert.issuer,
                    "notValidAfter": cert.not_after,
                    "signatureAlgorithm": cert.sig_algorithm,
                }
            }
        }));
    }
    // Private keys -> cryptographic-asset / related-crypto-material.
    for key in &section.private_keys {
        components.push(json!({
            "type": "cryptographic-asset",
            "name": key.path,
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "type": "private-key",
                }
            }
        }));
    }
    // Protocol hints -> cryptographic-asset / protocol.
    for hint in &section.protocol_hints {
        components.push(json!({
            "type": "cryptographic-asset",
            "name": format!("{} {}", hint.protocol, hint.setting),
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": { "type": hint.protocol.to_lowercase() }
            }
        }));
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "ScanRook",
                "name": "scanrook",
                "version": env!("CARGO_PKG_VERSION"),
            }],
        },
        "components": components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cbom")
    }

    fn copy_fixture(root: &Path, rel: &str, fixture: &str) {
        let dst = root.join(rel);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::copy(fixtures_dir().join(fixture), dst).unwrap();
    }

    #[test]
    fn walk_collects_certs_keys_and_protocols() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        copy_fixture(root, "etc/ssl/certs/valid.pem", "rsa2048_valid.pem");
        copy_fixture(root, "etc/ssl/certs/expired.pem", "expired.pem");
        copy_fixture(root, "etc/ssl/private/server.key", "rsa_private.pem");
        copy_fixture(root, "etc/pki/bundle.p12", "dummy.p12");
        copy_fixture(root, "etc/nginx/nginx.conf", "nginx.conf");

        let section = collect_cbom_inner(root, &[], &[], &[], DEFAULT_CANDIDATE_CAP, 1_783_555_200);

        assert_eq!(section.spec, "cyclonedx-1.6-crypto");
        assert_eq!(section.certificates.len(), 2, "two certs expected");
        assert_eq!(section.summary.expired_certs, 1);
        // rsa_private.pem (rsa) + dummy.p12 (encrypted-pkcs12)
        assert_eq!(section.private_keys.len(), 2);
        assert!(section
            .private_keys
            .iter()
            .any(|k| k.kind == "encrypted-pkcs12"));
        assert!(section
            .protocol_hints
            .iter()
            .any(|h| h.setting == "TLSv1.3" && h.confidence == "heuristic"));
        assert!(!section.truncated);
    }

    #[test]
    fn candidate_cap_sets_truncated() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for i in 0..4 {
            copy_fixture(
                root,
                &format!("etc/ssl/certs/c{}.pem", i),
                "rsa2048_valid.pem",
            );
        }
        let section = collect_cbom_inner(root, &[], &[], &[], 2, 1_783_555_200);
        assert!(
            section.truncated,
            "cap of 2 over 4 candidates must truncate"
        );
        assert!(section.certificates.len() <= 2);
    }

    #[test]
    fn private_key_findings_are_high_severity() {
        let section = CbomSection {
            spec: CBOM_SPEC,
            crypto_libraries: vec![],
            certificates: vec![],
            private_keys: vec![
                PrivateKeyAsset {
                    path: "/etc/ssl/private/a.key".to_string(),
                    kind: "rsa".to_string(),
                },
                PrivateKeyAsset {
                    path: "/etc/ssl/private/b.key".to_string(),
                    kind: "openssh".to_string(),
                },
            ],
            protocol_hints: vec![],
            summary: CbomSummary::default(),
            truncated: false,
        };
        let findings = cbom_findings(&section);
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|f| f.severity.as_deref() == Some("HIGH") && f.id == PRIVATE_KEY_FINDING_ID));
        assert!(findings[0]
            .description
            .as_ref()
            .unwrap()
            .contains("/etc/ssl/private"));
    }

    #[test]
    fn cyclonedx_export_shape() {
        let section = CbomSection {
            spec: CBOM_SPEC,
            crypto_libraries: vec![CryptoLibrary {
                name: "openssl".to_string(),
                version: Some("3.0.11".to_string()),
                source: "package".to_string(),
                paths: vec![],
                cve_ids: vec![],
            }],
            certificates: vec![CertificateAsset {
                path: "/etc/ssl/certs/valid.pem".to_string(),
                subject: "CN=valid.example.com".to_string(),
                issuer: "CN=valid.example.com".to_string(),
                not_after: "2035-01-01T00:00:00Z".to_string(),
                sig_algorithm: "sha256WithRSAEncryption".to_string(),
                key_algorithm: "RSA".to_string(),
                key_bits: Some(2048),
                flags: vec![],
            }],
            private_keys: vec![PrivateKeyAsset {
                path: "/etc/ssl/private/a.key".to_string(),
                kind: "rsa".to_string(),
            }],
            protocol_hints: vec![],
            summary: CbomSummary::default(),
            truncated: false,
        };
        let doc = to_cyclonedx(&section);
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.6");
        let comps = doc["components"].as_array().unwrap();
        assert_eq!(comps.len(), 3);
        // library has no cryptoProperties
        let lib = comps.iter().find(|c| c["type"] == "library").unwrap();
        assert!(lib.get("cryptoProperties").is_none());
        // certificate asset
        let cert = comps
            .iter()
            .find(|c| c["cryptoProperties"]["assetType"] == "certificate")
            .unwrap();
        assert_eq!(cert["type"], "cryptographic-asset");
        // key asset
        assert!(comps
            .iter()
            .any(|c| c["cryptoProperties"]["assetType"] == "related-crypto-material"));
    }
}
