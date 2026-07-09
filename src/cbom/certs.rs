//! Certificate and private-key collectors for the CBOM module.
//!
//! Pure-Rust X.509 parsing via `x509-parser`; PEM block splitting via `pem`.

use super::{CertificateAsset, PrivateKeyAsset};
use x509_parser::prelude::{FromDer, X509Certificate};

/// SHA-1 signature algorithm OIDs (dotted-decimal). Presence sets the
/// `sha1-signature` flag. Primary case: sha1WithRSAEncryption (1.2.840.113549.1.1.5).
const SHA1_SIG_OIDS: &[&str] = &[
    "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
    "1.2.840.10045.4.3.1",  // ecdsa-with-SHA1
    "1.2.840.10040.4.3",    // dsa-with-sha1
    "1.3.14.3.2.29",        // sha1WithRSA (legacy OIW)
];

/// Map a signature-algorithm OID to a human-readable name, falling back to the OID.
pub(super) fn sig_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.3" => "dsa-with-sha1",
        "1.3.14.3.2.29" => "sha1WithRSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        other => other,
    }
    .to_string()
}

/// Map a public-key-algorithm OID to a short name (RSA/EC/...), falling back to the OID.
pub(super) fn key_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10040.4.1" => "DSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        other => other,
    }
    .to_string()
}

/// Compute the certificate weakness/expiry flags. `now_ts` is injected (Unix
/// seconds) so the logic is deterministic under test.
pub(super) fn cert_flags(
    not_after_ts: Option<i64>,
    key_algorithm: &str,
    key_bits: Option<u32>,
    sig_is_sha1: bool,
    now_ts: i64,
) -> Vec<String> {
    let mut flags = Vec::new();
    if let Some(exp) = not_after_ts {
        if exp < now_ts {
            flags.push("expired".to_string());
        } else if exp - now_ts < 90 * 24 * 3600 {
            flags.push("expires-soon".to_string());
        }
    }
    if sig_is_sha1 {
        flags.push("sha1-signature".to_string());
    }
    if let Some(bits) = key_bits {
        match key_algorithm {
            "RSA" | "RSASSA-PSS" | "DSA" => {
                if bits < 2048 {
                    flags.push("weak-rsa".to_string());
                }
            }
            "EC" => {
                if bits < 256 {
                    flags.push("weak-ec".to_string());
                }
            }
            _ => {}
        }
    }
    flags
}

/// Parse a single DER-encoded X.509 certificate into a `CertificateAsset`.
pub(super) fn parse_certificate_der(
    path: &str,
    der: &[u8],
    now_ts: i64,
) -> Option<CertificateAsset> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let sig_is_sha1 = SHA1_SIG_OIDS.contains(&sig_oid.as_str());
    let sig_algorithm = sig_algorithm_name(&sig_oid);

    let spki = cert.public_key();
    let key_oid = spki.algorithm.algorithm.to_id_string();
    let key_algorithm = key_algorithm_name(&key_oid);
    let key_bits = match spki.parsed() {
        Ok(pk) => {
            let bits = pk.key_size();
            if bits > 0 {
                Some(bits as u32)
            } else {
                None
            }
        }
        Err(_) => None,
    };

    let not_after_ts = Some(cert.validity().not_after.to_datetime().unix_timestamp());
    let not_after = not_after_ts
        .and_then(|ts| chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0))
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default();

    let flags = cert_flags(not_after_ts, &key_algorithm, key_bits, sig_is_sha1, now_ts);

    Some(CertificateAsset {
        path: path.to_string(),
        subject,
        issuer,
        not_after,
        sig_algorithm,
        key_algorithm,
        key_bits,
        flags,
    })
}

/// Classify a PEM private-key block by its tag.
pub(super) fn private_key_kind(tag: &str) -> Option<&'static str> {
    let t = tag.to_ascii_uppercase();
    if t.contains("OPENSSH PRIVATE KEY") {
        Some("openssh")
    } else if t.contains("RSA PRIVATE KEY") {
        Some("rsa")
    } else if t.contains("EC PRIVATE KEY") {
        Some("ec")
    } else if t.contains("PRIVATE KEY") {
        // PKCS#8 (BEGIN PRIVATE KEY / ENCRYPTED PRIVATE KEY), DSA, DH, ...
        Some("pkcs8")
    } else {
        None
    }
}

/// Scan the raw bytes of a candidate file, appending any discovered certificates
/// and private keys. Handles PEM (possibly multi-block), raw DER, and PKCS#12.
pub(super) fn scan_bytes(
    rel_path: &str,
    ext: Option<&str>,
    bytes: &[u8],
    now_ts: i64,
    certs_out: &mut Vec<CertificateAsset>,
    keys_out: &mut Vec<PrivateKeyAsset>,
) {
    // PKCS#12 / PFX: encrypted container — do not attempt to crack it.
    if matches!(ext, Some("p12") | Some("pfx")) {
        keys_out.push(PrivateKeyAsset {
            path: rel_path.to_string(),
            kind: "encrypted-pkcs12".to_string(),
        });
        return;
    }

    // PEM: a single file may hold multiple blocks (cert chains, key+cert bundles).
    let mut matched_pem = false;
    if let Ok(blocks) = pem::parse_many(bytes) {
        for block in &blocks {
            let tag = block.tag();
            if tag.contains("CERTIFICATE") && !tag.contains("REQUEST") {
                matched_pem = true;
                if let Some(cert) = parse_certificate_der(rel_path, block.contents(), now_ts) {
                    certs_out.push(cert);
                }
            } else if let Some(kind) = private_key_kind(tag) {
                matched_pem = true;
                keys_out.push(PrivateKeyAsset {
                    path: rel_path.to_string(),
                    kind: kind.to_string(),
                });
            }
        }
    }

    // Raw DER fallback for .der/.cer files that are not PEM-armored.
    if !matched_pem && matches!(ext, Some("der") | Some("cer")) {
        if let Some(cert) = parse_certificate_der(rel_path, bytes, now_ts) {
            certs_out.push(cert);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed "now" pinned to 2026-07-09 so fixture-based tests stay deterministic
    // regardless of the real clock. Fixtures with long validity remain non-expired.
    const NOW: i64 = 1_783_555_200;

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let p = format!(
            "{}/tests/fixtures/cbom/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {}", p, e))
    }

    fn parse_cert(name: &str) -> CertificateAsset {
        let bytes = fixture_bytes(name);
        let ext = std::path::Path::new(name)
            .extension()
            .and_then(|e| e.to_str());
        let mut certs = Vec::new();
        let mut keys = Vec::new();
        scan_bytes(name, ext, &bytes, NOW, &mut certs, &mut keys);
        certs.into_iter().next().expect("expected one certificate")
    }

    fn key_kind(name: &str) -> String {
        let bytes = fixture_bytes(name);
        let ext = std::path::Path::new(name)
            .extension()
            .and_then(|e| e.to_str());
        let mut certs = Vec::new();
        let mut keys = Vec::new();
        scan_bytes(name, ext, &bytes, NOW, &mut certs, &mut keys);
        keys.into_iter()
            .next()
            .expect("expected one private key")
            .kind
    }

    #[test]
    fn valid_rsa2048_cert_has_no_weakness_flags() {
        let c = parse_cert("rsa2048_valid.pem");
        assert!(
            c.subject.contains("valid.example.com"),
            "subject={}",
            c.subject
        );
        assert!(c.issuer.contains("ScanRook Test"), "issuer={}", c.issuer);
        assert_eq!(c.key_algorithm, "RSA");
        assert_eq!(c.key_bits, Some(2048));
        assert_eq!(c.sig_algorithm, "sha256WithRSAEncryption");
        assert!(c.not_after.contains("20"), "not_after={}", c.not_after);
        assert!(c.flags.is_empty(), "expected no flags, got {:?}", c.flags);
    }

    #[test]
    fn expired_cert_flagged_expired() {
        let c = parse_cert("expired.pem");
        assert!(
            c.flags.contains(&"expired".to_string()),
            "flags={:?}",
            c.flags
        );
    }

    #[test]
    fn sha1_cert_flagged_and_named() {
        let c = parse_cert("sha1.pem");
        assert_eq!(c.sig_algorithm, "sha1WithRSAEncryption");
        assert!(
            c.flags.contains(&"sha1-signature".to_string()),
            "flags={:?}",
            c.flags
        );
    }

    #[test]
    fn rsa1024_flagged_weak_rsa() {
        let c = parse_cert("rsa1024.pem");
        assert_eq!(c.key_bits, Some(1024));
        assert!(
            c.flags.contains(&"weak-rsa".to_string()),
            "flags={:?}",
            c.flags
        );
    }

    #[test]
    fn ec_p256_is_strong() {
        let c = parse_cert("ec_p256.pem");
        assert_eq!(c.key_algorithm, "EC");
        assert_eq!(c.key_bits, Some(256));
        assert!(
            !c.flags.iter().any(|f| f.starts_with("weak")),
            "flags={:?}",
            c.flags
        );
    }

    #[test]
    fn ec_192_flagged_weak_ec() {
        let c = parse_cert("ec_weak.pem");
        assert_eq!(c.key_bits, Some(192));
        assert!(
            c.flags.contains(&"weak-ec".to_string()),
            "flags={:?}",
            c.flags
        );
    }

    #[test]
    fn private_key_kinds_detected() {
        assert_eq!(key_kind("rsa_private.pem"), "rsa");
        assert_eq!(key_kind("ec_private.pem"), "ec");
        assert_eq!(key_kind("pkcs8_private.pem"), "pkcs8");
        assert_eq!(key_kind("openssh_ed25519"), "openssh");
        assert_eq!(key_kind("dummy.p12"), "encrypted-pkcs12");
    }

    #[test]
    fn cert_flags_expires_soon_within_90_days() {
        let now = 1_783_555_200;
        let soon = now + 30 * 24 * 3600;
        let flags = cert_flags(Some(soon), "RSA", Some(2048), false, now);
        assert!(flags.contains(&"expires-soon".to_string()), "{:?}", flags);
        assert!(!flags.contains(&"expired".to_string()));
    }

    #[test]
    fn cert_flags_far_future_is_clean() {
        let now = 1_783_555_200;
        let far = now + 400 * 24 * 3600;
        let flags = cert_flags(Some(far), "RSA", Some(2048), false, now);
        assert!(flags.is_empty(), "{:?}", flags);
    }
}
