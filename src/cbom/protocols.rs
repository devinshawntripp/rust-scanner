//! Best-effort TLS/SSH protocol hints from well-known config files.
//!
//! All hints are marked `confidence: "heuristic"` — this is trivial line parsing,
//! not a full config-grammar evaluation.

use super::ProtocolHint;

fn hint(path: &str, protocol: &str, setting: String) -> ProtocolHint {
    ProtocolHint {
        path: path.to_string(),
        protocol: protocol.to_string(),
        setting,
        confidence: "heuristic".to_string(),
    }
}

/// Parse a known crypto config file for TLS/SSH protocol settings.
pub(super) fn parse_config(
    basename: &str,
    rel_path: &str,
    bytes: &[u8],
    out: &mut Vec<ProtocolHint>,
) {
    let text = String::from_utf8_lossy(bytes);
    let base = basename.to_ascii_lowercase();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
        if let Some(rest) = line.strip_prefix("ssl_protocols") {
            for tok in rest.trim_end_matches(';').split_whitespace() {
                let t = tok.trim_end_matches(';');
                if t.starts_with("TLS") || t.starts_with("SSL") {
                    out.push(hint(rel_path, "TLS", t.to_string()));
                }
            }
            continue;
        }

        // openssl.cnf: `MinProtocol = TLSv1.2` / `MaxProtocol = ...`
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("minprotocol") || lower.starts_with("maxprotocol") {
            if let Some((k, v)) = line.split_once('=') {
                out.push(hint(rel_path, "TLS", format!("{}={}", k.trim(), v.trim())));
            }
            continue;
        }

        // sshd_config: Protocol / Ciphers / KexAlgorithms / MACs / HostKeyAlgorithms
        if base == "sshd_config" {
            let mut it = line.split_whitespace();
            if let Some(key) = it.next() {
                let rest: Vec<&str> = it.collect();
                if matches!(
                    key,
                    "Protocol" | "Ciphers" | "KexAlgorithms" | "MACs" | "HostKeyAlgorithms"
                ) && !rest.is_empty()
                {
                    out.push(hint(rel_path, "SSH", format!("{} {}", key, rest.join(" "))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nginx_ssl_protocols_parsed() {
        let conf = b"server {\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n";
        let mut out = Vec::new();
        parse_config("nginx.conf", "/etc/nginx/nginx.conf", conf, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .all(|h| h.protocol == "TLS" && h.confidence == "heuristic"));
        assert!(out.iter().any(|h| h.setting == "TLSv1.2"));
        assert!(out.iter().any(|h| h.setting == "TLSv1.3"));
    }

    #[test]
    fn openssl_min_protocol_parsed() {
        let conf = b"[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT\n";
        let mut out = Vec::new();
        parse_config("openssl.cnf", "/etc/ssl/openssl.cnf", conf, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].setting, "MinProtocol=TLSv1.2");
    }

    #[test]
    fn sshd_config_ciphers_parsed() {
        let conf = b"# comment\nCiphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n";
        let mut out = Vec::new();
        parse_config("sshd_config", "/etc/ssh/sshd_config", conf, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].protocol, "SSH");
        assert!(out[0].setting.starts_with("Ciphers "));
    }
}
