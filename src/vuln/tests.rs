use super::*;
use crate::container::PackageCoordinate;
use crate::report::{ConfidenceTier, EvidenceSource, Finding, PackageInfo, ReferenceInfo};

#[test]
fn parse_redhat_release_package_handles_name_with_dash() {
    let parsed = parse_redhat_release_package("kernel-rt-4.18.0-193.6.3.rt13.70.el8_2");
    let (name, evr) = parsed.expect("package should parse");
    assert_eq!(name, "kernel-rt");
    assert_eq!(evr, "4.18.0-193.6.3.rt13.70.el8_2");
}

#[test]
fn best_redhat_fixed_release_prefers_matching_el_stream() {
    let pkg = PackageInfo {
        name: "mariadb".into(),
        ecosystem: "redhat".into(),
        version: "3:10.3.25-1.module+el8.10.0+1234".into(),
        license: None,
    };
    let all = vec![
        RedHatFixedRelease {
            advisory: Some("RHSA-2020:4026".into()),
            package_name: "mariadb".into(),
            fixed_evr: "1:5.5.68-1.el7".into(),
        },
        RedHatFixedRelease {
            advisory: Some("RHSA-2020:5654".into()),
            package_name: "mariadb".into(),
            fixed_evr: "3:10.3.27-3.module+el8.2.0+9158".into(),
        },
    ];
    let best = best_redhat_fixed_release(&pkg, &all).expect("best release");
    assert_eq!(best.advisory.as_deref(), Some("RHSA-2020:5654"));
    assert_eq!(best.fixed_evr, "3:10.3.27-3.module+el8.2.0+9158");
}

#[test]
fn best_redhat_fixed_release_rejects_cross_stream_only_match() {
    let pkg = PackageInfo {
        name: "bind-license".into(),
        ecosystem: "redhat".into(),
        version: "32:9.11.4-26.P2.el7".into(),
        license: None,
    };
    let all = vec![RedHatFixedRelease {
        advisory: Some("RHSA-2023:7177".into()),
        package_name: "bind".into(),
        fixed_evr: "32:9.11.36-11.el8_9".into(),
    }];
    assert!(best_redhat_fixed_release(&pkg, &all).is_none());
}

#[test]
fn extract_el_tag_detects_rhel_tag() {
    assert_eq!(
        extract_el_tag("3:10.3.27-3.module+el8.2.0+9158"),
        Some("el8".into())
    );
    assert_eq!(extract_el_tag("1:5.5.68-1.el7"), Some("el7".into()));
    assert_eq!(extract_el_tag("1.2.3"), None);
}

#[test]
fn package_name_matches_rpm_subpackage_to_base_package() {
    assert!(package_name_matches("bind-license", "bind"));
    assert!(package_name_matches("bind-libs.x86_64", "bind"));
    assert!(!package_name_matches("openssl-libs", "bind"));
}

#[test]
fn extract_redhat_errata_from_url_decodes_colon() {
    let url = "https://access.redhat.com/errata/RHSA-2022%3A8162";
    assert_eq!(
        extract_redhat_errata_from_url(url).as_deref(),
        Some("RHSA-2022:8162")
    );
}

#[test]
fn retain_relevant_redhat_references_filters_errata_links() {
    let mut refs = vec![
        ReferenceInfo {
            reference_type: "redhat".into(),
            url: "https://access.redhat.com/errata/RHSA-2022%3A8162".into(),
        },
        ReferenceInfo {
            reference_type: "redhat".into(),
            url: "https://access.redhat.com/security/cve/CVE-2022-0001".into(),
        },
        ReferenceInfo {
            reference_type: "nvd".into(),
            url: "https://nvd.nist.gov/vuln/detail/CVE-2022-0001".into(),
        },
    ];
    retain_relevant_redhat_references(&mut refs, Some("RHSA-2022:8162"));
    assert_eq!(refs.len(), 3);

    retain_relevant_redhat_references(&mut refs, None);
    assert_eq!(refs.len(), 2);
    assert!(refs
        .iter()
        .all(|r| !r.url.contains("/errata/RHSA-2022%3A8162")));
}

fn mk_finding(id: &str, pkg_name: &str, fixed: Option<bool>) -> Finding {
    Finding {
        id: id.to_string(),
        source_ids: Vec::new(),
        package: Some(PackageInfo {
            name: pkg_name.to_string(),
            ecosystem: "redhat".to_string(),
            version: "1:1.2.3-1.el8".to_string(),
        license: None,
        }),
        confidence_tier: ConfidenceTier::ConfirmedInstalled,
        evidence_source: EvidenceSource::InstalledDb,
        accuracy_note: None,
        fixed,
        fixed_in: None,
        recommendation: None,
        severity: Some("HIGH".to_string()),
        cvss: None,
        description: None,
        evidence: Vec::new(),
        references: Vec::new(),
        confidence: Some("HIGH".to_string()),
        epss_score: None,
        epss_percentile: None,
        in_kev: None,
    }
}

#[test]
fn drop_fixed_findings_removes_resolved_rows() {
    let mut findings = vec![
        mk_finding("CVE-2021-0001", "pkg-a", Some(true)),
        mk_finding("CVE-2021-0002", "pkg-b", Some(false)),
        mk_finding("CVE-2021-0003", "pkg-c", None),
    ];
    let dropped = drop_fixed_findings(&mut findings);
    assert_eq!(dropped, 1);
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.fixed != Some(true)));
}

#[test]
fn select_best_candidate_prefers_nearest_fix() {
    let candidates = vec![
        DistroFixCandidate {
            fixed_version: "1.2.0".into(),
            source_id: "src".into(),
            reference_url: "https://example.test/a".into(),
            note: "a".into(),
        },
        DistroFixCandidate {
            fixed_version: "1.1.0".into(),
            source_id: "src".into(),
            reference_url: "https://example.test/b".into(),
            note: "b".into(),
        },
        DistroFixCandidate {
            fixed_version: "2.0.0".into(),
            source_id: "src".into(),
            reference_url: "https://example.test/c".into(),
            note: "c".into(),
        },
    ];
    let best = select_best_candidate("1.0.5", &candidates).expect("best candidate");
    assert_eq!(best.fixed_version, "1.1.0");
}

#[test]
fn build_ubuntu_candidate_index_maps_notice_to_pkg_cve_key() {
    let data = serde_json::json!({
        "notices": [
            {
                "id": "USN-1000-1",
                "cves_ids": ["CVE-2024-12345"],
                "release_packages": {
                    "jammy": [
                        {"name":"bash","version":"5.1-2ubuntu3.4"}
                    ]
                }
            }
        ]
    });
    let mut needed = std::collections::HashSet::new();
    needed.insert(pkg_cve_key("bash", "CVE-2024-12345"));
    let idx = build_ubuntu_candidate_index(&data, &needed);
    let key = pkg_cve_key("bash", "CVE-2024-12345");
    let rows = idx.get(&key).expect("ubuntu candidate present");
    assert_eq!(rows[0].fixed_version, "5.1-2ubuntu3.4");
    assert_eq!(rows[0].source_id, "USN-1000-1");
}

#[test]
fn detect_debian_release_from_package_versions() {
    let pkgs = vec![PackageCoordinate {
        ecosystem: "deb".into(),
        name: "libc6".into(),
        version: "2.36-9+deb12u9".into(),
        source_name: None,
        license: None,
    }];
    assert_eq!(
        debian_legacy::detect_debian_release(&pkgs),
        Some("bookworm")
    );

    let pkgs_11 = vec![PackageCoordinate {
        ecosystem: "deb".into(),
        name: "bash".into(),
        version: "5.1-2+deb11u1".into(),
        source_name: None,
        license: None,
    }];
    assert_eq!(
        debian_legacy::detect_debian_release(&pkgs_11),
        Some("bullseye")
    );
}

#[test]
fn urgency_to_severity_maps_correctly() {
    assert_eq!(debian_legacy::urgency_to_severity("high"), "HIGH");
    assert_eq!(debian_legacy::urgency_to_severity("medium"), "MEDIUM");
    assert_eq!(debian_legacy::urgency_to_severity("low"), "LOW");
    assert_eq!(debian_legacy::urgency_to_severity("low*"), "LOW");
    assert_eq!(debian_legacy::urgency_to_severity("end-of-life"), "MEDIUM");
    assert_eq!(debian_legacy::urgency_to_severity("unknown"), "MEDIUM");
}
