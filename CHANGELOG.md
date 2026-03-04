# Changelog

All notable changes to ScanRook are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.10.2] - 2026-03-04

### Added
- SQLite vulndb query integration for OSV batch queries (local cache lookup before remote API)
- SQLite vulndb query integration for EPSS enrichment (risk scoring from local cache)
- SQLite vulndb query integration for KEV enrichment (CISA Known Exploited Vulnerabilities from local cache)
- Magic-byte detection for gzip vs raw SQLite in vulndb fetch
- Dict-aware decompression for zstd-compressed vulndb payloads

### Changed
- OSV batch queries now check local SQLite vulndb cache first, falling back to remote OSV API

## [1.10.0] - 2026-03-04

### Added
- DMG scanning: detect .app bundles via Info.plist parsing (CFBundleIdentifier + CFBundleShortVersionString)
- DMG scanning: detect embedded frameworks within .app bundles
- DMG scanning: Rust-native extraction attempt via dmgwiz before falling back to external tools
- RHEL/Rocky: post-enrichment deduplication by (CVE, package) to eliminate duplicate findings
- RHEL/Rocky: RHEL-version CPE gating to prevent RHEL 7/8 false positives in RHEL 9 scans
- Unit tests: version comparison (cmp_versions, is_version_in_range) edge cases
- Unit tests: CPE matching (cpe_parts) parsing and validation
- Unit tests: RPM EVR comparison (compare_evr) with epoch, tilde, release tests
- Unit tests: package parsing (dpkg source name, APK origin field, RPM empty DB)

### Changed
- DMG extraction failure now emits a warning and falls through to binary-only scanning instead of returning no report
- RHEL enrichment pipeline now deduplicates findings after all three enrichment stages (OSV, unfixed CVE injection, OVAL)

### Fixed
- Duplicate CVE findings in Rocky Linux scans from overlapping OSV and OVAL enrichment paths
- False positive RHEL 7/8 CVEs appearing in RHEL 9 scan results due to cross-version CPE matching

## [1.9.2] - 2026-01-01

(Previous release)
