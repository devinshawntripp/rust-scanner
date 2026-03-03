# Requirements: ScanRook

**Defined:** 2026-03-02
**Core Value:** Every scan returns accurate, complete vulnerability results — no false positives, no missed CVEs — by checking local data first and only hitting live APIs as a fallback.

## v1 Requirements

Requirements for this milestone. Each maps to roadmap phases.

### Scanning Reliability

- [ ] **SCAN-01**: Scanner handles all supported image types (ISO, DMG, tar.gz, tar, OCI, docker-save) without crashing or hanging
- [ ] **SCAN-02**: All HTTP API requests have timeouts and circuit breakers — no infinite hangs on API failures or rate limits

### Enrichment Pipeline

- [ ] **ENRICH-01**: Scanner checks PostgreSQL cache before making any live OSV API call
- [ ] **ENRICH-02**: Scanner checks PostgreSQL cache before making any live NVD API call
- [ ] **ENRICH-03**: Scanner stores all API responses back to PostgreSQL after fetching
- [ ] **ENRICH-04**: Scanner uses file cache -> PG -> live API fallback chain (check file first, then PG, then live)
- [ ] **ENRICH-05**: Scanner with existing PG enrichment data does not make redundant live API calls for cached CVEs
- [ ] **ENRICH-06**: PG cache entries have a revalidation timestamp — scanner re-fetches when data is stale, not every time

### RHEL/Rocky Scanning

- [ ] **RHEL-01**: Three RHEL enrichment codepaths (OSV, OVAL, per-package API) consolidated into single unified pipeline
- [ ] **RHEL-02**: RHEL scanning uses strict RHEL-version CPE matching to eliminate false positives
- [ ] **RHEL-03**: Unfixed CVEs for RHEL/Rocky distros are accurately reported without duplicates

### Code Quality

- [ ] **QUAL-01**: vuln.rs broken into focused submodules, each under 800 lines
- [ ] **QUAL-02**: Version comparison logic (cmp_versions, is_version_in_range) has unit tests covering edge cases
- [ ] **QUAL-03**: CPE matching logic (cpe_parts, nvd_findings_by_product_version) has unit tests
- [ ] **QUAL-04**: OVAL evaluation (compare_evr, evaluate_oval_for_packages) has unit tests
- [ ] **QUAL-05**: Package parsing (RPM header, APK, dpkg status) has unit tests for both formats
- [x] **QUAL-06**: Dead code audit — remove unreachable, half-implemented, or nonsensical code across all modules

### Infrastructure

- [ ] **INFR-01**: Daily CronJob downloads bulk data from OSV, NVD, EPSS, KEV, Debian, Ubuntu, Alpine into PostgreSQL
- [ ] **INFR-02**: CronJob exports zstd-compressed SQLite DB to MinIO for standalone CLI users to download
- [ ] **INFR-03**: Clean separation between standalone mode (file cache only) and cluster mode (PG + Redis) with no cross-contamination
- [ ] **INFR-04**: CronJob preserves all payload fields the scanner needs — no stripping that causes format mismatches

### UI/Worker

- [ ] **UIWK-01**: UI displays scanner pipeline stages with real-time progress indication and log viewing
- [ ] **UIWK-02**: Pipeline stage display handles 15+ stages without overflowing — uses compaction, scrolling, or grouped stages

### Validation

- [ ] **BENCH-01**: Benchmark suite validates ScanRook finds >= Trivy and Grype across all test images after all fixes

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Security

- **SEC-01**: Supply chain attestation and signing for scanner binary releases
- **SEC-02**: Custom YARA rules management via web UI

### Platform

- **PLAT-01**: Mobile app for scan results viewing
- **PLAT-02**: Multi-tenant billing improvements beyond current Stripe integration

## Out of Scope

| Feature | Reason |
|---------|--------|
| Mobile app | CLI and web only for this milestone |
| Real-time chat/collaboration | Not a social platform |
| Supply chain attestation/signing | Future feature, not this milestone |
| Custom YARA rules UI | CLI-only feature, documented |
| Multi-tenant billing changes | Existing Stripe integration sufficient |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SCAN-01 | Phase 4 | Pending |
| SCAN-02 | Phase 2 | Pending |
| ENRICH-01 | Phase 2 | Pending |
| ENRICH-02 | Phase 2 | Pending |
| ENRICH-03 | Phase 2 | Pending |
| ENRICH-04 | Phase 2 | Pending |
| ENRICH-05 | Phase 2 | Pending |
| ENRICH-06 | Phase 2 | Pending |
| RHEL-01 | Phase 3 | Pending |
| RHEL-02 | Phase 3 | Pending |
| RHEL-03 | Phase 3 | Pending |
| QUAL-01 | Phase 1 | Pending |
| QUAL-02 | Phase 5 | Pending |
| QUAL-03 | Phase 5 | Pending |
| QUAL-04 | Phase 5 | Pending |
| QUAL-05 | Phase 5 | Pending |
| QUAL-06 | Phase 1 | Complete |
| INFR-01 | Phase 5 | Pending |
| INFR-02 | Phase 5 | Pending |
| INFR-03 | Phase 2 | Pending |
| INFR-04 | Phase 5 | Pending |
| UIWK-01 | Phase 6 | Pending |
| UIWK-02 | Phase 6 | Pending |
| BENCH-01 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 24 total
- Mapped to phases: 24
- Unmapped: 0

---
*Requirements defined: 2026-03-02*
*Last updated: 2026-03-02 — traceability table completed, all 24 requirements mapped across 6 phases*
