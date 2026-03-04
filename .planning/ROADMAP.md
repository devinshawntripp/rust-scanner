# Roadmap: ScanRook

## Overview

This milestone refactors and stabilizes ScanRook's vulnerability enrichment engine. The scanner works but has critical correctness bugs: 5GB of enrichment data sits unused in PostgreSQL while live API calls still fire on every scan; RHEL/Rocky scanning has three fragmented codepaths with overlapping results and gaps; the scanner crashes or hangs on certain image types and API failures; and dead code throughout the codebase makes every fix riskier than it should be. Phases are ordered to establish a clean foundation first (audit + refactor), then fix the worst bugs (enrichment pipeline + HTTP safety), then RHEL accuracy, then multi-format reliability, then tests + infrastructure hardening, and finally UI and benchmark validation.

## Phases

- [x] **Phase 1: Code Audit and Module Refactor** - Remove dead code, break up monolithic modules so subsequent bug fixes are safe to make
- [x] **Phase 2: DB-First Enrichment Pipeline** - Fix the #1 bug: scanner checks PostgreSQL before any live API call, with HTTP timeouts and clean standalone/cluster separation
- [ ] **Phase 3: RHEL/Rocky Consolidation** - Unify three fragmented RHEL enrichment codepaths into one accurate, deduplicated pipeline
- [ ] **Phase 4: Multi-Format Scanning Reliability** - Scanner handles all image types (ISO, DMG, OCI, docker-save) without crashing or hanging
- [ ] **Phase 5: Test Coverage and Cronjob Hardening** - Unit tests for core logic, daily cronjob imports to PG and exports to MinIO with full payloads
- [ ] **Phase 6: UI and Benchmark Validation** - Fix pipeline overflow in UI, confirm ScanRook >= Trivy and Grype after all fixes

## Phase Details

### Phase 1: Code Audit and Module Refactor
**Goal**: The codebase is clean — dead code removed, monolithic modules broken into focused submodules — so every subsequent bug fix targets the right code and introduces no regressions
**Depends on**: Nothing (first phase)
**Requirements**: QUAL-01, QUAL-06
**Success Criteria** (what must be TRUE):
  1. Every submodule under src/vuln/ is under 800 lines with a single clearly named responsibility
  2. A dead code audit report lists all removed or quarantined code, and `cargo build` compiles cleanly with zero warnings after removal
  3. The diff between old and new module structure is reviewable — no functional changes, only reorganization and deletion
  4. `cargo test` passes without regression after all restructuring
**Plans**: 2 plans
Plans:
- [x] 01-01-PLAN.md — Dead code audit: remove all unused functions, structs, imports; fix dangerous unwraps
- [x] 01-02-PLAN.md — Module splits: break all >800-line files into focused submodules

### Phase 2: DB-First Enrichment Pipeline
**Goal**: Every scan checks the PostgreSQL cache before making any live API call, stores all API responses back to PG, and uses strict standalone/cluster mode separation with no cross-contamination — with no infinite hangs on API failures
**Depends on**: Phase 1
**Requirements**: ENRICH-01, ENRICH-02, ENRICH-03, ENRICH-04, ENRICH-05, ENRICH-06, SCAN-02, INFR-03
**Success Criteria** (what must be TRUE):
  1. A scan against an image whose CVEs are already in the PostgreSQL cache completes with zero OSV or NVD HTTP requests
  2. A scan against a new image fetches from live APIs and writes all responses back to PostgreSQL for future scans
  3. PG cache entries carry a last_checked_at timestamp; the scanner re-fetches only entries older than the configured TTL
  4. Running the scanner with SCANROOK_CLUSTER_MODE=0 never touches PostgreSQL or Redis; running with SCANROOK_CLUSTER_MODE=1 skips the local file cache
  5. All HTTP API calls have a timeout; NVD 403 rate limit responses trigger a retry with backoff rather than an infinite hang
**Plans**: 5 plans
Plans:
- [x] 02-01-PLAN.md — Foundation: CircuitBreaker struct, PG schema extensions, jittered TTL, report warnings
- [x] 02-02-PLAN.md — osv_batch_query PG cache support + all 10 caller updates
- [x] 02-03-PLAN.md — EPSS/KEV PG cache support + all caller updates
- [x] 02-04-PLAN.md — Circuit breaker wiring, mode separation enforcement, report warnings collection
- [ ] 02-05-PLAN.md — Gap closure: wire circuit breaker into NVD query functions (nvd_cpe_findings, nvd_keyword_findings, nvd_findings_by_product_version)

### Phase 3: RHEL/Rocky Consolidation
**Goal**: Rocky Linux and RHEL container scans produce accurate findings through one unified enrichment path — no duplicate CVEs, no false positives from wrong-version CPE matches
**Depends on**: Phase 2
**Requirements**: RHEL-01, RHEL-02, RHEL-03
**Success Criteria** (what must be TRUE):
  1. A Rocky 9 scan follows a single unified enrichment path — OSV, OVAL, and per-package API results are merged and deduplicated in one place, not in three independent codepaths
  2. CVE count for a known Rocky 9 test image stays within 10% of the v1.8.1 baseline (481 CVEs) across any code change
  3. No CVE from a RHEL 7 or RHEL 8 CPE entry appears in a RHEL 9 scan result
  4. Unfixed CVEs (will not fix, fix deferred) appear exactly once per package in the output
**Plans**: 4 plans
Plans:
- [ ] 02-01-PLAN.md — Foundation: CircuitBreaker struct, PG schema extensions, jittered TTL, report warnings
- [ ] 02-02-PLAN.md — osv_batch_query PG cache support + all 10 caller updates
- [ ] 02-03-PLAN.md — EPSS/KEV PG cache support + all caller updates
- [ ] 02-04-PLAN.md — Circuit breaker wiring, mode separation enforcement, report warnings collection

### Phase 4: Multi-Format Scanning Reliability
**Goal**: The scanner accepts any supported input type — ISO, DMG, tar.gz, OCI tar, docker-save tar — and completes without crashing or hanging, even on malformed or edge-case files
**Depends on**: Phase 1
**Requirements**: SCAN-01
**Success Criteria** (what must be TRUE):
  1. Scanning an ISO image, an OCI image tar, a docker-save tar, a DMG, and a source tar.gz all complete without a panic or process hang
  2. Malformed or partially corrupted archives return a structured error (not a panic), emit an error progress event, and exit with non-zero status
  3. A test suite of at least three real image tarballs (different formats) passes through the full scan pipeline end-to-end
**Plans**: 6 plans
Plans:
- [x] 04-01-PLAN.md — Post-enrichment dedup and RHEL-version CPE gating
- [x] 04-02-PLAN.md — DMG scanning: macOS package detection and dmgwiz extraction stub
- [x] 04-03-PLAN.md — OVAL evaluation and package parsing unit tests (QUAL-02/03/04/05)
- [x] 04-04-PLAN.md — Version bump to 1.10.0 and release artifacts
- [ ] 04-05-PLAN.md — Gap closure: DMG extraction hardening (documentation, tests, error messages)
- [ ] 04-06-PLAN.md — Gap closure: Tag and publish GitHub release v1.10.0

### Phase 5: Test Coverage and Cronjob Hardening
**Goal**: Core scanning logic is covered by unit tests, and the daily CronJob imports complete payloads from all sources into PostgreSQL and exports a usable SQLite snapshot to MinIO
**Depends on**: Phase 2, Phase 3, Phase 4
**Requirements**: QUAL-02, QUAL-03, QUAL-04, QUAL-05, INFR-01, INFR-02, INFR-04
**Success Criteria** (what must be TRUE):
  1. Version comparison unit tests cover epoch format, pre-release suffixes, RPM EVR, and semantic versioning edge cases — all pass with `cargo test`
  2. CPE matching unit tests verify cpe_parts parsing and nvd_findings_by_product_version version range evaluation against known CVE fixtures
  3. OVAL evaluation unit tests verify compare_evr and evaluate_oval_for_packages with known RHEL package/CVE pairs
  4. Package parsing unit tests cover RPM header (magic and no-magic formats), APK origin field extraction, and dpkg source name extraction
  5. The daily CronJob imports OSV, NVD, EPSS, KEV, Debian, Ubuntu, and Alpine data into PostgreSQL with all payload fields the scanner needs intact — verified by running a scan against PG-cached data and getting correct findings
  6. After the CronJob completes, a zstd-compressed SQLite snapshot is available at a known MinIO path that `scanrook db fetch` can download and use
**Plans**: 4 plans
Plans:
- [ ] 02-01-PLAN.md — Foundation: CircuitBreaker struct, PG schema extensions, jittered TTL, report warnings
- [ ] 02-02-PLAN.md — osv_batch_query PG cache support + all 10 caller updates
- [ ] 02-03-PLAN.md — EPSS/KEV PG cache support + all caller updates
- [ ] 02-04-PLAN.md — Circuit breaker wiring, mode separation enforcement, report warnings collection

### Phase 6: UI and Benchmark Validation
**Goal**: The scan job UI displays pipeline stages without overflow, and a benchmark run confirms ScanRook finds >= vulnerabilities compared to Trivy and Grype across all test images
**Depends on**: Phase 5
**Requirements**: UIWK-01, UIWK-02, BENCH-01
**Success Criteria** (what must be TRUE):
  1. Each scanner pipeline stage is visible by name (extract, inventory, OSV, NVD, EPSS, KEV, report) with a running/done/pending indicator that updates in real-time via SSE
  2. The pipeline stage display handles 15 or more stages without any content being hidden or cut off — uses compaction, scrolling, or grouped stage display
  3. The benchmark suite runs against alpine:3.20, debian:12, nginx:1.27, and node:20 and ScanRook finds >= the vulnerability count reported by both Trivy and Grype for each image
**Plans**: 4 plans
Plans:
- [ ] 02-01-PLAN.md — Foundation: CircuitBreaker struct, PG schema extensions, jittered TTL, report warnings
- [ ] 02-02-PLAN.md — osv_batch_query PG cache support + all 10 caller updates
- [ ] 02-03-PLAN.md — EPSS/KEV PG cache support + all caller updates
- [ ] 02-04-PLAN.md — Circuit breaker wiring, mode separation enforcement, report warnings collection

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Code Audit and Module Refactor | 2/2 | Complete | 2026-03-03 |
| 2. DB-First Enrichment Pipeline | 4/5 | Gap closure | 2026-03-03 |
| 3. RHEL/Rocky Consolidation | 0/TBD | Not started | - |
| 4. Multi-Format Scanning Reliability | 4/6 | Gap closure | - |
| 5. Test Coverage and Cronjob Hardening | 0/TBD | Not started | - |
| 6. UI and Benchmark Validation | 0/TBD | Not started | - |
