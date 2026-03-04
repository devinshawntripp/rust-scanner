# ScanRook

## What This Is

ScanRook is a vulnerability scanner CLI (and platform) that scans container images, ISOs, DMGs, binaries, source archives, and SBOMs for known vulnerabilities. It enriches findings from OSV, NVD, EPSS, CISA KEV, and distro-specific feeds (Red Hat OVAL, Debian, Ubuntu, Alpine). It operates in two modes: standalone (free CLI with local cache, downloads DB via `scanrook db fetch`) and cluster mode (shared PostgreSQL enrichment cache across Kubernetes workers, reads directly from PG).

## Core Value

Every scan returns accurate, complete vulnerability results — no false positives, no missed CVEs — by checking local data first and only hitting live APIs as a fallback. The scanner should be faster and more accurate than Trivy and Grype across all supported image types.

## Requirements

### Validated

- ✓ Container tar scanning (docker-save, OCI) — existing
- ✓ Binary scanning (ELF/PE/Mach-O) via goblin — existing
- ✓ Source archive scanning (tar.gz, tar.bz2) — existing
- ✓ ISO image scanning via bsdtar — existing
- ✓ SBOM import (CycloneDX, SPDX, Syft) — existing
- ✓ OSV batch vulnerability queries — existing
- ✓ NVD CPE matching with version ranges — existing
- ✓ EPSS scoring enrichment — existing
- ✓ CISA KEV catalog enrichment — existing
- ✓ Red Hat OVAL XML evaluation — existing
- ✓ Red Hat unfixed CVE injection — existing
- ✓ Multi-ecosystem package detection (RPM, APK, dpkg, npm, pip, Go, Cargo, Maven, Composer, Ruby) — existing
- ✓ File-based cache at ~/.scanrook/cache/ — existing
- ✓ PostgreSQL enrichment cache (cluster mode) — existing
- ✓ Redis distributed cache — existing
- ✓ Pre-built SQLite vulndb (scanrook db fetch/build) — existing
- ✓ NDJSON progress streaming — existing
- ✓ Light and deep scan modes — existing
- ✓ CLI auth with device flow and API key — existing
- ✓ Benchmark command (compare against Trivy/Grype) — existing
- ✓ Report diff command — existing
- ✓ SBOM policy gates — existing
- ✓ Zip Slip protection in tar extraction — existing
- ✓ ISO symlink escape detection — existing

### Active

- [ ] Scanner handles ALL image types (ISO, DMG, tar.gz, tar, OCI) without crashes or hangs
- [ ] HTTP API requests have timeouts and circuit breakers — no infinite hangs
- [ ] DB-first enrichment pipeline — scanner checks PG/cache before any live API call, stores results back
- [ ] PG cache revalidation — scanner re-fetches only when data is stale (tracked by timestamp field)
- [ ] Cronjob bulk enrichment import — daily download from all sources → PG → zstd compress → MinIO for CLI fetch
- [ ] Cronjob preserves all payload fields scanner needs — no stripping that causes format mismatches
- [ ] Accurate RHEL/Rocky scanning — consolidate three codepaths into unified enrichment, eliminate false positives
- [ ] vuln.rs module refactor — break up monolithic modules, improve testability
- [ ] Dead code audit — remove unreachable, half-implemented, or nonsensical code
- [ ] Test coverage for core scanning logic — version comparison, CPE matching, OVAL evaluation, package parsing
- [ ] Clean standalone vs cluster mode separation — no cross-contamination
- [ ] UI pipeline/progress visibility with stage indication and log viewing
- [ ] UI pipeline stage display handles many stages without overflow
- [ ] Benchmark validation — confirm ScanRook >= Trivy/Grype after all fixes

### Out of Scope

- Mobile app — CLI and web only
- Real-time chat/collaboration — not a social platform
- Supply chain attestation/signing — future feature, not this milestone
- Custom YARA rules UI — CLI-only feature, documented
- Multi-tenant billing changes — existing Stripe integration sufficient

## Context

This is a brownfield refactor milestone. The scanner works but has significant bugs:
- 5GB of enrichment data in PostgreSQL but scanner still makes live API calls (data format in PG may not match what scanner expects — Python cronjob strips payload fields during import)
- The #1 bug: osv_batch_query() in src/vuln/osv.rs has zero PG cache support — only checks file cache which is disabled in cluster mode; called BEFORE PG connection exists
- RHEL/Rocky scanning has three independent codepaths (OSV, OVAL, per-package API) that overlap and leave gaps
- vuln.rs was ~170KB before partial refactor; submodules still exceed 1,800 lines
- 366+ unwrap/expect calls throughout codebase — crashes on unexpected data
- API fetching crashes and hangs — no timeouts or circuit breakers on HTTP requests
- Scanner crashes/hangs on certain image types (ISO, DMG)
- ~95% test coverage gap in core scanning logic
- No integration tests with real container images
- UI ProgressGraph.tsx uses CSS Grid with overflow-hidden — 15+ stages overflow, content to the right becomes unviewable
- Dead/unreachable/half-implemented code throughout codebase needs audit

Three-service architecture:
- **Scanner** (this repo, Rust) — CLI tool, free standalone download
- **Worker** (`~/Desktop/GitHub/go/rust-scanner-worker`) — Go service, polls PG, runs scanner
- **UI** (`~/Desktop/GitHub/Javascript/deltaguard`) — Next.js, renamed to ScanRook, domains: scanrook.sh, scanrook.io

Infrastructure: 3-node K8s cluster with CNPG PostgreSQL, MinIO S3, Redis. Edge proxy with Caddy for TLS.

### Root Causes Identified

**Bug #1: OSV Batch Query Bypasses PG Cache (CRITICAL)**
- File: src/vuln/osv.rs — osv_batch_query()
- Has NO pg parameter, NO PostgreSQL cache lookup
- Only checks file cache via cache_get() — disabled when SCANROOK_CLUSTER_MODE=1
- Called BEFORE PG connection is established in container scan flow
- Every container scan hits the OSV API directly, ignoring 5GB of cached data

**Bug #2: Python Cronjob Strips Payload Fields**
- File: scripts/vulndb-pg-import.py (in deltaguard repo)
- OSV payloads stripped to subset of fields
- NVD payloads stripped to subset of fields
- Scanner may need fields that were removed — needs verification

**Bug #3: UI Pipeline Overflow**
- File: src/components/ProgressGraph.tsx (in deltaguard repo)
- CSS Grid with overflow-hidden (not overflow-x-auto)
- 15+ stages overflows, content to the right is unviewable

**Bug #4: API Fetch Crashes/Hangs**
- Blocking reqwest with no timeout on batch requests
- NVD enrichment hangs when API returns 403 (rate limit)
- No circuit breaker for repeated failures

## Constraints

- **Tech stack**: Rust for scanner, Go for worker, Next.js for UI — no changes
- **Cluster**: 3-node K8s with finite resources — avoid memory-intensive operations
- **Backward compat**: CLI interface must remain compatible for existing users
- **Performance**: Warm scans should complete in under 5 seconds for typical images
- **Accuracy**: ScanRook must find >= vulnerabilities compared to Trivy and Grype

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| DB-first enrichment (PG/cache before API) | 5GB of data already exists but isn't being used properly | — Pending |
| Consolidate RHEL enrichment paths | Three overlapping codepaths cause gaps and fragility | — Pending |
| Daily cronjob → PG → zstd → MinIO | Single pipeline for both cluster and standalone users | — Pending |
| Refactor before feature work | Monolithic modules and untested code make bug fixes risky | — Pending |
| Revalidation timestamps in PG cache | Scanner should re-fetch only when data is stale, not every time | — Pending |
| Cronjob stays in Python/Next.js for now | Already works there, moving to Rust not needed this milestone | — Pending |

---
*Last updated: 2026-03-02 after deep context gathering with user*
