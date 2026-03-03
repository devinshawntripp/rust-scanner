---
phase: 02-db-first-enrichment-pipeline
plan: 01
subsystem: vuln
tags: [circuit-breaker, pg-schema, ttl, report, foundation]
dependency_graph:
  requires: []
  provides: [CircuitBreaker, osv_batch_chunk_cache, compute_jittered_ttl_days, Summary.warnings, pg_put_epss_scores, pg_put_kev_entries]
  affects: [src/vuln/circuit.rs, src/vuln/pg.rs, src/vuln/mod.rs, src/report.rs]
tech_stack:
  added: []
  patterns: [scan-scoped atomic circuit breaker, jittered TTL, PG upsert helpers]
key_files:
  created: [src/vuln/circuit.rs]
  modified: [src/vuln/mod.rs, src/vuln/pg.rs, src/report.rs]
decisions:
  - "#[allow(dead_code)] on Phase 2 forward-declared infrastructure (used by plans 02-04)"
  - "CircuitBreaker is NOT Arc-wrapped or static — instantiated fresh per scan"
  - "Summary.warnings uses serde default + skip_serializing_if for full backward compat"
metrics:
  duration: 5min
  completed: 2026-03-03
  tasks_completed: 2
  files_modified: 4
---

# Phase 2 Plan 01: Foundation Infrastructure Summary

**One-liner:** CircuitBreaker with atomic failure counting, jittered TTL PG helpers (osv_batch_chunk_cache, EPSS, KEV), and backward-compatible Summary.warnings field.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | CircuitBreaker struct and PG schema extensions | 0b14302 | src/vuln/circuit.rs, src/vuln/mod.rs, src/vuln/pg.rs |
| 2 | Summary.warnings field and unit tests | 3da923f | src/report.rs |

## What Was Built

### CircuitBreaker (src/vuln/circuit.rs)

Scan-scoped circuit breaker for HTTP enrichment sources. Uses `std::sync::atomic::AtomicU32` with `Ordering::SeqCst` for thread-safe failure counting. When failure count reaches threshold, emits a progress event via `crate::utils::progress()` so the user sees the circuit trip in the scan log. Resets to zero on `record_success()`.

Key design decisions:
- NOT static/OnceLock — created fresh per scan so different scans don't share failure state
- NOT Arc-wrapped internally — callers wrap if needed for multi-thread sharing
- Re-exported from `vuln` module as `pub use circuit::CircuitBreaker`

### PG Schema Extensions (src/vuln/pg.rs)

New table added to `pg_init_schema`:
- `osv_batch_chunk_cache` — stores full OSV batch query responses keyed by SHA256 of the sorted package list

New helper functions (all `pub(super)`, `#[allow(dead_code)]` for plans 02-04):
- `compute_jittered_ttl_days(base_days, jitter_days)` — adds random jitter to TTL to prevent thundering herd
- `pg_get_osv_batch_chunk` / `pg_put_osv_batch_chunk` — GET/PUT for OSV batch chunk cache
- `pg_get_epss_scores` / `pg_put_epss_scores` — batch EPSS score cache operations
- `pg_get_kev_entries` / `pg_put_kev_entries` — CISA KEV catalog cache operations

Note: `epss_scores_cache` and `kev_entries_cache` tables already existed in `pg_init_schema` from prior work. Only `osv_batch_chunk_cache` was added as a new table.

### Summary.warnings (src/report.rs)

Added `warnings: Vec<String>` to `Summary` struct:
- `#[serde(default, skip_serializing_if = "Vec::is_empty")]` — absent from JSON when empty
- Uses `#[derive(Default)]` on the struct — `Vec::new()` by default, no construction sites needed
- Backward compatible: JSON without `warnings` deserializes cleanly

### Unit Tests

6 new tests added:
- `vuln::circuit::tests::test_circuit_breaker_starts_closed`
- `vuln::circuit::tests::test_circuit_breaker_trips_at_threshold`
- `vuln::circuit::tests::test_circuit_breaker_resets_on_success`
- `vuln::circuit::tests::test_circuit_breaker_stays_open_past_threshold`
- `vuln::pg::tests::test_compute_jittered_ttl_days_range`
- `vuln::pg::tests::test_compute_jittered_ttl_days_min_clamp`

Total test count: 46 -> 52 (all pass).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Removed orphaned flat module files blocking compilation**
- **Found during:** Task 1 (first build attempt)
- **Issue:** The Phase 1 module refactor created subdirectories (`distro/`, `nvd/`, `osv/`, `redhat_enrich/`) but left untracked copies of the original flat files (`src/vuln/distro.rs`, `nvd.rs`, `osv.rs`, `redhat_enrich.rs`). Rust E0761: "file for module found at both X.rs and X/mod.rs".
- **Fix:** Deleted the 4 orphaned flat files (pre-refactor versions, content already migrated to submodules).
- **Files deleted:** src/vuln/distro.rs, src/vuln/nvd.rs, src/vuln/osv.rs, src/vuln/redhat_enrich.rs
- **Commit:** 0b14302 (included in Task 1 commit)

**2. [Rule 2 - Missing] Added `#[allow(dead_code)]` on forward-declared Phase 2 infrastructure**
- **Found during:** Task 1 build
- **Issue:** New functions are not yet called (they will be in plans 02-04), causing 7 compiler warnings
- **Fix:** Added `#[allow(dead_code)]` on each new Phase 2 function and `#![allow(dead_code)]` in circuit.rs, plus `#[allow(unused_imports)]` on the re-export in mod.rs
- **Commit:** 0b14302

## Self-Check

Verified:
- [x] src/vuln/circuit.rs exists and has 4 tests
- [x] src/vuln/mod.rs contains `pub use circuit::CircuitBreaker`
- [x] src/vuln/pg.rs contains `osv_batch_chunk_cache`, `epss_scores_cache`, `kev_entries_cache`
- [x] src/report.rs contains `warnings: Vec<String>`
- [x] Commit 0b14302 exists
- [x] Commit 3da923f exists
- [x] cargo build --release: zero warnings, zero errors
- [x] cargo test: 52/52 pass

## Self-Check: PASSED
