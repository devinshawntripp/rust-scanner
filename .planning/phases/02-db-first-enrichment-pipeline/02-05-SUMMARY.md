---
phase: 02-db-first-enrichment-pipeline
plan: 05
subsystem: vuln
tags: [circuit-breaker, nvd, binary-scan, source-scan, gap-closure]
dependency_graph:
  requires:
    - phase: 02-db-first-enrichment-pipeline
      plan: 04
      provides: [CircuitBreaker wired into 5 enrichment functions, per-scan breakers in 7 scan pipelines]
  provides:
    - CircuitBreaker wired into all 4 lower-level NVD query functions
    - nvd_breaker passed to NVD query calls in binary scan, source scan, container heuristic fallback
    - All NVD API call paths are circuit-breaker-protected
  affects:
    - src/vuln/nvd/query.rs
    - src/binary.rs
    - src/container/source.rs
    - src/container/scan.rs
    - src/container/cli.rs
    - src/vuln/circuit.rs
tech-stack:
  added: []
  patterns:
    - "breaker parameter as last arg on all 4 NVD query functions: consistent with enrichment function convention"
    - "is_open() early-exit at top of each query function: prevents any HTTP call when circuit is open"
    - "record_success/record_failure on nvd_get_json result: immediate feedback, not deferred"
    - "is_open() break in binary.rs component loop: short-circuits entire per-component NVD scan"
    - "Named breaker variables in source.rs: nvd_breaker_build (build_source_report), nvd_breaker_scan (scan_source_tarball), nvd_breaker_src (enrich step)"
key-files:
  created: []
  modified:
    - src/vuln/nvd/query.rs
    - src/vuln/circuit.rs
    - src/binary.rs
    - src/container/source.rs
    - src/container/scan.rs
    - src/container/cli.rs
key-decisions:
  - "breaker as last parameter (not first): consistent with enrichment functions from Plan 04"
  - "Separate named breakers in source.rs: nvd_breaker_build for initial query loop, nvd_breaker_src for enrich step — clean separation avoids sharing state between phases of the function"
  - "binary.rs breakers moved before if !bytes.is_empty() block: ensures nvd_breaker is in scope for both the NVD loop and the post-block enrichment calls"
  - "is_open() check in binary.rs per-component for loop: break exits early on tripped breaker mid-loop"
metrics:
  duration: 3min
  started: 2026-03-03T17:37:51Z
  completed: 2026-03-03T17:41:17Z
  tasks_completed: 2
  files_modified: 6
requirements-completed:
  - ENRICH-02
  - SCAN-02
---

# Phase 2 Plan 05: NVD Query Function Circuit Breaker Gap Closure Summary

**All 4 lower-level NVD query functions (nvd_cpe_findings, nvd_keyword_findings, nvd_keyword_findings_name, nvd_findings_by_product_version) now accept a CircuitBreaker parameter and skip NVD API calls when the breaker is open. All call sites in binary.rs, container/source.rs, container/scan.rs, and container/cli.rs pass the breaker.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-03T17:37:51Z
- **Completed:** 2026-03-03T17:41:17Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

### Task 1: Add CircuitBreaker parameter to all 4 NVD query functions (2 files)

- Added `use super::super::circuit::CircuitBreaker;` to `src/vuln/nvd/query.rs`
- Added `breaker: &CircuitBreaker` as the last parameter to all 4 public NVD query functions:
  - `nvd_keyword_findings`
  - `nvd_cpe_findings`
  - `nvd_keyword_findings_name`
  - `nvd_findings_by_product_version`
- Each function adds `if breaker.is_open() { return Vec::new(); }` at the very top
- Each `nvd_get_json()` match arm calls `breaker.record_success()` on `Some(j)` and `breaker.record_failure()` on `None`
- Removed stale `#![allow(dead_code)]` from `src/vuln/circuit.rs` — all methods are now used across Plans 04 and 05
- Left `match_vuln()` unchanged (CLI diagnostic function, not scan pipeline)

### Task 2: Update all callers to pass nvd_breaker (4 files)

**src/binary.rs:**
- Moved `pg_connect`, `pg_init_schema`, and all 4 circuit breaker creations (`osv_breaker`, `nvd_breaker`, `epss_breaker`, `kev_breaker`) to BEFORE the `if !bytes.is_empty()` block
- Added `if nvd_breaker.is_open() { break; }` check at the top of the per-component NVD lookup loop
- Passed `&nvd_breaker` to `nvd_findings_by_product_version`, `nvd_cpe_findings`, `nvd_keyword_findings`

**src/container/source.rs — build_source_report:**
- Created `nvd_breaker_build` immediately before the NVD candidate for-loop
- Added `if nvd_breaker_build.is_open() { break; }` at top of loop
- Passed `&nvd_breaker_build` to all 4 NVD query calls

**src/container/source.rs — scan_source_tarball:**
- Created `nvd_breaker_scan` immediately before the NVD candidate for-loop
- Added `if nvd_breaker_scan.is_open() { break; }` at top of loop
- Passed `&nvd_breaker_scan` to all 4 NVD query calls

**src/container/scan.rs:**
- `nvd_breaker` already existed at line 250; just passed `&nvd_breaker` to all 8 NVD query calls in both heuristic fallback blocks (filename heuristic + busybox detection)

**src/container/cli.rs:**
- `nvd_breaker` already existed; passed `&nvd_breaker` to all 8 NVD query calls in both heuristic fallback blocks

## Task Commits

1. **Task 1: Add CircuitBreaker param to NVD query functions** — `2668856` (feat)
2. **Task 2: Update all callers to pass nvd_breaker** — `a1cf4fc` (feat)

## Deviations from Plan

None — plan executed exactly as written.

## Phase 2 Gap Closure Status

After Plans 01-05, all NVD API call paths have circuit breaker protection:

- **Plans 01-04:** CircuitBreaker wired into 5 enrichment functions (`osv_batch_query`, `osv_enrich_findings`, `enrich_findings_with_nvd`, `epss_enrich_findings`, `kev_enrich_findings`). All 7 scan pipeline entry points create per-scan breakers.
- **Plan 05 (this plan):** The 4 lower-level NVD query functions used in binary/source/heuristic fallback paths now also check the circuit breaker. No NVD API call can execute when the breaker is open.

## Verification Results

1. `cargo build --release` — zero errors, zero warnings (10.47s)
2. `cargo test --locked --no-fail-fast` — 52/52 tests pass
3. `grep -n "breaker" src/vuln/nvd/query.rs` — shows CircuitBreaker in all 4 functions
4. `grep -n "nvd_breaker" src/binary.rs` — breaker created before bytes check block, passed to all NVD calls
5. `grep -n "nvd_breaker" src/container/source.rs` — breaker in both build_source_report and scan_source_tarball
6. `grep -n "nvd_breaker" src/container/scan.rs` — breaker passed in heuristic fallback
7. `grep -rn "allow(dead_code)" src/vuln/circuit.rs` — empty (attribute removed)

---
*Phase: 02-db-first-enrichment-pipeline*
*Completed: 2026-03-03*

## Self-Check: PASSED

- [x] 02-05-SUMMARY.md written to correct path
- [x] src/vuln/nvd/query.rs — all 4 functions have breaker param, is_open(), record_success/failure
- [x] src/vuln/circuit.rs — #![allow(dead_code)] removed
- [x] src/binary.rs — nvd_breaker created before if !bytes.is_empty(), passed to all NVD calls, is_open() check in loop
- [x] src/container/source.rs — nvd_breaker_build and nvd_breaker_scan created before loops, passed to all NVD calls
- [x] src/container/scan.rs — &nvd_breaker passed to all heuristic NVD calls
- [x] src/container/cli.rs — &nvd_breaker passed to all heuristic NVD calls
- [x] Commit 2668856 exists (Task 1)
- [x] Commit a1cf4fc exists (Task 2)
- [x] cargo build --release: zero warnings, zero errors
- [x] cargo test --locked --no-fail-fast: 52/52 pass
