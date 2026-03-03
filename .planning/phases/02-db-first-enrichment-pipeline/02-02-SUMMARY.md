---
phase: 02-db-first-enrichment-pipeline
plan: 02
subsystem: vuln
tags: [postgres, osv, cluster-mode, caching, batch-query]
dependency_graph:
  requires:
    - phase: 02-db-first-enrichment-pipeline
      plan: 01
      provides: [pg_get_osv_batch_chunk, pg_put_osv_batch_chunk, compute_jittered_ttl_days, osv_batch_chunk_cache]
  provides:
    - PG-aware osv_batch_query with cluster/standalone mode separation
    - osv_batch_query checks osv_batch_chunk_cache before calling OSV API in cluster mode
    - Writes successful API responses back to PG chunk cache
    - Jittered TTL (30 ± 7 days) for cache freshness
  affects: [src/vuln/osv/batch.rs, src/vuln/pg.rs]
tech-stack:
  added: []
  patterns:
    - "Cluster-mode early return: PG chunk cache checked before entering retry loop"
    - "Standalone-mode file cache: existing cache_get/cache_put path preserved behind cluster_mode() guard"
    - "pub(crate) visibility for pg helpers accessed from osv/batch.rs submodule"
key-files:
  created: []
  modified:
    - src/vuln/osv/batch.rs
    - src/vuln/pg.rs
key-decisions:
  - "PG check happens BEFORE the retry loop, not inside it — avoids counting cache hits as retry attempts"
  - "File cache skipped in cluster mode — not just bypassed, actively gated with !cluster_mode() guard"
  - "pg_get/put_osv_batch_chunk and compute_jittered_ttl_days promoted from pub(super) to pub(crate) — needed for osv/batch.rs access"
  - "Call site updates already committed by prior 02-03 session — Task 2 was verification-only"
metrics:
  duration: 10min
  completed: 2026-03-03
  tasks_completed: 2
  files_modified: 2
---

# Phase 2 Plan 02: OSV Batch Query PG Cache Support Summary

**osv_batch_query now accepts a caller-provided PG connection and checks osv_batch_chunk_cache before calling the OSV API in cluster mode — the #1 missing cache in the enrichment pipeline.**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-03T16:42:54Z
- **Completed:** 2026-03-03T16:52:54Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

### Task 1: PG Cache Support in osv_batch_query (src/vuln/osv/batch.rs)

Changed signature from `osv_batch_query(packages)` to `osv_batch_query(packages, pg: &mut Option<PgClient>)`.

**Cluster-mode path:**
- Before entering the per-chunk retry loop, checks `pg_get_osv_batch_chunk(c, &body_digest, ttl)` with a jittered TTL (30 ± 7 days)
- On PG hit: populates results from cached JSON, emits `osv.query.chunk.pg_cache` progress event, continues to next chunk
- File cache check (`cache_get`) is gated behind `!cluster_mode()` — skipped entirely in cluster mode
- After successful API fetch: writes to PG via `pg_put_osv_batch_chunk(c, &body_digest, &v)`

**Standalone-mode path:**
- File cache check (`cache_get`) proceeds as before
- After successful API fetch: writes to file cache via `cache_put`
- PG is never accessed — the `if cluster_mode()` guard ensures no PG code runs

### Task 2: Call Site Updates (All 10 sites verified)

All 10 call sites of `osv_batch_query` were already updated in the prior `d2b4d33` commit (from the 02-03 session which ran concurrently). Task 2 was verification-only:

| Site | File | pg Parameter |
|------|------|-------------|
| 1 | src/container/scan.rs:254 | `&mut pg` (pg moved before osv call) |
| 2 | src/container/scan.rs:285 | `&mut pg` (RHEL supplement query) |
| 3 | src/container/cli.rs:162 | `&mut pg` (pg_connect added before call) |
| 4 | src/container/cli.rs:190 | `&mut pg` (RHEL supplement query) |
| 5 | src/binary.rs:356 | `&mut pg` (pg moved to outer scope) |
| 6 | src/sbom.rs:45 | `&mut pg` (pg already in scope) |
| 7 | src/iso/report.rs:144 | `&mut pg` (pg already in scope) |
| 8 | src/archive/scan.rs:132 | `&mut pg` (pg moved before osv call) |
| 9 | src/archive/dmg.rs:117 | `&mut pg` (pg moved before osv call) |
| 10 | src/cli/db.rs:576 | `&mut None` (benchmark/seed path) |

### PG Visibility Fix (src/vuln/pg.rs)

Three functions promoted from `pub(super)` to `pub(crate)` so they can be accessed from the `vuln::osv::batch` submodule via `crate::vuln::pg::`:
- `compute_jittered_ttl_days`
- `pg_get_osv_batch_chunk`
- `pg_put_osv_batch_chunk`

## Task Commits

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add PG cache support to osv_batch_query | 6a31bb3 | src/vuln/osv/batch.rs, src/vuln/pg.rs |
| 2 | Verify all call sites (no code changes — prior 02-03 commit already handled) | — | — |

## Verification

- `cargo build --release` — zero errors, zero warnings
- `cargo test --locked --no-fail-fast` — 52/52 pass
- All 10 osv_batch_query call sites pass the pg parameter
- No call site uses pg_connect() in standalone-mode-only code paths

## Deviations from Plan

### Context Discovery

**1. [Context] Prior 02-03 session had already updated all call sites**
- **Found during:** Task 2 (checking git status)
- **Issue:** A prior session (commit `d2b4d33`) ran Plan 02-03 which updated epss/kev call sites AND fixed osv_batch_query call sites (since 02-03 was blocked by the 02-02 signature change)
- **Action:** Verified call sites are correct; no code changes needed for Task 2
- **Impact:** Zero — code is correct, compilation clean, tests pass

None of the auto-fix deviations rules were triggered. The plan executed as written (Task 1 implemented, Task 2 verified).

## Self-Check

Verified:
- [x] src/vuln/osv/batch.rs has PG chunk cache lookup in cluster mode
- [x] src/vuln/osv/batch.rs has file cache in standalone mode
- [x] src/vuln/osv/batch.rs has PG write-back after API fetch in cluster mode
- [x] src/vuln/pg.rs: compute_jittered_ttl_days, pg_get_osv_batch_chunk, pg_put_osv_batch_chunk are pub(crate)
- [x] Commit 6a31bb3 exists
- [x] cargo build --release: zero warnings, zero errors
- [x] cargo test: 52/52 pass
- [x] All 10 osv_batch_query call sites pass pg parameter

## Self-Check: PASSED
