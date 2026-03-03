---
phase: 02-db-first-enrichment-pipeline
plan: 03
subsystem: vuln
tags: [postgres, epss, kev, cluster-mode, caching]
dependency_graph:
  requires:
    - phase: 02-db-first-enrichment-pipeline
      plan: 01
      provides: [pg_get_epss_scores, pg_put_epss_scores, pg_get_kev_entries, pg_put_kev_entries, compute_jittered_ttl_days]
  provides:
    - PG-aware EPSS enrichment with cluster/standalone mode separation
    - PG-aware KEV enrichment with cluster/standalone mode separation
    - epss_enrich_findings accepts pg parameter
    - kev_enrich_findings accepts pg parameter
    - All ~10 call sites updated with pg parameter
  affects: [src/vuln/epss.rs, src/vuln/kev.rs, all scan orchestration files]
tech-stack:
  added: []
  patterns:
    - "Caller-provided PG connection: enrichment functions receive pg from caller, no internal pg_connect()"
    - "Cluster mode guard: crate::vuln::cluster_mode() checked before any PG operation"
    - "pg2 naming for secondary PG connection where caller's pg is out of scope"
    - "Promote pg to outer scope when inner block pg needs to reach post-block enrichment"
key-files:
  created: []
  modified:
    - src/vuln/epss.rs
    - src/vuln/kev.rs
    - src/container/scan.rs
    - src/container/cli.rs
    - src/container/source.rs
    - src/binary.rs
    - src/sbom.rs
    - src/iso/report.rs
    - src/archive/scan.rs
    - src/archive/dmg.rs
    - src/cli/db.rs
key-decisions:
  - "PG is passed from caller rather than opened internally: avoids duplicate connections, allows connection reuse across OSV/NVD/EPSS/KEV pipeline"
  - "KEV cluster-mode returns early after PG hit: avoids unnecessary fallback to file cache/API"
  - "api_fetched tracking vec: API-fetched EPSS scores are collected then bulk-written to PG in one pass at the end"
  - "cli/db.rs seed path uses &mut None: benchmark/seed path should not incur PG overhead"
  - "scan_source_tarball uses pg2 naming: avoids conflict with build_source_report's pg in different function scope"
  - "Promoted pg to outer scope in sbom.rs and binary.rs: both had pg inside inner blocks unreachable by post-block epss/kev calls"
requirements-completed:
  - ENRICH-02
  - ENRICH-03
  - ENRICH-04
duration: 18min
completed: 2026-03-03
---

# Phase 2 Plan 03: EPSS and KEV PG Cache Support Summary

**epss_enrich_findings and kev_enrich_findings now accept a caller-provided pg connection, check PG cache before live API calls in cluster mode, and write API results back to PG — all 10+ call sites updated.**

## Performance

- **Duration:** 18 min
- **Started:** 2026-03-03T16:34:00Z
- **Completed:** 2026-03-03T16:52:33Z
- **Tasks:** 2
- **Files modified:** 11

## Accomplishments

- Both `epss_enrich_findings` and `kev_enrich_findings` accept `pg: &mut Option<PgClient>` parameter
- In cluster mode: EPSS checks `pg_get_epss_scores` (Plan 01 helper) before calling FIRST.org API; API results written back via `pg_put_epss_scores`
- In cluster mode: KEV checks `pg_get_kev_entries` (Plan 01 helper) before calling CISA API; API results written back via `pg_put_kev_entries`
- Standalone mode unchanged: file cache path used exclusively, PG never touched
- All 10 call sites updated across 9 files with `&mut pg` or `&mut None`
- Compilation clean: zero errors, zero warnings, 52/52 tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Add PG support to epss_enrich_findings and kev_enrich_findings** - `8768a8d` (feat)
2. **Task 2: Update all epss/kev call sites with pg parameter** - `d2b4d33` (feat)

## Files Created/Modified

- `src/vuln/epss.rs` - Changed signature; added cluster-mode PG hit/miss/write path
- `src/vuln/kev.rs` - Changed signature; added cluster-mode PG hit with early return path
- `src/container/scan.rs` - Pass `&mut pg` (pg already in scope from osv_enrich)
- `src/container/cli.rs` - Pass `&mut pg` (pg already in scope from osv_enrich)
- `src/container/source.rs` - `build_source_report` uses existing `pg`; `scan_source_tarball` adds `pg2`
- `src/binary.rs` - Promoted `pg` from inner block to outer scope to reach epss/kev calls
- `src/sbom.rs` - Promoted `pg` from inner if-else block to outer scope to reach epss/kev calls; also fixed `osv_batch_query` call (Plan 02-02 changed signature)
- `src/iso/report.rs` - Pass `&mut pg` (pg already in scope)
- `src/archive/scan.rs` - Pass `&mut pg` (pg already in scope)
- `src/archive/dmg.rs` - Moved pg initialization before `osv_batch_query`; pass `&mut pg` to epss/kev
- `src/cli/db.rs` - Pass `&mut None` for seed path; fixed `osv_batch_query` seed call

## Decisions Made

- Caller-provided PG connection rather than internal `pg_connect()`: the function reuses whatever connection the caller already opened for OSV/NVD enrichment. No duplicate TCP connections, no extra connection overhead.
- KEV cluster-mode returns early on PG hit: once we have the KEV set from PG, the function applies it to findings and returns, skipping the file-cache and API paths entirely.
- `api_fetched` tracking vec in EPSS: API-fetched scores are collected into a `Vec<(String, f32, f32)>` then written to PG in one pass after the loop, matching the `pg_put_epss_scores` batch signature.
- `pg2` in `scan_source_tarball`: this function is separate from `build_source_report` (which has its own `pg`). Using `pg2` avoids shadowing confusion.
- Scope promotion for `pg` in `sbom.rs` and `binary.rs`: both files had `pg` inside a block that didn't extend to the epss/kev calls. Moving `pg` to outer scope fixes scope without structural refactor.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed remaining osv_batch_query call sites blocking compilation**
- **Found during:** Task 2 (updating all call sites)
- **Issue:** Plan 02-02 changed `osv_batch_query` to accept a `pg` parameter, but 3 call sites still used the old 1-argument form: `archive/dmg.rs:113`, `cli/db.rs:576`, plus scope issues in `sbom.rs` and `binary.rs`
- **Fix:** Updated `archive/dmg.rs` to move `pg` before `osv_batch_query` call and pass `&mut pg`; updated `cli/db.rs` to pass `&mut None` to seed path; fixed scope issues in `sbom.rs` and `binary.rs` by promoting `pg` out of inner blocks
- **Files modified:** src/archive/dmg.rs, src/cli/db.rs, src/sbom.rs, src/binary.rs
- **Verification:** `cargo check` — zero errors; `cargo test` — 52/52 pass
- **Committed in:** d2b4d33 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (blocking compilation issue from parallel Plan 02-02 changes)
**Impact on plan:** Auto-fix necessary for compilation. Scope stayed within Task 2's files. No new scope or new functionality.

## Issues Encountered

- Plan 02-02 was running in parallel and changed `osv_batch_query` signature but left some call sites using the old 1-argument form. Fixed under Rule 3 (blocking compilation).
- `pg` variable scope issues in `sbom.rs` and `binary.rs` where pg was declared inside inner blocks not visible to the post-block epss/kev calls. Resolved by promoting pg to outer scope.

## Next Phase Readiness

- EPSS and KEV enrichment functions are now PG-aware in cluster mode
- Combined with Plan 02 (OSV PG cache), 3 of 4 major enrichment sources now check PG before hitting live APIs
- Plan 04 (NVD PG cache) is the remaining enrichment source
- All call sites compile cleanly, all 52 tests pass

---
*Phase: 02-db-first-enrichment-pipeline*
*Completed: 2026-03-03*

## Self-Check: PASSED

- [x] src/vuln/epss.rs exists with pg parameter in signature
- [x] src/vuln/kev.rs exists with pg parameter in signature
- [x] 02-03-SUMMARY.md exists
- [x] Commit 8768a8d exists (Task 1)
- [x] Commit d2b4d33 exists (Task 2)
- [x] cargo check: Finished (zero errors)
- [x] cargo test: 52/52 pass
