# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Every scan returns accurate, complete vulnerability results — no false positives, no missed CVEs — by checking local data first and only hitting live APIs as a fallback.
**Current focus:** Phase 1 - Code Audit and Module Refactor

## Current Position

Phase: 1 of 6 (Code Audit and Module Refactor)
Plan: 2 of 2 in current phase (COMPLETE)
Status: Phase 01 Complete
Last activity: 2026-03-03 — Completed 01-02 module splits (9 modules split, all under 800 lines)

Progress: [██░░░░░░░░] 17%

## Performance Metrics

**Velocity:**
- Total plans completed: 2
- Average duration: 33min
- Total execution time: 1.1 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01 | 2 | 66min | 33min |

**Recent Trend:**
- Last 5 plans: 12min, 54min
- Trend: Second plan larger scope (10 splits vs 1 audit)

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Test-only functions gated behind #[cfg(test)] rather than deleted to preserve test coverage
- Sibling submodule re-exports split into production (use) and test-only (#[cfg(test)] use) in vuln/mod.rs
- All production unwrap/expect calls assessed as provably safe -- no conversions needed
- Regex OnceLock conversion deferred -- no hot-path compilations found
- main.rs split by extracting upgrade and sbom handlers to cli/ (953 -> 728 lines)
- Directory module pattern: flat .rs -> directory/ with mod.rs for files over 800 lines
- Minimal re-exports: only pub use items actually used externally to avoid warnings
- Container scan split as sibling files (cli.rs, source.rs) rather than subdirectory
- Refactor before feature work: monolithic modules and dead code make bug fixes risky
- DB-first enrichment: 5GB of data exists in PG but scanner still hits live APIs on every scan
- osv_batch_query() in src/vuln/osv.rs has zero PG cache support — this is the #1 bug, fixed in Phase 2
- Consolidate RHEL enrichment paths: three overlapping codepaths cause gaps and fragility
- SCAN-02 (HTTP timeouts) addressed in Phase 2 alongside enrichment, not separately
- INFR-03 (standalone/cluster separation) addressed in Phase 2 — it is a symptom of the same enrichment pipeline bug
- SCAN-01 (multi-format reliability) is Phase 4 — depends on Phase 1 refactor only, can run in parallel with Phase 2 and 3 in practice
- Daily cronjob -> PG -> zstd -> MinIO is Phase 5 — tested after core enrichment pipeline is correct
- UI work (UIWK-01, UIWK-02) is Phase 6, in a separate repo, and can be worked independently
- Benchmark validation (BENCH-01) is last — validates all other fixes together

### Pending Todos

- Create phase directories for phases 4, 5, 6 under .planning/phases/

### Blockers/Concerns

- (RESOLVED) vuln/redhat_enrich.rs split into inject.rs (700), cve_enrich.rs (519), helpers.rs (456)
- Three RHEL codepaths have overlapping but non-identical results; regression risk is high without Phase 1 refactor complete before Phase 3
- INFR-04 (cronjob payload stripping) — the Python cronjob strips fields from OSV/NVD payloads; this must be verified and fixed in Phase 5 or the PG cache will contain broken data

## Session Continuity

Last session: 2026-03-03
Stopped at: Completed 01-02-PLAN.md (Phase 01 complete)
Resume file: None
