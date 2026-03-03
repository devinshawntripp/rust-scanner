---
gsd_state_version: 1.0
milestone: v1.8
milestone_name: milestone
status: unknown
last_updated: "2026-03-03T17:46:23.789Z"
progress:
  total_phases: 8
  completed_phases: 2
  total_plans: 7
  completed_plans: 7
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Every scan returns accurate, complete vulnerability results — no false positives, no missed CVEs — by checking local data first and only hitting live APIs as a fallback.
**Current focus:** Phase 2 - DB-First Enrichment Pipeline

## Current Position

Phase: 2 of 6 (DB-First Enrichment Pipeline) — COMPLETE
Plan: 5 of 5 in current phase (COMPLETE — all Phase 2 plans done including gap closure 02-05)
Status: Phase 02 Complete — all 5 plans (01/02/03/04/05) done. Next: Phase 3 (RHEL/Rocky Consolidation)
Last activity: 2026-03-03 — Completed 02-05 NVD Query Circuit Breaker Gap Closure: all 4 lower-level NVD query functions now accept CircuitBreaker; binary.rs, container/source.rs, container/scan.rs, container/cli.rs updated; 52/52 tests pass

Progress: [██████████] 67%

## Performance Metrics

**Velocity:**
- Total plans completed: 3
- Average duration: 25min
- Total execution time: 1.2 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01 | 2 | 66min | 33min |
| 02 | 5 | 39min | 8min |

**Recent Trend:**
- Last 5 plans: 12min, 54min, 5min, ~5min (02-02), 18min (02-03), 13min (02-04)
- Trend: Phase 2 plans are fast (focused enrichment pipeline changes)

*Updated after each plan completion*

| Phase 02 P02 | 10min | 2 tasks | 2 files |
| Phase 02 P04 | 13min | 2 tasks | 14 files |
| Phase 02 P05 | 3 | 2 tasks | 6 files |

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
- CircuitBreaker is scan-scoped (NOT static/OnceLock) — created fresh per scan invocation, no cross-scan state sharing
- #[allow(dead_code)] on Phase 2 forward-declared infrastructure (pg.rs helpers) — circuit.rs dead_code removed in 02-05 (all methods now used)
- Summary.warnings uses serde default + skip_serializing_if for full backward compatibility
- epss_enrich_findings and kev_enrich_findings accept caller-provided pg parameter; no internal pg_connect()
- KEV cluster-mode returns early on PG hit (avoids file-cache/API fallback when PG has fresh data)
- cli/db.rs seed path uses &mut None (benchmark/seed path should not incur PG overhead)
- Promoted pg to outer scope in sbom.rs and binary.rs (both had pg inside inner blocks unreachable by post-block epss/kev calls)
- [Phase 02]: PG check in osv_batch_query happens before retry loop — cache hits never count as retry attempts
- [Phase 02]: File cache skipped entirely in cluster mode (gated by !cluster_mode()) — not just bypassed
- [Phase 02]: pg helpers promoted to pub(crate) so osv/batch.rs submodule can access crate::vuln::pg directly
- [Phase 02-04]: One breaker per API source per scan (osv/nvd/epss/kev) — separate failure counting prevents one source's failures affecting others
- [Phase 02-04]: osv_breaker shared between osv_batch_query and osv_enrich_findings: one breaker for all OSV operations per scan
- [Phase 02-04]: Jittered TTL (30 +/- 7 days) replaces compute_dynamic_ttl_days in OSV enrich and NVD enrich paths
- [Phase 02-04]: Warning collection is post-enrichment: iterate all 4 breakers after enrichment pipeline, push to summary.warnings
- [Phase 02-04]: Seed/benchmark paths use per-call breakers with &mut None pg (no PG overhead for seed operations)
- [Phase 02-05]: breaker as last parameter on all 4 NVD query functions: consistent with enrichment function convention from Plan 04
- [Phase 02-05]: binary.rs breakers moved before if !bytes.is_empty() block: ensures nvd_breaker in scope for both NVD loop and post-block enrichment calls
- [Phase 02-05]: Separate named breakers in source.rs: nvd_breaker_build (initial query loop) and nvd_breaker_src (enrich step) to avoid shared state between function phases

### Pending Todos

- Create phase directories for phases 4, 5, 6 under .planning/phases/

### Blockers/Concerns

- (RESOLVED) vuln/redhat_enrich.rs split into inject.rs (700), cve_enrich.rs (519), helpers.rs (456)
- (RESOLVED 02-01) Orphaned flat module files (distro.rs, nvd.rs, osv.rs, redhat_enrich.rs) blocked compilation — removed
- Three RHEL codepaths have overlapping but non-identical results; regression risk is high without Phase 1 refactor complete before Phase 3
- INFR-04 (cronjob payload stripping) — the Python cronjob strips fields from OSV/NVD payloads; this must be verified and fixed in Phase 5 or the PG cache will contain broken data

## Session Continuity

Last session: 2026-03-03
Stopped at: Phase 2 plan 05 complete — NVD query circuit breaker gap closure. All 4 lower-level NVD query functions now accept CircuitBreaker. All NVD API call paths are circuit-breaker-protected. 52/52 tests pass. Zero warnings in release build.
Resume file: .planning/phases/03-rhel-rocky-consolidation/03-01-PLAN.md
