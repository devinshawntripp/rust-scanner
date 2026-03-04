# Phase 1: Code Audit and Module Refactor - Context

**Gathered:** 2026-03-02
**Updated:** 2026-03-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Clean up the codebase: audit all modules for dead/unreachable/half-implemented code and remove it. Break ALL oversized modules (not just vuln/) into focused submodules under 800 lines each. No functional changes to scanning behavior — this is reorganization and cleanup only, making subsequent phases safe to execute.

</domain>

<decisions>
## Implementation Decisions

### Split Scope
- Split ALL files over 800 lines across the entire project, not just vuln/ submodules
- Target files (10 total):
  - `vuln/redhat_enrich.rs` (1,858 lines) — highest priority, Phase 2-3 critical path
  - `archive.rs` (1,604 lines) — lower priority, Phase 4 dependency
  - `vulndb.rs` (1,447 lines) — split by concern: build, query, fetch
  - `redhat.rs` (1,351 lines) — highest priority, Phase 2-3 critical path
  - `container/scan.rs` (1,268 lines) — split into pipeline stages: orchestrate, inventory, enrich
  - `iso.rs` (1,089 lines) — lower priority, Phase 4 dependency
  - `vuln/osv.rs` (993 lines) — highest priority, Phase 2 critical path
  - `main.rs` (953 lines) — Claude's discretion on whether to split
  - `vuln/nvd.rs` (868 lines) — borderline, Claude's discretion
  - `vuln/distro.rs` (804 lines) — borderline, Claude's discretion
- Priority order: vuln/ and redhat modules first (Phase 2-3 depend on them), then container/scan.rs, then archive.rs/iso.rs/vulndb.rs

### Module Split Approaches
- `vulndb.rs` → split into vulndb/build.rs (bulk import), vulndb/query.rs (cache lookups), vulndb/fetch.rs (download from API)
- `container/scan.rs` → split into scan/orchestrate.rs (main flow), scan/inventory.rs (package detection dispatch), scan/enrich.rs (enrichment calls)
- `redhat.rs` and `redhat_enrich.rs` → Claude assesses whether to merge/redesign boundaries or keep separate with cleaner splits. Goal: single clear responsibility per module
- Other files: Claude determines natural split points based on code structure

### Plan Structure
- Two plans: audit first, then refactor
  - Plan 1: Dead code audit — scan all modules, remove dead/unreachable code, document in commits
  - Plan 2: Module splits — break all oversized files into focused submodules
- Audit before refactor ensures we don't waste time splitting dead code

### Dead Code Audit
- Full sweep across all modules
- Remove ALL unreachable, half-implemented, or nonsensical code
- No separate report file — each commit message explains what was removed and why (git log IS the audit trail)
- build_report.rs already removed (confirmed gone)
- Hunt for: dead functions, unused imports, stale feature flags, orphaned code paths

### Commit Strategy
- One atomic commit per module split in Plan 2
- Easy to revert individual splits if something breaks
- Expect ~8-10 commits for module splits

### Cleanup Scope
- Claude's discretion on what to clean up vs leave alone
- Fix dangerous unwrap/expect calls that can actually panic on real data, leave safe patterns like unwrap_or_default()
- Consolidate duplicated logic where it improves clarity
- Compile regex patterns into OnceLock statics where they're currently compiled multiple times

### Bug Fixes During Audit
- Claude judges severity — fix critical bugs found during audit (e.g., missing timeouts), document minor issues for later phases
- Don't introduce functional changes that could affect scan accuracy

### Claude's Discretion
- Exact module split boundaries for files not explicitly specified above
- Whether main.rs benefits from splitting (953 lines for 12 subcommands)
- Whether nvd.rs (868) and distro.rs (804) need splitting at the borderline
- Which unwrap/expect calls to convert vs leave
- Whether to merge redhat.rs + redhat_enrich.rs or keep separate with cleaner boundaries
- Naming conventions for new submodules

</decisions>

<specifics>
## Specific Ideas

- User wants a "clean sweep" — read all code, look for anything that "seems off"
- This is an audit first, refactor second — understand what's there before reorganizing
- The user trusts Claude's judgment on technical decisions for this phase
- Priority order matters: vuln/ and redhat modules first, archive/iso/vulndb lower priority

</specifics>

<code_context>
## Existing Code Insights

### Files Requiring Attention (updated line counts)
- `src/vuln/redhat_enrich.rs` (1,858 lines) — Red Hat unfixed CVE injection
- `src/archive.rs` (1,604 lines) — archive extraction (tar, zip, etc.)
- `src/vulndb.rs` (1,447 lines) — SQLite vulndb operations
- `src/redhat.rs` (1,351 lines) — OVAL XML parsing and evaluation
- `src/container/scan.rs` (1,268 lines) — container scan orchestration
- `src/iso.rs` (1,089 lines) — ISO image scanning
- `src/vuln/osv.rs` (993 lines) — OSV API integration, batch query
- `src/main.rs` (953 lines) — Clap CLI entry point, 12+ subcommands
- `src/vuln/nvd.rs` (868 lines) — NVD API integration
- `src/vuln/distro.rs` (804 lines) — Debian/Ubuntu/Alpine feeds

### Well-Structured Modules (patterns to follow)
- `src/vuln/` already has clean per-concern splits: epss.rs (173), kev.rs (111), version.rs (68), cvss.rs, pg.rs (456), http.rs (341)
- `src/container/` has clean splits: detect.rs (197), dpkg.rs (111), ecosystem.rs (107), image.rs (92), apk.rs
- OnceLock statics used for HTTP clients — same pattern for regex compilations
- Error handling: anyhow::Result in some places, raw unwrap in others

### unwrap/expect Inventory
- 47 total across 11 files
- Hotspots: archive.rs (15), redhat.rs (9), main.rs (6), binary.rs (4), vuln/tests.rs (4)

### Integration Points
- Module public APIs (function signatures) must remain stable
- Re-exports in vuln/mod.rs and container/mod.rs must be updated when files are split
- main.rs imports from all modules — import paths will change after splits

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-code-audit-and-module-refactor*
*Context gathered: 2026-03-02*
*Context updated: 2026-03-02*
