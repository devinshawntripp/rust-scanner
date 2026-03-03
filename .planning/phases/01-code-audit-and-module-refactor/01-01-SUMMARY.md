---
phase: 01-code-audit-and-module-refactor
plan: 01
subsystem: scanner
tags: [rust, dead-code, compiler-warnings, code-audit, unwrap-safety]

requires: []
provides:
  - "Zero-warning codebase ready for module split refactoring"
  - "Clean re-export structure in vuln/mod.rs with test-only imports gated"
  - "All 46 existing tests passing on cleaned code"
affects: [01-02-PLAN, 02-enrichment-pipeline]

tech-stack:
  added: []
  patterns:
    - "#[cfg(test)] gating for test-only re-exports in vuln/mod.rs"
    - "Sibling submodule access via use (not pub use) internal re-exports"

key-files:
  created: []
  modified:
    - src/vulndb.rs
    - src/license.rs
    - src/vuln/mod.rs
    - src/vuln/debian_legacy.rs
    - src/vuln/distro.rs
    - src/vuln/osv.rs
    - src/vuln/nvd.rs
    - src/vuln/redhat_enrich.rs
    - src/archive.rs
    - src/container/mod.rs
    - src/container/scan.rs
    - src/progress.rs
    - src/sbom.rs
    - src/cli/db.rs
    - src/cli/mod.rs
    - src/main.rs

key-decisions:
  - "Test-only functions (detect_debian_release, urgency_to_severity) gated behind #[cfg(test)] rather than deleted, preserving test coverage"
  - "Sibling submodule re-exports split into production (use) and test-only (#[cfg(test)] use) in vuln/mod.rs"
  - "No dangerous unwrap/expect calls found in production code -- all are provably safe patterns (hardcoded regex, post-check unwrap, serialization of valid structs, CLI-context operations)"
  - "Regex OnceLock conversion deferred -- no hot-path regex compilations found (all called once per scan)"

patterns-established:
  - "cfg(test) gating: Test-only re-exports behind #[cfg(test)] to avoid dead-code warnings while preserving test access"
  - "Internal vs public re-exports: use (not pub use) for sibling submodule access within vuln/"

requirements-completed: [QUAL-06]

duration: 12min
completed: 2026-03-03
---

# Phase 01 Plan 01: Dead Code Audit Summary

**Eliminated 53 compiler warnings by removing 663 lines of dead code across 16 files, with zero-warning release build and all 46 tests passing**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-03T04:53:15Z
- **Completed:** 2026-03-03T05:05:28Z
- **Tasks:** 2
- **Files modified:** 16

## Accomplishments
- Removed 663 lines of dead code: unused functions, structs, imports, statics, and stale assignments
- Achieved zero compiler warnings (down from 53)
- All 46 existing tests pass without modification to test logic
- Audited all 47 unwrap/expect calls across production code -- zero dangerous patterns found

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove all dead functions, structs, and stale code** - `35514dc` (fix)
2. **Task 2: Audit for dangerous unwrap/expect patterns** - No code changes needed (all patterns assessed as safe)

## Files Created/Modified

**vulndb.rs** - Removed VulnDb struct, 12 dead query/decompress functions, print_db_status, unused imports (GzEncoder, Compression). Fixed unnecessary mut on url variable.

**license.rs** - Removed LicenseReport, LicenseSummary structs, LICENSE_FILE_NAMES static, scan_licenses_in_tree and build_license_report functions. Removed unused walkdir/Path imports.

**vuln/mod.rs** - Restructured re-exports: removed dead public debian_tracker_enrich export, split internal re-exports into production (use) and test-only (#[cfg(test)] use) categories. Removed dead resolve_cache_dir re-export from cli/mod.rs.

**vuln/debian_legacy.rs** - Removed dead debian_tracker_enrich function (155 lines), debian_tracker_enabled helper, serde_json/HashSet imports. Gated detect_debian_release and urgency_to_severity behind #[cfg(test)].

**vuln/distro.rs** - Removed unnecessary parentheses around two if conditions.

**vuln/osv.rs** - Removed unused HashMap/HashSet imports.

**vuln/nvd.rs** - Removed unused sleep/Duration imports.

**vuln/redhat_enrich.rs** - Removed unused EvidenceItem import. Removed dead client variable in redhat_inject_unfixed_cves.

**archive.rs** - Removed unused EvidenceItem/PathBuf imports, fixed unnecessary mut, prefixed unused variable with underscore.

**container/mod.rs** - Removed unused extract_tar re-export.

**container/scan.rs** - Fixed two instances of rootfs dead initial assignment.

**progress.rs** - Removed dead stage_progress and current_pct functions, unused progress import.

**sbom.rs** - Removed dead check_policy function (check_policy_from_value is the live path).

**cli/db.rs** - Removed unused DataSourceDef import.

**main.rs** - Removed unused resolve_cache_dir import.

## Decisions Made

1. **Test-only functions gated, not deleted**: detect_debian_release and urgency_to_severity are called only from vuln/tests.rs. Rather than deleting them (which would break tests) or leaving them (which would trigger warnings), they were gated behind #[cfg(test)].

2. **Re-export strategy for vuln submodules**: Production code in sibling submodules (osv.rs calling redhat_enrich_findings via super::) requires internal `use` re-exports. Test code requires separate `#[cfg(test)] use` re-exports. This clean separation avoids all warnings.

3. **Unwrap audit conclusion**: All 47 production unwrap/expect calls are provably safe:
   - 4x Regex::new with hardcoded valid patterns (expect with explanatory message)
   - 5x serde_json::to_string_pretty on well-formed structs
   - 4x regex capture group access after successful match
   - 2x Mutex/condvar standard poisoning behavior
   - 1x HTTP client builder with defaults
   - 1x epoch.unwrap() inside if epoch.is_some() branch
   - 1x .unwrap() after .is_err() short-circuit check
   - 2x CLI-context operations (tempdir, current_exe) with descriptive expect messages
   - Remaining in test code (correctly left as-is)

4. **Regex OnceLock conversion deferred**: The CVE regex is compiled in 6+ locations, but each is called once per scan (not in loops). Moving to OnceLock would save microseconds per scan -- not worth the code complexity.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Re-export structure required for sibling submodule access**
- **Found during:** Task 1
- **Issue:** Removing all internal re-exports from vuln/mod.rs broke production code in osv.rs that calls redhat_enrich_findings, redhat_enrich_cve_findings, distro_feed_enrich_findings, and map_debian_advisory_to_cves via super::
- **Fix:** Added production re-exports (use, not pub use) for functions accessed by sibling submodules, and separate #[cfg(test)] re-exports for test-only functions
- **Files modified:** src/vuln/mod.rs
- **Verification:** cargo build --release (zero warnings) + cargo test (46 passed)
- **Committed in:** 35514dc

**2. [Rule 3 - Blocking] Unused re-export in cli/mod.rs cascading from main.rs removal**
- **Found during:** Task 1
- **Issue:** Removing resolve_cache_dir import from main.rs exposed an unused re-export warning in cli/mod.rs
- **Fix:** Removed unused resolve_cache_dir from cli/mod.rs pub use statement
- **Files modified:** src/cli/mod.rs
- **Verification:** cargo build --release (zero warnings)
- **Committed in:** 35514dc

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both auto-fixes were necessary to achieve zero warnings without breaking production code. No scope creep.

## Issues Encountered
None -- plan executed smoothly after deviation fixes.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Codebase compiles with zero warnings and passes all 46 tests
- Clean re-export structure established in vuln/mod.rs for Plan 02 module splits
- All dead code removed so Plan 02 operates on living code only

---
*Phase: 01-code-audit-and-module-refactor*
*Completed: 2026-03-03*
