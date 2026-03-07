# M7 Handoff — Session 1

**Date:** 2026-03-07
**Branch:** `feature/m7-scanner-refactor` (rust_scanner repo)

## Completed

- [x] Design doc committed (`docs/plans/2026-03-06-m7-memory-optimization-design.md`)
- [x] Implementation plan written (`docs/plans/2026-03-07-m7-implementation-plan.md`) — 17 tasks, 6 phases
- [x] **Task 1: PE DLL import version fix** — `find_version_near_name()` + `extract_version_from_region()` added, PE import block updated. 143 tests pass. Committed.

## Not Started (14 remaining tasks)

### Phase 1: Accuracy (Tasks 2-3)
- [ ] Task 2: Raw byte regex false positive exclusions (binary.rs)
- [ ] Task 3: ELF .comment version extraction (binary.rs)

### Phase 2: OVAL → PG (Tasks 4-7)
- [ ] Tasks 4-5: OVAL SQL migration + Python import (scanrook-ui repo)
- [ ] Tasks 6-7: Scanner OVAL PG query + quick_xml fallback (rust_scanner)

### Phase 3: NDJSON (Tasks 8-10)
- [ ] Task 8: Scanner NDJSON output format (rust_scanner)
- [ ] Task 9: Go worker NDJSON parsing (rust-scanner-worker repo)
- [ ] Task 10: UI NDJSON S3 fallback (scanrook-ui repo)

### Phase 4: Clone Reduction (Task 11)
- [ ] Task 11: Rc<> clone reduction in OSV mapping

### Phase 5: Quality/Speed (Tasks 12-16)
- [ ] Task 12: Deduplicate scan/cli enrichment pipelines
- [ ] Task 13: Parallel enrichment
- [ ] Task 14: Circuit breaker shared TTL
- [ ] Task 15: Test coverage (binary + ISO)
- [ ] Task 16: vuln module splitting

### Phase 6: Release (Task 17)
- [ ] Task 17: Version bump v1.13.0

## Resume Instructions

1. `cd ~/Desktop/GitHub/scanrook/rust_scanner`
2. `git checkout feature/m7-scanner-refactor`
3. Verify: `cargo test` (143 tests should pass)
4. Continue with Task 2 (raw byte regex false positives) using the implementation plan at `docs/plans/2026-03-07-m7-implementation-plan.md`
5. Use subagent-driven-development skill to dispatch implementers per task

## Key Files

- Plan: `rust_scanner/docs/plans/2026-03-07-m7-implementation-plan.md`
- Design: `rust_scanner/docs/plans/2026-03-06-m7-memory-optimization-design.md`
- Modified so far: `rust_scanner/src/binary.rs` (PE version fix)

## Cross-Repo Work

Tasks 4-5 and 10 touch `scanrook-ui` repo. Task 9 touches `rust-scanner-worker` repo. Create branches there when ready:
- scanrook-ui: `feature/m7-oval-ndjson`
- rust-scanner-worker: `feature/m7-ndjson-support`
