# Milestone 7 — Scanner Refactor Notes

Observations from Milestone 4 scanner quality work.

## Speed Improvements

### 1. Sequential Enrichment Pipeline (HIGH PRIORITY)
- **Location**: `container/scan.rs:254-605`, `sbom.rs:38-98`
- OSV, NVD, OVAL, EPSS, KEV all run sequentially
- OSV + NVD are independent and can run concurrently via `tokio::join!`
- EPSS + KEV are independent of each other and of the main pipeline
- Estimated speedup: 30-50% on enrichment phase

### 2. Circuit Breaker Per-Source Overhead
- Each scan creates 4 fresh circuit breakers
- Consider shared breakers with TTL so a failed source stays tripped across scans

### 3. S3 Fallback in Findings API
- `route.ts` does an extra DB query when filters return 0 rows
- Could cache whether job has DB findings in the job record itself

## Accuracy Improvements

### 4. Binary Version Extraction
- `.so` ABI version != release version (e.g. libssl.so.1.1 != OpenSSL 1.1.1w)
- Consider parsing ELF `.note` sections or `.comment` for actual version strings

### 5. PE DLL Import Version Assignment
- `binary.rs:282-291`: single version from `find_version_in_bytes` assigned to ALL imports
- Fix: only assign version to imports where we find matching version strings

### 6. Raw Byte Regex False Positives
- `binary.rs:537-555`: matches compiler strings, build paths, copyright notices
- Add exclusion patterns for common false positive strings (gcc, clang, Copyright)

### 7. SBOM Error Swallowing (FIXED in M4)
- `build_sbom_report` now returns Result instead of Option

### 8. Heuristic Filter Bug (FIXED in M4)
- S3 fallback no longer bypasses tier filters

## Code Quality

### 9. Duplicate Scan Logic
- `container/scan.rs` and `container/cli.rs` have nearly identical enrichment pipelines
- Refactor to shared enrichment function

### 10. vuln/mod.rs Size
- ~169KB single file — split into focused submodules (done partially, continue)

### 11. Test Coverage
- Binary scanning has minimal tests
- ISO comps.xml filtering has no test for the status fix
- Add integration tests with small test fixtures
