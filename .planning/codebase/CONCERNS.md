# Codebase Concerns

**Analysis Date:** 2026-03-02

## Code Organization & Maintainability

**Monolithic Modules:**
- Files: `src/vuln.rs` (was ~5,962 lines), `src/container.rs` (2,617 lines), `src/main.rs` (2,343 lines)
- Issue: Despite refactoring into subdirectories (vuln/, container/, cli/), individual files still exceed 1000 lines, making navigation and testing difficult
- Impact: Hard to locate specific functions; increased cognitive load when modifying enrichment logic; test coverage fragmented across modules
- Safe modification: Follow REFACTOR_PLAN.md Phase 1-3 to further split vuln/redhat_enrich.rs (1,858 lines), osv.rs (993 lines), and distro.rs (804 lines) into focused submodules
- Status: Partial refactor completed; Phase 1 split vuln.rs into submodules but redhat_enrich.rs still exceeds 1,800 lines

**Fragmented Test Coverage:**
- Files: Only `src/vuln/tests.rs` contains structured tests (227 lines, 12 #[test] functions); other modules have no test files
- Issue: Vulnerability enrichment logic (OSV, NVD, EPSS, KEV, distro feeds) lacks unit tests; container/rpm/dpkg parsing has no isolated tests; binary scanning patterns untested
- Impact: Regressions in enrichment logic (version comparisons, CPE matching, OVAL evaluation) can slip through; false positives/negatives may increase undetected
- Fix approach: Add test modules for:
  - Version comparison edge cases (pre-release, rc, alpha, beta, epoch-based comparisons)
  - CPE parsing and version range evaluation
  - OVAL constraint evaluation and RPM EVR comparison
  - Container layer merging and dpkg/apk/rpm parsing (use fixture data)
  - CVE enrichment pipeline (OSV → NVD → distro → EPSS → KEV)
- Priority: High - core vulnerability logic is untested

## Error Handling & Robustness

**Unwrap/Expect Usage (366+ occurrences):**
- Pattern: `.unwrap()`, `.unwrap_or()`, `.expect("message")` used throughout for fallback values and error handling
- Files affected: vuln/*.rs (distro.rs, pg.rs, osv.rs, nvd.rs, redhat_enrich.rs), container/*.rs, archive.rs, iso.rs
- Issue: While many unwraps use `unwrap_or()` with safe defaults, ~20 use `.expect()` with assertions that may not always hold (regex compiles, XML parsing, PG schema setup)
  - `src/redhat.rs:128` — `Regex::new(r"CVE-\d{4}-\d+").expect("valid CVE regex")` — assumes regex always compiles (should be unreachable but not asserted as such)
  - `src/redhat.rs:1274` — `Element::parse(xml.as_bytes()).expect("xml parse")` — crashes on malformed OVAL XML instead of returning error
  - `src/redhat.rs:1347` — `.expect("test constraint")` during OVAL evaluation
- Impact: Panics on unexpected data (malformed API responses, corrupted cache files) instead of graceful degradation
- Fix approach:
  - Replace `.expect()` with `.unwrap_or_default()` or `?` error propagation where safe
  - Wrap regex compilations in constants or OnceLock to guarantee they compile once at startup
  - Add error context with `anyhow::Context::context()` for API/parse failures
  - Return `Option<Report>` or `anyhow::Result<>` instead of panicking
- Priority: Medium - affects availability but not correctness for typical usage

**Silent Fallbacks:**
- Pattern: Functions silently return None/empty vec on errors without logging
- Examples:
  - `src/vuln/distro.rs:map_debian_advisory_to_cves()` returns None on HTTP/parse failure
  - `src/vuln/osv.rs:osv_batch_query()` retries silently, may return empty if all retries fail
  - `src/container/scan.rs` package detection falls back to heuristics without warning
- Impact: Users unaware of incomplete scans or missing enrichment; no visibility into cache/API issues
- Fix approach: Emit progress events for failures (already partially done); ensure warnings logged to stderr
- Priority: Low - non-critical data quality issue

## Vulnerability Enrichment Correctness

**Red Hat OVAL Evaluation Complexity:**
- Files: `src/redhat.rs` (1,351 lines), `src/vuln/redhat_enrich.rs` (1,858 lines)
- Issue: RHEL CVE detection has three independent codepaths:
  1. OSV batch query (missing many Red Hat specific vulnerabilities)
  2. OVAL XML evaluation (evaluates test constraints, version ranges)
  3. Per-package CVE API queries (fetches Red Hat "affected", "deferred", "will not fix")
- Each has different coverage; gaps create false negatives (unreported CVEs)
- Impact: Rocky 9 scans historically underreported by 200-300 CVEs (fixed in v1.8.1, but fragility remains)
- Fix approach:
  - Consolidate OVAL evaluation and per-package API into single unified enrichment step
  - Add integration tests comparing against known RHEL release CVE counts
  - Document why three codepaths exist and when each applies
- Status: Fixed for Rocky 9 (Apr 2026 memory notes), but underlying architecture fragile
- Priority: Medium - affects RHEL accuracy

**Version Comparison Edge Cases:**
- Files: `src/vuln/version.rs` — `cmp_versions()`, `is_version_in_range()`
- Issue: Custom version tokenizer splits on non-alphanumeric and compares integer tokens left-to-right
  - Does NOT handle: epoch (Debian format: `2:7.4.052-1`), pre-release suffixes correctly for all ecosystems
  - May fail on: RPM EVR (Epoch:Version-Release), semantic versioning with build metadata, Debian DEP5 versions
- Impact: NVD CPE matching for binaries may miss or over-match vulnerabilities due to version range errors
- Fix approach: Use existing `rpm_crate` or `versioncmp` crates for version comparison instead of custom implementation
- Priority: Medium - affects binary scanning accuracy

**NPM/Yarn/pnpm Manifest Parsing Gaps:**
- Files: `src/archive.rs` (~250 lines of package.json parsing), `src/container/detect.rs`
- Issue: Only parses top-level `package.json`; does NOT handle:
  - Nested packages (workspaces, monorepos)
  - package-lock.json / yarn.lock / pnpm-lock.yaml installed versions (parses manifest versions instead)
  - Git dependencies with commit SHAs (not resolved to published versions)
- Impact: NPM packages inside containers may report declared versions instead of installed versions; lockfile versions ignored
- Fix approach: Parse lockfiles when package.json exists; resolve git SHAs to npm registry versions
- Priority: Low - affects npm accuracy but OSV already has high coverage

## Performance & Scaling

**CVE Cache Inefficiency (Pre-v1.7.0):**
- Files: `src/vulndb.rs`, `src/cache.rs`, `src/vuln/pg.rs`
- Issue: Every CVE lookup queries PostgreSQL OR file cache separately; no deduplication across packages
  - If 10,000 packages reference CVE-2024-1234, OSV/NVD API called 10,000 times (cached per-query, but still redundant)
  - Cache key includes full query body → different chunk orderings = different cache keys = cache misses
- Impact: EPSS enrichment historically took 700ms per scan (2026-02-28 notes); fixed by sorting CVE IDs before chunking
- Status: Fixed in v1.8.1 with deterministic chunking and EPSS sort; vulndb SQLite import not yet implemented
- Priority: Low - performance fixed; but pre-computed vulndb import still pending

**Memory Pressure on Large Container Images:**
- Files: `src/container/scan.rs`, `src/vuln/osv.rs`
- Issue:
  - Entire OSV batch response loaded into memory as Vec<Value> (see osv.rs:53)
  - For node:20-bullseye with 3,868 vulnerabilities, response can be 50+ MB
  - rayon parallelization during enrichment may cause threads to allocate independently
- Impact: Container scans on memory-constrained systems (K8s pods with 512MB limit) may OOM
- Fix approach: Stream OSV/NVD responses instead of buffering; chunk enrichment step-by-step
- Priority: Medium - affects K8s deployments; not a problem on development machines

**RHEL Per-Package CVE Fetches (Parallelized in v1.8.1):**
- Files: `src/vuln/redhat_enrich.rs:redhat_inject_unfixed_cves()`
- Issue: For each RHEL package, makes API call to Red Hat CVE API (e.g., `curl https://access.redhat.com/hydra/rest/cves/cpe:a:redhat:kernel?state=affected`)
  - Rocky 9 image with 200+ packages = 200+ sequential HTTP requests
  - Fixed in v1.8.1 by parallelizing with rayon
- Status: Fixed but still slow (~400ms for 200 packages per scan)
- Impact: Scans with many RHEL packages slow (but now parallelized)
- Priority: Low - fixed; monitoring needed for timeout issues

## Security Concerns

**Archive Extraction (ZIP Slip & Decompression Bombs):**
- Files: `src/archive.rs:extract_zip()` (~50 lines), `src/container/extract.rs:extract_tar()`
- Status: ZIP Slip protection IN PLACE (validates path traversal), decompression bomb guards (MAX_ZIP_ENTRY_SIZE = 2GB, MAX_ENTRY_SIZE = 2GB)
- Remaining risk:
  - 2GB per-entry limit allows extraction of multi-GB archives (total size unbounded)
  - Symlink escape detection uses normalized paths (correct, but complex logic at lines 86-96 of extract.rs)
- Fix approach: Add total size cap across all entries; add logging for oversized entry rejections
- Priority: Low - mitigated but edge cases exist

**ISO Extraction via bsdtar:**
- Files: `src/iso.rs` (~1,076 lines)
- Issue: Uses `bsdtar` subprocess for extraction (lines 300-313); arbitrary user input passed as arguments
- Risk: `bsdtar --extract --file /tmp/malicious.iso --directory /tmp/scan` — ISO filename injection could trigger bsdtar exploits
- Mitigation: `--extract` flag prevents reading bsdtar commands from files; filename is quoted, but not escaped
- Fix approach: Use `--` argument separator; quote filename with shell::escape or validate characters
- Priority: Low - requires adversarial ISO; subprocess execution is necessary, but could be safer

**Redact Secrets from Logs:**
- Files: All modules use `progress()` which emits to stderr
- Issue: Package names with embedded credentials (e.g., `npm:myapp:1.0.0`) could appear in progress output
- Impact: If progress output is logged or captured, credentials may leak
- Fix approach: Redact known secret patterns from progress messages (API keys, tokens, passwords)
- Priority: Low - affects only if users pass secrets as package names

## Dependencies at Risk

**`yara` Feature (Optional):**
- File: `Cargo.toml` line 24
- Issue: Requires system `libyara` installed; feature gate is optional, so build succeeds without it
  - Worker Docker image may not have libyara; scanning with YARA rules in deep mode will fail silently
- Impact: Deep scans don't actually use YARA rules if binary can't load them
- Fix approach: Check for libyara at startup; error if `--mode deep --yara rules.yar` requested but libyara missing
- Priority: Low - feature is optional and documented

**`postgres` Crate (Blocking API):**
- File: `Cargo.toml` line 26
- Issue: Uses blocking postgres client (0.19), not async; enrichment functions call `client.query()` on main thread
  - Could block if PG is slow/down; no timeout on PG queries visible in code
- Impact: Slow PG responses (network issues, large dataset) can freeze scanner
- Fix approach: Add query timeout via PG connection string; consider tokio-postgres for async
- Priority: Low - PG is local in K8s, fast; but could improve resilience

**`regex` Crate (Compiled at Runtime):**
- Files: `src/vuln/distro.rs:31`, `src/redhat.rs:128,434,574,608`
- Issue: Regex patterns compiled multiple times per scan instead of cached
- Impact: Minor performance cost; not a real concern given regex complexity is low
- Fix approach: Move to OnceLock<Regex> constants or lazy_static (already done for some patterns)
- Priority: Very Low - cosmetic optimization

## Known Bugs & Workarounds

**Debian Source Package Name Lookup:**
- Files: `src/vuln/distro.rs:map_debian_advisory_to_cves()`
- Issue: Debian advisories reference SOURCE package names; dpkg status lists BINARY package names
  - Example: Advisory DSA-2024-1 for "gcc-10" source must match binary package "gcc-10-base"
- Workaround: Check `Source:` field in dpkg status; OSV query with source name
- Status: Implemented in v1.6.2 via PackageCoordinate.source_name field
- Priority: Low - fixed; test coverage for edge cases could be better

**Ubuntu Release Detection:**
- Files: `src/container/detect.rs`
- Issue: Different Ubuntu releases (focal, jammy, mantic) have separate OSV ecosystems
  - Scanner detects release via /etc/os-release or lsb-release; must exist
  - Some custom images don't have /etc/os-release
- Workaround: Falls back to generic "Debian" ecosystem if release unknown
- Priority: Low - rare edge case; fallback handles it

**Alpine Origin Field (APK Packages):**
- Files: `src/container/apk.rs`
- Issue: APK packages have `o:` origin field (e.g., alpine-baselayout/main) instead of package name
- Status: Fixed in v1.6.2; parser extracts origin and queries OSV separately
- Priority: Low - fixed; test fixtures needed to prevent regression

**RPM SQLite Header Format Variations:**
- Files: `src/container/rpm.rs:parse_rpm_sqlite()`
- Issue: RPM 4.x uses Berkeley DB; RPM 4.16+ uses SQLite
  - SQLite format has optional 16-byte magic prefix (0x8EADE801) or starts directly at entry records
  - Rocky 9 uses no-magic format
- Workaround: Check for magic; if found, skip 16 bytes; otherwise start at byte 8
- Status: Fixed in v1.6.1; handles both formats
- Priority: Low - fixed; but indicates fragile OS package detection

## Test Coverage Gaps

**Untested Areas:**
- `src/container/rpm.rs` — RPM parsing (BerkeleyDB, SQLite, EVR comparison) has no unit tests
  - Risk: Version range evaluation for RPM packages may regress; updates to rpm parsing could break silently
- `src/container/dpkg.rs` — Debian package parsing untested
  - Risk: Source field extraction, release detection
- `src/container/apk.rs` — APK origin/ecosystem detection untested
  - Risk: Alpine ecosystem mapping
- `src/archive.rs` — Zip extraction and manifest parsing untested
  - Risk: Path traversal, archive format detection
- `src/iso.rs` — ISO extraction and package detection untested
  - Risk: bsdtar subprocess usage, yum/dnf repodata parsing
- `src/binary.rs` — Binary format detection and string extraction untested
  - Risk: CPE construction from linked libraries
- `src/vuln/nvd.rs` — CPE matching and version range evaluation untested
  - Risk: Version comparisons, NVD API response parsing
- `src/vuln/redhat_enrich.rs` — OVAL evaluation and per-package CVE fetches untested
  - Risk: False positives/negatives in RHEL scans
- `src/vuln/distro.rs` — Debian/Ubuntu/Alpine enrichment untested
  - Risk: Distro-specific vulnerability matching
- `src/cli/db.rs` — Database fetch/build/import commands untested
  - Risk: Vulndb lifecycle (build, import to PG, export)

**Priority:** High — core scanning logic has ~95% coverage gap

## Scaling Limits

**PostgreSQL Enrichment Cache Growth:**
- Tables: `nvd_cve_cache`, `osv_vuln_cache`, `redhat_cve_cache`, `rhel_cves`, EPSS, KEV, distro feed caches
- Issue: Each scan adds new CVEs to cache tables; K8s cluster with 3 workers scanning 10+ images/day
  - `rhel_cves` table has composite PK (cve_id, package, rhel_version) — no dedup, grows without bound
  - Cache tables have TTL logic (`compute_dynamic_ttl_days()`) but no automated cleanup/vacuum
- Impact: PG WAL files grow; queries slow as tables balloon (currently ~8K rows osv_cache, 1.5K nvd_cache, 4K redhat_cache)
- Fix approach:
  - Set up automated pg_cron jobs to vacuum cache tables on schedule (delete rows older than TTL)
  - Add metrics to dashboard for cache table sizes
  - Consider partitioning rhel_cves by date (scan the most recent 30 days aggressively)
- Priority: Medium - not an issue yet (cluster 2 months old) but will become problem in 1 year at current growth rate

**Vulndb SQLite Size:**
- Files: `src/vulndb.rs`
- Issue: Pre-built SQLite vulndb can reach 1.8GB (compressed payloads); per-worker download/init takes time
  - Worker entrypoint downloads scanrook binary + potentially large vulndb
  - No caching of vulndb between pod restarts
- Impact: Worker startup slow (~30s for binary + vulndb download); disk usage on workers
- Fix approach: Add init container to download vulndb once at pod startup; mount as shared volume
- Priority: Medium - affects pod startup time; vulndb import to PG would reduce per-worker size

**Large Container Image Scanning:**
- Images like `node:20-bullseye` have 3,868 vulnerabilities (from v1.7.0 benchmarks)
- Issue: Enrichment pipeline processes all 3,868 findings through OSV, NVD, EPSS, KEV, distro enrichment sequentially
- Impact: Scan time ~4.9s for node:20 on fast connection (2026-02-28 notes)
- Fix approach: Already uses rayon parallelization; further optimization via streaming/incremental enrichment
- Priority: Low - acceptable performance; but room for improvement

## Missing Critical Features

**Pre-built Vulnerability Database Distribution:**
- Feature: `scanrook db fetch` — download pre-built vulndb (SQLite) from scanrook.io
- Status: Implemented in v1.7.0; requires auth + presigned S3 URL
- Gap: External CLI users (non-cluster) have no easy way to get vulndb
  - `scanrook db build` requires downloading 100+ MB of source data
  - `scanrook db fetch` requires scanrook.io access and API credentials
- Fix approach: Publish public snapshots (daily) to GitHub releases; support direct download
- Priority: Low - affects external users, not critical for cluster deployment

**SBOM Policy Enforcement:**
- Feature: `scanrook sbom policy check` — validate SBOM against policy.yaml
- Status: Implemented in v1.6.2 with Zod schema validation
- Gap: No integration with scan jobs; policies not enforced on scan reports, only on SBOM diffs
- Fix approach: Add `--policy` flag to scan commands; return non-zero exit if findings exceed policy thresholds
- Priority: Low - nice-to-have for CI/CD gating

**Supply Chain Attestation:**
- Feature: Sign reports with release keys; verify scanrook binary signatures
- Status: Not implemented
- Gap: No verification that report came from canonical scanrook binary (could be modified malicious binary)
- Fix approach: Add code signing to release pipeline; embed public key in Next.js frontend for verification
- Priority: Very Low - advanced security feature; low adoption risk

## Fragile Areas (Require Careful Modification)

**RHEL/Rocky Linux Vulnerability Detection:**
- Files: `src/vuln/redhat_enrich.rs` (1,858 lines), `src/redhat.rs` (1,351 lines), `src/vuln/distro.rs` (804 lines)
- Fragility: Three independent data sources (OSV, OVAL, per-package CVE API) with overlapping but non-identical results
  - Small changes to any one codepath can regress RHEL accuracy by 50-100 CVEs
  - OVAL evaluation is complex (test constraints, version ranges, package matching)
  - Per-package API queries have rate limits and may fail silently
- Safe modification:
  - Add integration tests comparing scans against known RHEL release manifest + Red Hat security advisories
  - Run full benchmark suite before committing changes
  - Log all three enrichment sources and their results for debugging
- Test gaps: No tests for OVAL evaluation, per-package API queries, or combined enrichment accuracy

**Cache Key Generation (Determinism Bug Fix):**
- Files: `src/vuln/osv.rs:osv_batch_query()` lines 74-84
- Fragility: Cache key is SHA256 of query body JSON; if JSON serialization order changes, cache keys change
  - Fixed in v1.8.1 by sorting CVE IDs before chunking (deterministic chunk boundaries)
  - Any future changes to query body structure could reintroduce non-determinism
- Safe modification:
  - Always sort arrays before serializing cache keys
  - Add test that verifies cache key stability across multiple runs with same packages
- Test gaps: No regression test for cache key determinism

**Container Layer Merging & Package Detection:**
- Files: `src/container/extract.rs` (merge logic), `src/container/detect.rs` (detection)
- Fragility: Docker images have multiple layers; must extract layers in order, apply file deletions from whiteout files
  - OCI images use different whiteout semantics than Docker save format
  - Symlinks and file permissions must be preserved correctly
  - If layer merging is wrong, package detection sees outdated OS (e.g., old kernel version from base layer)
- Safe modification:
  - Test against real Docker/OCI image tarballs, not synthetic fixtures
  - Verify layer extraction order via progress events
  - Compare detected packages against `docker inspect --format='{{json .Config.Labels}}'`
- Test gaps: No integration tests with real container images

---

*Concerns audit: 2026-03-02*
