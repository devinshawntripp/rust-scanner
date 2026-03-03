# Architecture

**Analysis Date:** 2026-03-02

## Pattern Overview

**Overall:** Multi-stage vulnerability enrichment pipeline with pluggable scanning backends.

**Key Characteristics:**
- **Auto-detection based scanning:** Magic byte inspection routes files to appropriate scanner (container, binary, source, ISO)
- **Staged enrichment pipeline:** Findings flow through OSV → NVD → EPSS → KEV stages, each enriching with additional vulnerability metadata
- **Evidence-based confidence tiers:** Findings are marked `ConfirmedInstalled` (from package manager DBs) or `HeuristicUnverified` (from binary string matching)
- **Streaming progress reporting:** NDJSON stage-based progress events emitted to stdout/file with calculated percentages for UI progress bars
- **Multi-layer caching:** File cache → PostgreSQL → Redis with cluster mode detection for shared enrichment across workers

## Layers

**CLI Entry Point:**
- Purpose: Parses arguments and routes to scan/utility subcommands
- Location: `src/main.rs`
- Contains: Clap command definitions, enum variants for all subcommands (Scan, Bin, Container, Source, Auth, Config, Db, Sbom, etc.)
- Depends on: `cli::*` modules for subcommand implementations
- Used by: User invocations of `scanrook` binary

**Scanning Layer:**
- Purpose: Auto-detect input type and execute appropriate scanning backend
- Location: `src/binary.rs`, `src/container/scan.rs`, `src/container/image.rs`, `src/iso.rs`, `src/archive.rs`
- Contains:
  - Binary scanning via ELF/PE/Mach-O parsing (goblin + memory-mapped I/O)
  - Container image extraction and OS package detection (tar/OCI/docker-save formats)
  - Source tarball scanning for app packages (npm, pip, Go, Cargo, Maven, etc.)
  - ISO extraction and filesystem scanning
  - SBOM import from CycloneDX/SPDX/Syft JSON formats
- Depends on: `vuln::*` for enrichment, `report::*` for data structures, `progress::*` for stage tracking
- Used by: Main CLI command handlers

**Package Inventory Layer:**
- Purpose: Detect installed packages from extracted filesystems and binaries
- Location: `src/container/detect.rs`, `src/container/apk.rs`, `src/container/dpkg.rs`, `src/container/rpm.rs`, `src/container/ecosystem.rs`
- Contains:
  - RPM database parsing (both Berkeley DB and SQLite formats) from `/var/lib/rpm/Packages`
  - APK installed database parsing from `/etc/apk/installed`
  - Debian/Ubuntu dpkg parsing with source package name extraction
  - NPM/pip/Go/Maven/Cargo/Composer/Ruby ecosystem detection
  - Go binary introspection for linked packages and build info
  - Syft SBOM generation via subprocess
- Depends on: `report::PackageCoordinate`, `utils::*` for hashing and progress
- Used by: Scanning layer to build `Vec<PackageCoordinate>` for enrichment

**Extraction & Archive Layer:**
- Purpose: Safely extract tar/tar.gz/tar.bz2/ISO files to temp directories
- Location: `src/container/extract.rs`, `src/iso.rs`, `src/archive.rs`
- Contains:
  - Tar extraction with Zip Slip protection (manual entry iteration, path validation)
  - Layer merging for docker-save (manifest.json) and OCI image layouts (index.json, blobs/)
  - ISO extraction via bsdtar with symlink escape detection
  - Automatic file type detection (tar vs tar.gz vs tar.bz2 vs ISO)
- Depends on: Standard library `tar`, `flate2`, `bzip2`, `zip` crates; `tempfile` for workdirs
- Used by: Scanning layer to prepare filesystem for inventory detection

**Vulnerability Enrichment Layer:**
- Purpose: Enrich packages with CVE/vulnerability data from multiple sources
- Location: `src/vuln/mod.rs` and submodules (`osv.rs`, `nvd.rs`, `epss.rs`, `kev.rs`, `pg.rs`, `redhat_enrich.rs`, `debian_legacy.rs`, `distro.rs`)
- Contains:
  - **OSV integration** (`osv.rs`): Batch query OSV API with `POST /query` endpoint, map results to findings
  - **NVD integration** (`nvd.rs`): Keyword search + CPE matching with version range evaluation via `cmp_versions()`
  - **EPSS scoring** (`epss.rs`): Batch query api.first.org for EPSS scores and percentiles
  - **KEV catalog** (`kev.rs`): Download CISA Known Exploited Vulnerabilities catalog as HashSet
  - **Red Hat OVAL** (`redhat_enrich.rs`): Parse XML, evaluate test constraints, filter installed CVEs by release
  - **Debian/Ubuntu** (`debian_legacy.rs`, `distro.rs`): Legacy vulnerability feeds with version range matching
  - **PostgreSQL caching** (`pg.rs`): Shared cache tables for multi-worker clusters
  - **Cluster mode detection** (`cluster_mode()`): Skip local file cache when `SCANROOK_CLUSTER_MODE=1`
- Depends on: `reqwest::blocking::Client` for HTTP, `serde_json` for API parsing, `postgres` for cache, `redis` for distributed cache
- Used by: Scanning layer to enrich findings with severity, CVSS, fixed versions, evidence

**Report Assembly Layer:**
- Purpose: Construct final JSON/text reports with summary statistics
- Location: `src/report.rs`
- Contains:
  - **Data structures:** `Report`, `Finding`, `Summary`, `PackageInfo`, `TargetInfo`, `CvssInfo`, `EvidenceItem`
  - **Summary computation:** Count by severity/confidence tier via `compute_summary()`
  - **Output formatting:** JSON serialization via serde, text rendering
  - **Confidence tier logic:** Mark findings as `ConfirmedInstalled` vs `HeuristicUnverified` based on evidence source
- Depends on: `serde` for JSON, `ConfidenceTier` and `EvidenceSource` enums
- Used by: All scanning backends to produce final output

**Cache Layer:**
- Purpose: Reduce API calls via multi-tier caching strategy
- Location: `src/cache.rs`, `src/vuln/pg.rs`
- Contains:
  - **File cache:** `~/.scanrook/cache/` with SHA256-keyed BLOB storage
  - **PostgreSQL cache:** Shared tables for cluster-wide enrichment (`nvd_cve_cache`, `osv_vuln_cache`, `redhat_cve_cache`, `epss_scores_cache`, `kev_entries_cache`)
  - **Redis cache:** Optional distributed cache for high-concurrency scenarios
  - **Vulndb SQLite:** Pre-built vulnerability database with OSV/NVD payloads
- Depends on: `cache_get()`/`cache_put()` for file I/O, `postgres` crate for DB, `redis` crate for distributed cache
- Used by: Enrichment layer before making API calls

**Utilities Layer:**
- Purpose: Cross-cutting concerns like progress reporting, hashing, and file operations
- Location: `src/utils.rs`, `src/progress.rs`, `src/license.rs`, `src/usercli.rs`
- Contains:
  - **Progress reporting:** Structured NDJSON events with stage tracking via `progress()` and `progress_pct()`
  - **File hashing:** SHA256 via streaming reader in `hash_file_stream()`
  - **Output writing:** JSON/text file writing with optional gzip compression
  - **License detection:** Pattern matching for 15 SPDX license headers
  - **CLI auth:** Device flow, API key storage, config persistence in `~/.scanrook/config/`
  - **Syft integration:** Subprocess wrapper for SBOM generation
- Depends on: `sha2`, `chrono`, `serde_json`, `regex`, `walkdir`
- Used by: All layers for common operations

**CLI Subcommand Layer:**
- Purpose: Implement user-facing commands beyond scan
- Location: `src/cli/db.rs`, `src/cli/benchmark.rs`, `src/cli/diff.rs`, `src/cli/helpers.rs`
- Contains:
  - **DB management:** Status, check connectivity, update cache, clear cache
  - **Benchmarking:** Compare against Trivy/Grype with warm/cold/no-cache profiles
  - **Report diffing:** Compare CVE IDs across scanner outputs
  - **Policy enforcement:** SBOM policy gates with YAML/JSON config
- Depends on: Scanning layer for core logic, report structures
- Used by: CLI entry point for non-scan operations

## Data Flow

**Container Scan Flow (primary path):**

1. User invokes: `scanrook scan --file image.tar --format json`
2. **Detection:** `main.rs` routes to `scan_container()` in `container/scan.rs`
3. **Extraction:** `extract_tar()` unpacks to temp directory, validates for Zip Slip
4. **Layer merging:** If OCI/docker-save detected, merge layers from blobs/ or manifest.json
5. **Fast inventory (optional):** Attempt `try_detect_os_packages_from_layout()` without full rootfs merge
6. **Full rootfs merge:** Merge all container layers to single filesystem
7. **Package detection:** Call `detect_os_packages()` which dispatches to rpm.rs/dpkg.rs/apk.rs based on `/etc` markers
8. **OSV batch query:** `osv_batch_query()` POSTs all packages to OSV API, caches results
9. **OSV enrichment:** `osv_enrich_findings()` maps results to structured findings with fixed versions
10. **NVD enrichment:** `enrich_findings_with_nvd()` adds CVSS scores via keyword/CPE matching
11. **Red Hat OVAL (if provided):** `apply_redhat_oval_enrichment()` filters for installed RPMs with fixed EVR
12. **EPSS scoring:** `epss_enrich_findings()` batch query api.first.org, cache 24h
13. **KEV catalog:** `kev_enrich_findings()` checks CISA catalog for known exploits
14. **Summary computation:** `compute_summary()` counts by severity/confidence
15. **Report assembly:** Build JSON Report struct with scanner/target/findings/summary
16. **Output:** Write to file or stdout

**Binary Scan Flow (alternative path):**

1. User invokes: `scanrook scan --file /usr/bin/curl`
2. **Detection:** Auto-detect via goblin magic bytes → `scan_binary_with_enrichment()`
3. **Binary parsing:** Extract linked libraries, Go build info, Rust panic strings via `goblin::Object`
4. **Memory-mapped I/O:** Sampled byte reading for large binaries (head + middle + tail chunks)
5. **String extraction:** Regex patterns for common dependency names (e.g., "openssl", "libcrypto")
6. **OSV query:** Query OSV for detected components (e.g., "openssl", version from strings)
7. **NVD fallback:** If OSV misses, try CPE matching strategies (priority: `nvd_findings_by_product_version()` → `nvd_cpe_findings()` → `nvd_keyword_findings()`)
8. **Confidence tier:** Mark as `HeuristicUnverified` (binary string match, not package manager)
9. **EPSS/KEV enrichment:** Same as container flow
10. **Report assembly:** Generate findings with evidence from binary analysis

**State Management:**

- **Findings lifecycle:** Created in enrichment layer, immutable in report (serde-serialized as-is)
- **Progress state:** Managed via `PIPELINE` OnceLock mutex in `progress.rs`, cumulative percentage calculation
- **Cache state:**
  - File: SHA256-keyed entries in `~/.scanrook/cache/`, disabled by `SCANNER_SKIP_CACHE=1`
  - PG: Check cache before API in cluster mode, update on miss
  - Redis: Optional TTL-based distributed cache
- **Session state:** Cached HTTP client via `OnceLock` statics in `vuln/http.rs`, reused across API calls

## Key Abstractions

**PackageCoordinate:**
- Purpose: Unique identifier for a package across all ecosystems
- Definition: `{ ecosystem, name, version, source_name? }`
- Examples: `{ "npm", "lodash", "4.17.21" }`, `{ "Debian", "openssl", "1.1.1k-1", source: "openssl" }`
- Pattern: Used throughout: container detect → OSV query → enrichment → report findings

**Finding:**
- Purpose: Represents a single vulnerability discovered in the target
- Definition: Struct with id, package, severity, cvss, evidence, references, confidence_tier, evidence_source
- Examples: `{ id: "CVE-2021-1234", package: { name: "openssl", ecosystem: "RPM", version: "1.1.1" }, severity: "HIGH", fixed_in: "1.1.1k" }`
- Pattern: Created during enrichment, finalized at report stage, serialized to JSON

**Report:**
- Purpose: Top-level container for all scan results
- Definition: Struct with scanner info, target info, findings vec, summary, optional SBOM
- Pattern: Returned from all scan functions, written to file or stdout as JSON

**PipelineStage:**
- Purpose: Defines ordered scan phases with weight percentages for progress tracking
- Definition: `{ id, label, weight }` where weights sum to 100
- Examples: Container pipeline has 10 stages (extract 10%, inventory 10%, OSV 10%, etc.)
- Pattern: Initialized per scan type, progress events reference stage_id to calculate cumulative %

**ConfidenceTier (Enum):**
- Purpose: Indicates whether finding comes from authoritative source or heuristic match
- Values: `ConfirmedInstalled` (from package manager DB), `HeuristicUnverified` (from binary strings)
- Pattern: Used to segregate findings in summary (critical_confirmed vs critical_heuristic)

**EvidenceSource (Enum):**
- Purpose: Tracks which part of scan pipeline discovered the package
- Values: `InstalledDb` (pkg manager), `RepoMetadata`, `FilenameHeuristic`, `BinaryHeuristic`
- Pattern: Guides what accuracy note to display in findings

## Entry Points

**Main Binary Entry (`scanrook`):**
- Location: `src/main.rs`
- Triggers: User CLI invocation with subcommand (Scan, Bin, Container, Source, Auth, Db, Sbom, etc.)
- Responsibilities:
  - Parse args via Clap
  - Initialize cache directory and permissions (0o700 on unix)
  - Route to appropriate command handler
  - Handle TTY detection for progress formatting
  - Call `init_pipeline()` for progress tracking

**Scan Subcommand Handler:**
- Location: `src/cli/detect.rs::build_scan_report_value()`
- Triggers: `scanrook scan --file ...`
- Responsibilities:
  - Detect input file type (container tar, binary, source tar, ISO) via magic bytes
  - Call appropriate scanning backend
  - Manage NDJSON progress file if `--progress-file` given
  - Write output JSON or text to file/stdout
  - Handle errors and emit progress events

**Container Scan Handler:**
- Location: `src/container/scan.rs::scan_container()`
- Triggers: Detected or explicit `--file image.tar` or `scanrook container --tar image.tar`
- Responsibilities:
  - Create temp directory
  - Call `extract_tar()` for safe unpacking
  - Attempt fast inventory detection
  - Merge container layers if multi-layer format
  - Call `detect_os_packages()` for inventory
  - Call enrichment pipeline (OSV → NVD → EPSS → KEV)
  - Assemble and return Report

**Binary Scan Handler:**
- Location: `src/binary.rs::scan_binary_with_enrichment()`
- Triggers: Detected or explicit `scanrook bin --path /usr/bin/curl`
- Responsibilities:
  - Memory-map file for efficient reading
  - Extract components via string matching and goblin ELF/PE parsing
  - Query OSV then NVD for each component
  - Mark findings as `HeuristicUnverified`
  - Return Report

**Enrichment Entry Point:**
- Location: `src/vuln/mod.rs::osv_batch_query()` (primary)
- Triggers: Called from all scanning backends with package list
- Responsibilities:
  - Build OSV batch request JSON
  - Check file/PG/Redis cache before API call
  - POST to OSV API with retry logic
  - Parse response and map to findings
  - Cache results

## Error Handling

**Strategy:** Graceful degradation with partial results and status indicators.

**Patterns:**
- **Inventory detection:** Mark as `InventoryStatus::Missing` if package manager DBs not found, emit `PartialFailed` scan status
- **API failures:** Cached results returned if available, otherwise skip that enrichment stage (findings still reported with partial data)
- **Extraction failures:** Return error immediately, cleanup temp dir, emit error progress event
- **File access:** Report specific path errors, continue scan if able (e.g., skip directories with permission denied)
- **YARA compilation:** Log warning if rules file invalid, continue without YARA
- **Symlink escapes:** Reject tar entries with `..` in path, emit security warning

## Cross-Cutting Concerns

**Logging:**
- Framework: Structured NDJSON events via `progress(stage, detail)` and `progress_pct(stage, detail, pct)`
- Output destinations: stderr (if TTY or `--progress`), file (if `--progress-file`), both
- Formats: text (trivy-style brackets with timestamps) or JSON
- Levels: error, warn, info, debug (filtered by `--log-level`)

**Validation:**
- **Path traversal:** Tar entries checked for `..` and absolute paths in `extract_tar()`, ISO entries validated in `iso.rs`
- **File permissions:** Cache dir set to 0o700 (owner-only) on Unix in `cache.rs::set_dir_permissions()`
- **API responses:** JSON parsing via serde with strict enum variants, missing fields default to None

**Authentication:**
- **API keys:** Stored in `~/.scanrook/config/` with readable defaults (NOT encrypted)
- **Device flow:** `usercli.rs` implements OAuth-style token exchange
- **Rate limiting:** NVD sleeps 400ms with key, 6s without (override via `SCANNER_NVD_SLEEP_MS`)

**Performance Optimization:**
- **Caching layers:** File → PG → Redis → API (each miss checks next tier)
- **Batch APIs:** OSV supports batch queries (up to 1000 packages per request)
- **Parallelization:** `rayon` used for per-package CVE list loading and file cache reads in RHEL enrichment
- **Memory mapping:** Binary scanning uses `memmap2` for large file access without full load
- **Streaming:** Tar extraction via streaming reader, not full decompress in memory

---

*Architecture analysis: 2026-03-02*
