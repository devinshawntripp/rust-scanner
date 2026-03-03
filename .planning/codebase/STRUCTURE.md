# Codebase Structure

**Analysis Date:** 2026-03-02

## Directory Layout

```
rust_scanner/
├── src/                    # All Rust source code
│   ├── main.rs            # CLI entry point, Clap command definitions, subcommand routing
│   ├── report.rs          # Finding, Report, Summary, PackageInfo data structures
│   ├── binary.rs          # Binary (ELF/PE/Mach-O) scanning via goblin
│   ├── archive.rs         # Generic archive detection and dispatch
│   ├── iso.rs             # ISO image extraction and scanning
│   ├── license.rs         # SPDX license detection patterns
│   ├── progress.rs        # Pipeline stage definitions and progress tracking
│   ├── cache.rs           # File-based cache with SHA256 keys
│   ├── utils.rs           # Progress reporting, file hashing, SBOM generation
│   ├── usercli.rs         # CLI auth, API key storage, config persistence
│   ├── redhat.rs          # Red Hat OVAL parsing and application
│   ├── sbom.rs            # SBOM import from CycloneDX/SPDX/Syft JSON
│   ├── cli/               # Subcommand handlers and utilities
│   │   ├── mod.rs         # Module exports
│   │   ├── detect.rs      # Auto-detect file type and dispatch to scanner
│   │   ├── db.rs          # Database management (status, check, update, clear)
│   │   ├── benchmark.rs   # Benchmark ScanRook vs Trivy/Grype
│   │   ├── diff.rs        # Diff CVE IDs across scanner outputs
│   │   └── helpers.rs     # Shared CLI utilities (cache resolution, yara rules)
│   ├── container/         # Container image scanning and package detection
│   │   ├── mod.rs         # Module exports and PackageCoordinate struct
│   │   ├── scan.rs        # Orchestration of container scan pipeline
│   │   ├── extract.rs     # Tar extraction with Zip Slip protection, layer merging
│   │   ├── detect.rs      # Package manager detection (rpm/apk/dpkg, Go binaries)
│   │   ├── rpm.rs         # RPM database parsing (Berkeley DB and SQLite)
│   │   ├── apk.rs         # APK installed database parsing
│   │   ├── dpkg.rs        # Debian/Ubuntu dpkg package detection
│   │   ├── ecosystem.rs   # App package detection (npm, pip, Go, Maven, Cargo, etc.)
│   │   ├── image.rs       # Docker/OCI image pulling and saving
│   │   └── [OLD] build_report.rs  # (Deprecated, logic moved to scan.rs)
│   └── vuln/              # Vulnerability enrichment pipeline
│       ├── mod.rs         # Main module, re-exports all enrichment functions
│       ├── osv.rs         # OSV API integration with batch query
│       ├── nvd.rs         # NVD API integration (keyword + CPE matching)
│       ├── epss.rs        # EPSS scoring from api.first.org
│       ├── kev.rs         # CISA KEV catalog enrichment
│       ├── redhat_enrich.rs  # Red Hat unfixed CVE injection
│       ├── debian_legacy.rs  # Debian security feed (legacy)
│       ├── distro.rs      # Distro-specific feeds (Alpine, Ubuntu, Debian)
│       ├── pg.rs          # PostgreSQL cache tables and connection
│       ├── http.rs        # HTTP client utilities and rate limiting
│       ├── cvss.rs        # CVSS score parsing and computation
│       ├── version.rs     # Version range comparison utilities
│       └── tests.rs       # Integration tests for enrichment
├── vulndb.rs              # SQLite vulnerability database (pre-built)
├── Cargo.toml             # Package manifest with dependencies
├── Cargo.lock             # Locked dependency versions
├── Makefile               # Build automation (build, install, fmt, test, scan)
├── Dockerfile             # Multi-stage Docker image for distribution
├── .github/               # GitHub Actions CI/CD configuration
│   └── workflows/         # CI workflows (build, test, release)
├── .planning/             # GSD planning documents (generated)
│   └── codebase/          # ARCHITECTURE.md, STRUCTURE.md, etc.
├── docs/                  # User documentation
│   ├── benchmarks/        # Benchmark results and comparison data
│   ├── guides/            # Usage guides and examples
│   └── marketing/         # Product materials
├── rules/                 # YARA rules for deep scanning
│   └── default.yar        # Default rule set (bundled with binary)
├── scripts/               # Build and deployment helpers
├── benchmark-out/         # Generated benchmark comparison results
├── dist/                  # Pre-built release artifacts
└── target/                # Build output directory (gitignored)
```

## Directory Purposes

**src/:**
- Purpose: All Rust source code organized by concern
- Contains: Main entry point, data structures, scanning backends, enrichment pipeline, CLI subcommands
- Key files: `main.rs` (CLI routing), `report.rs` (data structures), `container/scan.rs` (orchestration)

**src/cli/:**
- Purpose: Subcommand implementations and CLI utilities
- Contains: Auto-detect logic, DB management, benchmarking, diff reporting, helpers
- Key files: `detect.rs` (file type detection), `db.rs` (cache management), `helpers.rs` (shared utils)

**src/container/:**
- Purpose: Container image scanning and package inventory detection
- Contains: Tar extraction, OS package manager parsers, OCI/docker-save layer merging, syft integration
- Key files: `scan.rs` (orchestration), `extract.rs` (safe unpacking), `detect.rs` (package detection), `rpm.rs`/`dpkg.rs`/`apk.rs` (ecosystem-specific)

**src/vuln/:**
- Purpose: Vulnerability enrichment from multiple sources
- Contains: OSV/NVD API integration, EPSS scoring, KEV catalog, Red Hat OVAL, caching (PG/Redis)
- Key files: `mod.rs` (re-exports), `osv.rs` (primary enrichment), `nvd.rs` (fallback/CPE), `pg.rs` (cluster cache)

**Cargo.toml:**
- Purpose: Package manifest and dependency specification
- Contains: Package name, version, edition, dependency versions, feature flags
- Key config: `yara` feature is optional (requires system libyara)

**Makefile:**
- Purpose: Build automation and common commands
- Contains: Cargo wrapper commands, install target, test/fmt runners
- Commands: `make build`, `make install`, `make test`, `make fmt`, `make scan`

**Dockerfile:**
- Purpose: Multi-stage container image for distribution
- Contains: Rust builder stage, slim runtime stage, binary copy
- Output: Single-layer image with `scanrook` binary and minimal dependencies

**.github/workflows/:**
- Purpose: GitHub Actions CI/CD automation
- Contains: Lint, build, test, and release workflows
- Key: Uses `cargo build --locked` (requires Cargo.lock to be up-to-date)

**docs/:**
- Purpose: User-facing documentation
- Contains: Benchmark comparisons, usage guides, product materials
- Generated from: Benchmark runs and command examples

**rules/:**
- Purpose: YARA pattern definitions for deep scanning
- Contains: Default rules bundled into binary via `include_str!()`
- Usage: Optional deep scan with `--mode deep --yara /path/to/rules.yar`

## Key File Locations

**Entry Points:**
- `src/main.rs`: Binary entry point with Clap CLI definition, subcommand enum, global flags
- `src/cli/detect.rs::build_scan_report_value()`: Auto-detect and route to appropriate scanner
- `src/container/scan.rs::scan_container()`: Container scan orchestration
- `src/binary.rs::scan_binary_with_enrichment()`: Binary scan entry point

**Configuration:**
- `Cargo.toml`: Package metadata, dependency versions, feature flags
- `CLAUDE.md` (in repo root): Project-specific Claude Code guidance
- `.env` (gitignored): Local development environment variables (not secrets)

**Core Logic:**
- `src/report.rs`: Finding, Report, Summary, PackageInfo, TargetInfo structs
- `src/container/mod.rs::PackageCoordinate`: Universal package identifier
- `src/vuln/mod.rs`: Enrichment pipeline orchestration and function re-exports
- `src/progress.rs`: Pipeline stage definitions and progress tracking (OnceLock state)

**Testing:**
- `src/vuln/tests.rs`: Integration tests for enrichment pipeline (46 tests total)
- Test strategy: Unit tests for parsing, integration tests for full pipelines
- Run: `cargo test --locked --no-fail-fast`

**Utilities:**
- `src/utils.rs`: Progress reporting, file hashing (streaming SHA256), SBOM generation, output writing
- `src/cache.rs`: File-based cache with SHA256-keyed entries, disabled by `SCANNER_SKIP_CACHE=1`
- `src/progress.rs`: Pipeline stage tracking with cumulative percentage calculation

## Naming Conventions

**Files:**
- Modules named after their primary responsibility: `container.rs` for container logic, `binary.rs` for binary scanning, `vuln.rs` (submodule) for enrichment
- Test files: Inline `#[test]` in modules or separate `tests.rs` for integration tests (e.g., `src/vuln/tests.rs`)
- CLI modules: `db.rs`, `benchmark.rs`, `diff.rs` matching subcommand names

**Directories:**
- Domain-specific grouping: `container/`, `vuln/` separate concerns
- Avoid generic names; each directory has a clear purpose
- Single-letter abbreviations avoided (except `src/` per Rust convention)

**Functions:**
- Action verbs for entry points: `scan_container()`, `scan_binary()`, `extract_tar()`, `enrich_findings_with_nvd()`
- Predicates end with `_*`: `heuristic_fallback_allowed()`, `env_bool()`, `deep_require_installed_inventory()`
- Internal helpers prefixed with `_` or suffixed with `_impl`: `_parse()`, `_internal()`
- Batch operations explicit: `osv_batch_query()`, `nvd_findings_by_product_version()` (plural or explicit batch semantics)

**Variables:**
- `packages` for `Vec<PackageCoordinate>`
- `findings` for `Vec<Finding>`
- `cache_dir` for `Option<&Path>` (respects `resolve_cache_dir()` helper)
- `report` for final `Report` struct
- Prefix temp/intermediate: `tmp`, `temp_`, `staging_` for temporary directories and variables

**Types:**
- Enums for discriminated unions: `ConfidenceTier`, `EvidenceSource`, `ScanMode`, `OutputFormat`
- Structs for data: `PackageCoordinate`, `Finding`, `Report`, `PipelineStage`
- Trait objects avoided in favor of concrete types or generics

## Where to Add New Code

**New Scanning Backend (e.g., scanning a new archive format):**
- Primary code: Create new file `src/new_format.rs` implementing `scan_new_format(path: &str) -> Report`
- Integrate: Add module to `src/main.rs` as `mod new_format;`
- CLI routing: Add variant to `Commands` enum in `main.rs`, handle in `cli/detect.rs::build_scan_report_value()`
- Tests: Add integration test to `src/new_format.rs` or new test module
- Example: ISO scanning is in `src/iso.rs`, integrated with auto-detection in CLI layer

**New Package Manager Ecosystem (e.g., new language's package format):**
- Detection logic: Add parser to `src/container/ecosystem.rs` (single file for all app package managers)
- Or separate file: If complex, create `src/container/newlang.rs` with parser, re-export in `src/container/mod.rs`
- Integration: Call from `detect_os_packages()` in `src/container/detect.rs`
- Ecosystem mapping: Update `get_osv_ecosystem()` in `src/container/ecosystem.rs` to map package manager name → OSV ecosystem name
- Tests: Add test cases to same file or `src/vuln/tests.rs` for enrichment

**New Enrichment Source (e.g., new vulnerability database):**
- Implementation: Create `src/vuln/newsource.rs` with functions like `newsource_enrich_findings(findings: &[Finding]) -> Result<Vec<Finding>>`
- Re-export: Add public function to `src/vuln/mod.rs` exports
- Integration points: Call from appropriate scan backend (e.g., `src/container/scan.rs` after NVD enrichment)
- Caching: Add PostgreSQL table in `src/vuln/pg.rs::pg_init_schema()`, check cache in `newsource_enrich_findings()`
- Tests: Add integration test to `src/vuln/tests.rs`
- Example: EPSS is in `src/vuln/epss.rs`, integrated at line ~250 of `src/container/scan.rs`

**New CLI Subcommand:**
- Command enum: Add variant to `Commands` enum in `src/main.rs`
- Handler: Create `src/cli/newcmd.rs` implementing command logic, export function in `src/cli/mod.rs`
- Integration: Match command variant in `main.rs::main()` function, call handler
- Tests: Add integration tests or document behavior
- Example: `Benchmark` command is in `src/cli/benchmark.rs`, matched in main.rs line ~600

**Utilities (helpers used across modules):**
- Shared helpers: `src/utils.rs` (progress, hashing, file I/O, syft integration)
- Cache utilities: `src/cache.rs` (file cache key/get/put)
- Progress utilities: `src/progress.rs` (stage definitions, tracking)
- Container-specific helpers: `src/container/mod.rs` exports or per-file utilities
- Do NOT create new utils file; extend existing files

## Special Directories

**target/:**
- Purpose: Cargo build output directory
- Generated: Yes
- Committed: No (in .gitignore)
- Contents: Compiled binaries, intermediate artifacts, build scripts

**.planning/codebase/:**
- Purpose: GSD-generated codebase analysis documents
- Generated: Yes (by `/gsd:map-codebase` orchestrator)
- Committed: Yes
- Contents: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, STACK.md, INTEGRATIONS.md, CONCERNS.md

**benchmark-out/:**
- Purpose: Generated benchmark comparison results
- Generated: Yes (by `make bench` or `scanrook benchmark`)
- Committed: Yes (for historical comparison)
- Contents: summary.csv, tool JSON outputs, timing data

**rules/:**
- Purpose: YARA rule files for deep scanning
- Generated: No
- Committed: Yes
- Contents: default.yar (bundled into binary via include_str!())

**docs/:**
- Purpose: User documentation and guides
- Generated: Partially (benchmarks generated, guides hand-written)
- Committed: Yes
- Contents: README excerpts, guides, benchmark results, examples

**dist/:**
- Purpose: Pre-built release artifacts
- Generated: Yes (from CI/CD)
- Committed: Yes (historical releases)
- Contents: Archived binary releases for different platforms

---

*Structure analysis: 2026-03-02*
