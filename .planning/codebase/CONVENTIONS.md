# Coding Conventions

**Analysis Date:** 2026-03-02

## Naming Patterns

**Files:**
- Module files use snake_case: `container.rs`, `cache.rs`, `vuln/mod.rs`, `vuln/tests.rs`
- Submodules organized in directories with `mod.rs` acting as barrel file: `src/container/`, `src/vuln/`, `src/cli/`
- Test modules named `tests.rs` placed at `src/module/tests.rs` (e.g., `src/vuln/tests.rs`)

**Functions:**
- Use snake_case for all public and private functions: `extract_tar()`, `osv_batch_query()`, `parse_dpkg_status()`
- Prefix utility functions with module context: `env_bool()`, `cache_disabled()`, `level_rank()`
- Builder functions use explicit verbs: `build_container_report()`, `build_archive_report()`
- Parser functions prefix with `parse_`: `parse_rpm_sqlite()`, `parse_redhat_release_package()`, `parse_dpkg_status()`
- Detector functions prefix with `detect_`: `detect_rpm_packages_native()`, `detect_licenses_in_text()`, `detect_el_tag()`
- Enrichment functions prefix with `*_enrich_`: `osv_enrich_findings()`, `epss_enrich_findings()`, `kev_enrich_findings()`

**Variables:**
- Use snake_case throughout: `cache_dir`, `nvd_api_key`, `pkg_name`, `installed_ok`
- Single letter variables acceptable in loop scope: `f` for Finding iteration, `s` for String, `n` for name
- Prefix booleans with `is_`, `has_`, `should_`: `is_confirmed`, `has_findings`, `should_skip`
- Private module-level variables in SCREAMING_SNAKE_CASE when constant: `RPM_TAG_NAME`, `MAX_ZIP_ENTRY_SIZE`, `LICENSE_PATTERNS`

**Types:**
- Use PascalCase for struct, enum, and trait names: `PackageCoordinate`, `ConfidenceTier`, `ScanStatus`, `Finding`
- Enums with explicit serde rename: `#[serde(rename_all = "snake_case")]` applied to all public enums
- Newtype wrappers not used; struct fields are public where needed
- Type abbreviations kept minimal; use full names in structs

## Code Style

**Formatting:**
- `cargo fmt --all` enforces Rust standard formatting
- 4-space indentation (Rust default)
- Line length: no hard limit enforced, but typical lines under 100 characters
- Imports organized in three groups: `use std::`, `use crate::`, `use external_crate::`
- Each import group separated by blank line

**Linting:**
- `cargo test --locked --no-fail-fast` used in CI as test runner
- No explicit clippy configuration found; uses Rust defaults
- Dependency versions locked via `Cargo.lock`; CI uses `cargo build --locked` and `cargo test --locked`

**Platform-specific code:**
- Conditional compilation via `#[cfg(unix)]` and `#[cfg(not(unix))]` for OS-specific operations
  - Example: `set_dir_permissions()` in `cache.rs` (lines 55-62) sets 0o700 on Unix only
- Optional features via `#[cfg(feature = "yara")]` for YARA rule integration

## Import Organization

**Order:**
1. `use std::...` (standard library)
2. Blank line
3. `use crate::...` (internal modules)
4. Blank line
5. `use external_crate::{...}` (external dependencies)

**Examples from codebase:**
- `archive.rs` (lines 1-22): std imports → crate::report, crate::utils, crate::vuln → external (tempfile, walkdir)
- `container/dpkg.rs` (lines 1-3): std → crate
- `cache.rs` (lines 1-4): sha2, std imports only

**Path Aliases:**
- No path aliases (`use ... as ...`) found
- Module re-exports done via `pub use` in barrel files: `src/container/mod.rs` re-exports `extract_tar`, `build_container_report`
- `src/vuln/mod.rs` extensively uses `pub use` for submodule exports (lines 14-26)

**Visibility:**
- Functions prefixed with `pub` if part of public API; private otherwise
- `pub(super)` used sparingly in submodules (e.g., `pub(super) fn detect_rpm_packages_native()` in `container/rpm.rs`)
- Structs and enums are typically `pub` if used across modules

## Error Handling

**Patterns:**
- `anyhow::Result<T>` used as return type for fallible functions
  - Example: `pub(super) fn detect_rpm_packages_native(rootfs: &Path) -> anyhow::Result<Vec<...>>` in `container/rpm.rs` (line 20)
- `Option<T>` used for optional/nullable values rather than unwrap
  - Example: `pub fn build_archive_report(...) -> Option<Report>` in `archive.rs` (line 64)
- Errors logged via `progress()` utility, not panicked
  - Example: `progress("archive.extract.error", &format!("{}", e))` in `archive.rs` (line 74)
- Fallback strategies used extensively (e.g., SQLite → BerkeleyDB → rpm CLI in `container/rpm.rs` lines 28-98)
- Silent failures acceptable when errors are logged: `match fs::File::open(&path) { Ok(mut f) => {...}, Err(_) => None }`

**No explicit error types defined** — using `anyhow` for ergonomics. No custom `Error` enum.

## Logging

**Framework:** None — uses `crate::utils::progress()` helper

**Patterns:**
- All progress events emit via `progress(stage: &str, detail: &str)` function
- Stage is hierarchical dot-notation: `"container.rpm.native.sqlite"`, `"archive.extract.start"`
- Detail contains context: file paths, package counts, or error messages
- Log level inferred from stage suffix: `.error`, `.warn`, `.timing` map to error/warn/debug
- Timestamp added by `progress()` function, not by caller
- Output format (text/json) and level (error/warn/info/debug) controlled via CLI flags `--log-format` and `--log-level`
- Optional file output via `--progress-file` flag; NDJSON format for machine parsing

**Example calls:**
```rust
progress("container.rpm.native.sqlite", &sqlite_path.to_string_lossy());
progress("archive.extract.done", path);
progress_timing("archive.extract", started);  // computes elapsed time
```

## Comments

**When to Comment:**
- Module-level doc comments using `//!` explain purpose and high-level design
- Comments precede complex algorithms or non-obvious logic
- Comments explain *why*, not *what* (code should be clear enough to show what)
- Examples:
  - `container/rpm.rs` (line 1-2): `//! RPM package detection: SQLite, BerkeleyDB, and CLI fallback.`
  - `container/dpkg.rs` (lines 31-33): Explains OSV's Debian ecosystem indexing strategy
  - `archive.rs` (line 24): Documents zip bomb guard constant

**JSDoc/Rust Doc:**
- Doc comments (`///`) used for public functions and public types
- Examples:
  - `cache.rs` (line 54): `/// Set directory permissions to 0o700 (owner-only) on unix systems.`
  - `license.rs` (line 123): `/// Detect license from a single file and print human-readable output`
  - `license.rs` (line 147): `/// Scan a directory tree for license files and return structured detections`
- Tests and internal functions typically have no doc comments
- `pub use` statements in barrel files don't include doc comments

## Function Design

**Size:**
- Functions typically 10–100 lines; no hard limit enforced
- Large functions (> 200 lines) used for complex enrichment pipelines (e.g., `osv_enrich_findings()` in `vuln/osv.rs`)
- Fallback chains (SQLite → BerkeleyDB → CLI) kept in single function for clarity

**Parameters:**
- Prefix mutable references with `&mut`: `parse_dpkg_status(contents: &str, out: &mut Vec<PackageCoordinate>)`
- Accept `&Path` for filesystem operations, not `&str` paths
- Accept `Option<T>` rather than `None` as default argument
- Use owned types for short-lived data; borrow long-lived data

**Return Values:**
- Return `Option<T>` for optional results: `cache_get() -> Option<Vec<u8>>`
- Return `anyhow::Result<T>` for fallible operations with errors
- Return `Vec<T>` for collections; no need for references
- Tuple returns used for simple pairs: `(name, version, source_name)` in RPM parsing

## Module Design

**Exports:**
- Barrel file pattern: `src/container/mod.rs` defines private module declarations, then re-exports public items
  ```rust
  mod rpm;
  mod dpkg;
  pub use rpm::parse_rpm_bdb;
  ```
- Re-exports use `pub use`, not manual forwarding
- Sibling modules access private items via `use super::*` in tests or via explicit public API

**Barrel Files:**
- Located at `src/{module}/mod.rs` (e.g., `src/vuln/mod.rs`)
- List all submodules with `mod name;` declarations
- Re-export public items with `pub use` for public API
- Example: `src/vuln/mod.rs` (lines 1-56) declares 12 submodules, re-exports 8 public functions
- Enable `#[cfg(test)] mod tests;` at barrel file end for test modules

**Internal Organization:**
- Private helper functions placed in same file or same module
- Minimal file sizes enforced: each ecosystem detector (RPM, APK, dpkg) gets own file
- Vulnerability enrichment pipeline split across multiple files: `osv.rs`, `nvd.rs`, `epss.rs`, `kev.rs`, `redhat_enrich.rs`

---

*Convention analysis: 2026-03-02*
