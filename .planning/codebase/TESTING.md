# Testing Patterns

**Analysis Date:** 2026-03-02

## Test Framework

**Runner:**
- `cargo test --locked --no-fail-fast` (used in CI at `.github/workflows/ci.yml` line 22)
- Built-in Rust test harness; no external test runner (no pytest, Jest, etc.)
- Tests run serially by default; parallelism controlled by test runner flags

**Assertion Library:**
- Standard Rust macros: `assert_eq!()`, `assert!()`, `expect()`
- No external assertion library (no spec, should_panic patterns)

**Run Commands:**
```bash
cargo test --locked --no-fail-fast    # Run all tests (CI command)
cargo test --lib                      # Run library tests only
cargo test module::tests::             # Run tests in specific module
cargo test test_name -- --nocapture   # Run single test with output
```

## Test File Organization

**Location:**
- Tests co-located with source code in same module/file
- Dedicated test module `#[cfg(test)] mod tests { ... }` placed at end of each file
- Centralized test file: `src/vuln/tests.rs` (227 lines) contains all vuln module tests

**Naming:**
- Test functions prefixed with `test_`: `test_parse_dpkg_status_basic()`
- Test function names describe what is tested: `test_parse_dpkg_status_basic()`, `best_redhat_fixed_release_prefers_matching_el_stream()`
- No `#[test]` attribute naming convention; names reflect the test purpose

**Structure:**
```
src/
├── module.rs               # Source code + #[cfg(test)] mod tests { ... }
├── module/
│   ├── mod.rs
│   ├── submodule.rs        # Source + optional inline tests
│   └── tests.rs            # (For large test suites)
```

**Examples:**
- `src/container/dpkg.rs` (lines 98-111): Inline test module `#[cfg(test)] mod tests`
- `src/container/rpm.rs`: Tests mixed inline with source
- `src/license.rs` (lines 266+): Inline tests
- `src/vuln/tests.rs`: Dedicated test file imported as `#[cfg(test)] mod tests;` in `src/vuln/mod.rs` (line 56)

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;              // Bring source items into scope
    use crate::report::{...};  // Import necessary types

    #[test]
    fn test_name() {
        // Arrange
        let input = create_test_data();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected_value);
    }
}
```

**Patterns:**
- Tests follow Arrange-Act-Assert pattern implicitly (no explicit comments)
- Setup via helper functions: `mk_finding()` in `src/vuln/tests.rs` (lines 104-129) creates reusable Finding fixtures
- No teardown needed (Rust handles stack cleanup automatically)
- No setup fixtures (each test creates needed data inline)
- Assertion pattern: `assert_eq!()` for equality, `assert!()` for boolean checks, `.is_ok()` / `.is_none()` for Result/Option

**Example from `src/vuln/tests.rs` (lines 5-11):**
```rust
#[test]
fn parse_redhat_release_package_handles_name_with_dash() {
    let parsed = parse_redhat_release_package("kernel-rt-4.18.0-193.6.3.rt13.70.el8_2");
    let (name, evr) = parsed.expect("package should parse");
    assert_eq!(name, "kernel-rt");
    assert_eq!(evr, "4.18.0-193.6.3.rt13.70.el8_2");
}
```

## Mocking

**Framework:** None — uses actual data and real parsing

**Patterns:**
- No mocking library used; tests use real data structures
- Test fixtures created inline via builder patterns or helper functions
  - Example: `mk_finding()` in `src/vuln/tests.rs` (lines 104-129) builds a Finding with specified fields
  - Example: Vector literals for test data: `vec![PackageCoordinate { ... }, ...]`
- JSON test data created inline: `serde_json::json!({...})` in `src/vuln/tests.rs` (line 172)

**What to Mock:**
- Nothing is explicitly mocked; all external dependencies avoided in unit tests
- HTTP requests: Not tested at unit level (would require mocking `reqwest` client)
- Database queries: Not tested at unit level
- File I/O: Tests use `tempfile::tempdir()` for isolation, not mocks

**What NOT to Mock:**
- Parsing logic: Always tested against real input data
- Version comparison: Always tested with real semantic version strings
- Enum matching: Always tested with actual enum variants, not synthetic representations

**Example of real data approach from `src/vuln/tests.rs` (lines 171-192):**
```rust
#[test]
fn build_ubuntu_candidate_index_maps_notice_to_pkg_cve_key() {
    let data = serde_json::json!({
        "notices": [
            {
                "id": "USN-1000-1",
                "cves_ids": ["CVE-2024-12345"],
                "release_packages": {
                    "jammy": [
                        {"name":"bash","version":"5.1-2ubuntu3.4"}
                    ]
                }
            }
        ]
    });
    let mut needed = std::collections::HashSet::new();
    needed.insert(pkg_cve_key("bash", "CVE-2024-12345"));
    let idx = build_ubuntu_candidate_index(&data, &needed);
    let key = pkg_cve_key("bash", "CVE-2024-12345");
    let rows = idx.get(&key).expect("ubuntu candidate present");
    assert_eq!(rows[0].fixed_version, "5.1-2ubuntu3.4");
    assert_eq!(rows[0].source_id, "USN-1000-1");
}
```

## Fixtures and Factories

**Test Data:**
- Helper function pattern: `mk_finding()` in `src/vuln/tests.rs` (lines 104-129) constructs Finding with defaults
  ```rust
  fn mk_finding(id: &str, pkg_name: &str, fixed: Option<bool>) -> Finding {
      Finding {
          id: id.to_string(),
          package: Some(PackageInfo {
              name: pkg_name.to_string(),
              ecosystem: "redhat".to_string(),
              version: "1:1.2.3-1.el8".to_string(),
          }),
          // ... remaining fields with hardcoded defaults
      }
  }
  ```
- JSON literals via `serde_json::json!({...})`
- Struct literals with `{field: value, ...}` syntax for complex types
- Vector literals for collections: `vec![item1, item2, ...]`

**Location:**
- Fixtures defined inline within test modules, not in separate `fixtures` directory
- Helper functions (like `mk_finding()`) placed before tests that use them
- No separate fixture files; all test data embedded in source

**No dedicated factory pattern** — builders used inline when needed.

## Coverage

**Requirements:** Not enforced
- No coverage percentage specified in `Cargo.toml` or CI
- Tests present but coverage gaps exist (some modules have no tests)

**View Coverage:**
```bash
# Coverage not auto-generated; would require tarpaulin or llvm-cov
cargo tarpaulin --out Html  # If tarpaulin installed
```

## Test Types

**Unit Tests:**
- Scope: Single function or small helper
- Approach: Direct function calls with hardcoded test data
- Examples:
  - `src/vuln/tests.rs`: Parsing, version comparison, enum matching (12 tests)
  - `src/container/dpkg.rs`: dpkg status file parsing (1 test)
  - `src/license.rs`: License pattern detection (2 tests)
  - `src/container/rpm.rs`: RPM header parsing, SOURCERPM extraction (3 tests)
  - `src/iso.rs`: ISO filesystem parsing (1 test)
  - `src/archive.rs`: No tests (tested indirectly via container/sbom)
  - `src/redhat.rs`: Red Hat OVAL and enrichment (2 tests)
  - `src/sbom.rs`: SBOM import and policy checks (2 tests)

**Integration Tests:**
- No integration tests in traditional sense
- Full pipeline tests would require real files, network access, databases
- Some tests approach integration (e.g., `detect_debian_release_from_package_versions` in `src/vuln/tests.rs` line 194) by parsing multiple packages

**E2E Tests:**
- Not present in codebase
- Manual testing: `make scan FILE=/path/to/artifact FORMAT=json MODE=light`
- Real-world testing done via Kubernetes deployment in `deltaguard` namespace

**Test Count:**
- 46 total tests across codebase (as of 2026-02-28)
- Distribution:
  - vuln module: 12 tests (parsing, version comparison, Ubuntu/Debian fixups)
  - Other modules: ~34 tests distributed across container, rpms, license, etc.

## Common Patterns

**Async Testing:**
- Not applicable — no async/await in codebase
- All I/O blocking; tests use blocking operations naturally

**Error Testing:**
```rust
#[test]
fn best_redhat_fixed_release_rejects_cross_stream_only_match() {
    let pkg = PackageInfo { ... };
    let all = vec![RedHatFixedRelease { ... }];
    assert!(best_redhat_fixed_release(&pkg, &all).is_none());
}
```

**Option/Result Testing:**
- Use `.expect(msg)` with descriptive message: `parsed.expect("package should parse")`
- Use `.is_ok()` / `.is_none()` for boolean assertions
- Use `.as_deref()` or pattern matching for inner value extraction

**Parametrized Tests:**
- Not used; each case gets its own `#[test]` function
- Multiple test functions for related cases (e.g., `package_name_matches` tests several inputs)

**Data-Driven Tests:**
- Not formalized; test data hardcoded per function
- Vectors of test cases created inline: `vec![case1, case2, case3]`

**Example from `src/vuln/tests.rs` (lines 52-60):**
```rust
#[test]
fn extract_el_tag_detects_rhel_tag() {
    assert_eq!(
        extract_el_tag("3:10.3.27-3.module+el8.2.0+9158"),
        Some("el8".into())
    );
    assert_eq!(extract_el_tag("1:5.5.68-1.el7"), Some("el7".into()));
    assert_eq!(extract_el_tag("1.2.3"), None);
}
```

## CI/CD Integration

**CI Pipeline:**
- GitHub Actions at `.github/workflows/ci.yml`
- Steps:
  1. Checkout code
  2. Install Rust toolchain (via `dtolnay/rust-toolchain@stable`)
  3. Build: `cargo build --locked`
  4. Test: `cargo test --locked --no-fail-fast` (runs all tests, doesn't stop on first failure)
- Runs on: `ubuntu-latest`
- Triggered on: push to `main`, all pull requests

**Test Command in CI:**
```bash
cargo test --locked --no-fail-fast
```
- `--locked` — Uses exact versions from `Cargo.lock`
- `--no-fail-fast` — Runs all tests even if some fail (useful for reporting multiple failures)

**Release CI:**
- Separate workflow: `.github/workflows/release.yml`
- Creates GitHub releases with binary artifacts
- Requires version bump in `Cargo.toml` and `Cargo.lock` regeneration before tagging

---

*Testing analysis: 2026-03-02*
