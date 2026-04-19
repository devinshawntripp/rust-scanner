# ScanRook Scanner Code Refactor Plan

## Goal
Split large monolithic source files into well-organized modules. The scanner works correctly — this is a pure structural refactor with zero behavior changes.

## Current State

| File | Lines | Bytes | Description |
|------|-------|-------|-------------|
| `vuln.rs` | 5,962 | 231KB | Vulnerability enrichment (OSV, NVD, Red Hat, Debian, Ubuntu, Alpine, EPSS, KEV, PG cache, HTTP, version comparison) |
| `container.rs` | 2,617 | 99KB | Container/source scanning + package detection (dpkg, APK, RPM parsing, layer merging) |
| `main.rs` | 2,343 | 81KB | CLI parsing, subcommand dispatch, DB commands, benchmark, diff, upgrade |
| `vulndb.rs` | 1,354 | 51KB | SQLite vulndb build/query/fetch |
| `redhat.rs` | 1,350 | 45KB | Red Hat OVAL XML processing (separate from CSAF enrichment in vuln.rs) |
| `archive.rs` | 1,647 | 56KB | ZIP archive scanning + app package manifest parsers (npm, pip, gem, cargo, go, etc.) |
| `iso.rs` | 1,076 | 35KB | ISO image scanning |
| `sbom.rs` | 729 | 22KB | SBOM import/diff/policy |
| `binary.rs` | 582 | 20KB | Binary scanning |
| `utils.rs` | 414 | 12KB | Progress reporting, file hashing |
| `report.rs` | 312 | 8KB | Report types and summary |
| `license.rs` | 281 | 8KB | License detection |
| `cache.rs` | 62 | 2KB | File cache get/put |
| `usercli.rs` | 381 | 12KB | Auth, config, API client |
| **TOTAL** | **19,110** | **682KB** | |

## Refactor Strategy

### Phase 1: Split `vuln.rs` into a `vuln/` module directory

vuln.rs has 108 functions across 12+ logical domains. Split into:

```
src/vuln/
├── mod.rs          (~150 lines) — Re-exports, env helpers, cluster_mode(), resolve_enrich_cache_dir()
├── http.rs         (~350 lines) — build_http_client, nvd/enrich HTTP clients, redis_client, cached_http_json, nvd_get_json, rate limiting, retry backoff
├── version.rs      (~100 lines) — tokenize_version, cmp_versions, is_version_in_range, cpe_parts
├── cvss.rs         (~80 lines)  — parse_cvss_score, normalize_redhat_severity, severity helpers
├── pg.rs           (~450 lines) — pg_connect, pg_init_schema, all pg_get_*/pg_put_* functions, timestamp parsers, compute_dynamic_ttl_days, strip_param_from_url
├── osv.rs          (~950 lines) — osv_batch_query, map_ecosystem_name_version, map_osv_results_to_findings, osv_enrich_findings, osv_apply_payload_to_findings, osv_fetch_parallel, dedup helpers
├── nvd.rs          (~850 lines) — match_vuln, enrich_findings_with_nvd, nvd_keyword_findings, nvd_cpe_findings, nvd_findings_by_product_version
├── redhat.rs       (~1800 lines) — All CSAF/CVE enrichment: redhat_enrich_findings, redhat_enrich_cve_findings, redhat_inject_unfixed_cves, RPM helpers (parse_redhat_*, best_redhat_*, package_name_matches, etc.)
├── distro.rs       (~200 lines) — distro_feed_enrich_findings orchestrator, DistroFixCandidate, select_best_candidate, apply_distro_candidate_to_finding, pkg_cve_key
├── debian.rs       (~500 lines) — map_debian_advisory_to_cves, debian_source_name_candidates, load_debian_tracker_data, build_debian_candidate_index, build_debian_candidate_index_pg, debian_tracker_enrich (legacy), detect_debian_release, urgency_to_severity
├── ubuntu.rs       (~200 lines) — load_ubuntu_notices_data, build_ubuntu_candidate_index, build_ubuntu_candidate_index_pg
├── alpine.rs       (~100 lines) — alpine_secdb_branches, load_alpine_secdb, build_alpine_candidate_index
├── epss.rs         (~170 lines) — epss_enrich_findings, epss_enrich_enabled
├── kev.rs          (~110 lines) — kev_enrich_findings, kev_from_cache_or_api, fetch_kev_catalog
└── tests.rs        (~230 lines) — All #[cfg(test)] tests
```

**Why this split:**
- Each file has a single responsibility (one data source or one concern)
- Dependencies flow cleanly: `osv.rs` → `pg.rs`, `http.rs`, `distro.rs` → `debian.rs`, `ubuntu.rs`, `alpine.rs`
- `mod.rs` re-exports everything so callers don't need to change import paths
- Tests are isolated but can reference all submodules via `super::*`

### Phase 2: Split `container.rs` into a `container/` module directory

container.rs mixes container image handling with OS package parsers. Split into:

```
src/container/
├── mod.rs          (~150 lines) — Re-exports, PackageCoordinate struct, constants
├── scan.rs         (~500 lines) — scan_container, build_container_report, build_source_report, scan_source_tarball, report_state_for_inventory, env helpers
├── extract.rs      (~400 lines) — extract_tar, merge_layers_docker_save, merge_layers_oci_layout, apply_layer_tar, docker_save_layer_paths, oci_layer_paths, blob_path_from_digest
├── detect.rs       (~350 lines) — detect_os_packages, try_detect_os_packages_from_layout, detect_os_packages_from_layers, apply_layer_file_overrides, Go binary scanning
├── dpkg.rs         (~120 lines) — parse_dpkg_status, parse_dpkg_status_inner, parse_dpkg_status_with_ecosystem
├── apk.rs          (~80 lines)  — parse_apk_installed, parse_apk_installed_with_ecosystem
├── rpm.rs          (~400 lines) — detect_rpm_packages_native, parse_rpm_sqlite, parse_rpm_bdb, parse_rpm_bdb_scan, parse_rpm_header_blob, detect_rpm_packages_cli, RPM tag constants
├── ecosystem.rs    (~120 lines) — detect_dpkg_ecosystem, detect_rpm_ecosystem, detect_apk_ecosystem, trim_os_release_value
├── image.rs        (~80 lines)  — pull_and_save_image
└── tests.rs        (~130 lines) — All tests
```

**Why this split:**
- RPM parsing alone is 400 lines with BerkeleyDB and SQLite logic — deserves its own file
- Package parsers (dpkg, apk, rpm) are reusable and self-contained
- Layer extraction logic is independent from scan orchestration
- Ecosystem detection logic is shared across dpkg/apk/rpm

### Phase 3: Slim down `main.rs`

main.rs has 2343 lines because it handles all CLI subcommands inline. Extract:

```
src/
├── main.rs         (~600 lines) — CLI struct definitions, main(), subcommand dispatch (match only)
├── cli/
│   ├── mod.rs      (~50 lines)  — Re-exports
│   ├── db.rs       (~500 lines) — run_db, run_db_check, print_db_sources, print_pg_cache_check, seed_cache_from_pg, update_*_seed
│   ├── benchmark.rs (~200 lines) — run_benchmark, count_*_findings, command_exists
│   ├── diff.rs     (~150 lines) — run_diff, parse_report_ids, ParsedIds
│   ├── detect.rs   (~200 lines) — build_scan_report_value, looks_like_* file type detection functions
│   └── helpers.rs  (~200 lines) — resolve_cache_dir, clear_*_cache, resolve_yara_rules, env helpers, SCANROOK_DATA_SOURCES, LocalCacheStats
```

### Phase 4: Minor cleanups (no structural changes)

- `redhat.rs` (OVAL) — fine as-is at 1350 lines, single responsibility
- `archive.rs` — fine as-is, could split parsers into `archive/parsers/` later if it grows
- `vulndb.rs` — fine as-is, could split build vs query later
- `iso.rs`, `sbom.rs`, `binary.rs`, `utils.rs`, `report.rs`, `license.rs`, `cache.rs`, `usercli.rs` — all fine, no changes needed

## Execution Order

1. **Phase 1 (vuln.rs split)** — Highest impact, biggest file. Do this first.
2. **Phase 2 (container.rs split)** — Second biggest file.
3. **Phase 3 (main.rs slim)** — Third biggest file.
4. **Phase 4** — Skip unless requested.

## Rules

- **Zero behavior changes.** Every function keeps its exact signature and logic.
- **All `pub` items get re-exported from `mod.rs`** so callers in other modules don't need to change their import paths. E.g., `use crate::vuln::osv_enrich_findings` still works.
- **Move functions, don't copy.** No duplication.
- **Tests move with their functions** into the relevant submodule's `tests.rs`, or stay in a top-level `tests.rs` if they span modules.
- **One commit per phase.** Each phase should compile and pass tests before moving on.
- **No new dependencies.** This is purely structural.

## Verification

After each phase:
1. `cargo build --release` — must compile
2. `cargo test` — all tests pass
3. `cargo fmt --all` — formatted
4. Quick smoke test: `./target/release/scanrook --version` prints correct version
