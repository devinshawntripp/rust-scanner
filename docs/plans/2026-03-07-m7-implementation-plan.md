# M7: Aggressive Scanner Refactor — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate OOM kills on large container scans (500-950MB → 100-150MB peak), improve binary scanning accuracy, speed up enrichment, and reduce code duplication.

**Architecture:** Three-pronged memory optimization (OVAL→PG, NDJSON streaming reports, Rc<> clone reduction) plus accuracy fixes for binary scanning, concurrent enrichment, shared circuit breakers, dedup of scan/cli pipelines, and test coverage.

**Tech Stack:** Rust (scanrook CLI), Go (worker), Python (vulndb CronJob), TypeScript (Next.js UI)

---

## Phase 1: Accuracy Fixes (binary scanning)

Small, isolated changes with no cross-repo dependencies. Safe to do first.

### Task 1: PE DLL Import Version Fix

The bug: `binary.rs:350-361` — when scanning PE binaries, `find_version_in_bytes()` finds ONE version string in the binary's raw bytes and assigns it to ALL DLL imports. So if `openssl.dll` and `zlib.dll` are both imported and the binary contains version string "1.2.11" (zlib), both get version "1.2.11".

**Files:**
- Modify: `src/binary.rs:350-361`
- Test: `src/binary.rs` (add test at bottom of file)

**Step 1: Write a failing test**

Add to bottom of `src/binary.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_dll_version_not_shared_across_imports() {
        // Simulate: a PE binary with two DLL imports (openssl.dll, zlib.dll)
        // and version string "1.2.11" somewhere in the bytes.
        // The old code assigns "1.2.11" to BOTH imports — wrong.
        // The fix: only assign a version to a DLL if we can find a version
        // string near a matching library name in the binary's byte content.

        // We can't easily construct a real PE here, but we CAN test the
        // helper directly:
        let bytes = b"some data openssl 1.1.1w more data zlib 1.2.11 end";
        let budget = bytes.len();

        // find_version_in_bytes should return the FIRST version it finds anywhere
        let ver = find_version_in_bytes(bytes, budget);
        assert!(ver.is_some(), "should find at least one version");

        // The new find_version_near_name should be more selective
        let openssl_ver = find_version_near_name(bytes, budget, "openssl");
        let zlib_ver = find_version_near_name(bytes, budget, "zlib");
        assert_eq!(openssl_ver.as_deref(), Some("1.1.1w"));
        assert_eq!(zlib_ver.as_deref(), Some("1.2.11"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib -- tests::test_pe_dll_version_not_shared_across_imports 2>&1 | head -20`
Expected: FAIL — `find_version_near_name` doesn't exist yet.

**Step 3: Implement `find_version_near_name()`**

Add a new function near `find_version_in_bytes()` in `binary.rs`:

```rust
/// Find a version string that appears within `window` bytes of `name` in the binary content.
/// Returns None if no version is found near the given library name.
fn find_version_near_name(bytes: &[u8], budget: usize, name: &str) -> Option<String> {
    let haystack = &bytes[..budget.min(bytes.len())];
    let name_lower = name.to_lowercase();
    let name_bytes = name_lower.as_bytes();
    let window = 64; // bytes to search before/after the name occurrence

    // Find all occurrences of `name` (case-insensitive via lowercase haystack scan)
    let haystack_lower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();

    let mut pos = 0;
    while pos + name_bytes.len() <= haystack_lower.len() {
        if &haystack_lower[pos..pos + name_bytes.len()] == name_bytes {
            // Found name at `pos` — look for version in surrounding window
            let start = pos.saturating_sub(window);
            let end = (pos + name_bytes.len() + window).min(haystack.len());
            let region = &haystack[start..end];
            if let Some(ver) = extract_version_from_region(region) {
                return Some(ver);
            }
        }
        pos += 1;
    }
    None
}

/// Extract a version-like string (e.g., "1.2.11", "3.0.2") from a byte region.
fn extract_version_from_region(region: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(region);
    let re = regex::Regex::new(r"\d+\.\d+(?:\.\d+[a-z]?)*").ok()?;
    re.find(&text).map(|m| m.as_str().to_string())
}
```

Then update the PE import scanning block at `binary.rs:350-361`:

```rust
Ok(Object::PE(_)) => {
    if let Ok(pe) = PE::parse(&bytes) {
        for imp in pe.imports.iter() {
            let dll = imp.dll.to_string().to_lowercase();
            if let Some(name) = infer_name_from_lib_without_version(&dll) {
                // Try name-aware version extraction first
                if let Some(ver) = find_version_near_name(&bytes, text_budget, &name) {
                    seen_pairs.insert((name, ver));
                } else if let Some(ver) = find_version_in_bytes(&bytes, text_budget) {
                    // Fallback: only if this is the ONLY import (no ambiguity)
                    if pe.imports.len() == 1 {
                        seen_pairs.insert((name, ver));
                    }
                    // Otherwise skip — we can't confidently assign the version
                }
            }
        }
    }
}
```

**Step 4: Run tests**

Run: `cargo test --lib -- tests::test_pe_dll_version_not_shared_across_imports -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/binary.rs
git commit -m "fix: PE DLL import version no longer shared across all imports"
```

---

### Task 2: Raw Byte Regex False Positive Exclusions

The bug: `binary.rs` `find_name_version_pairs()` and `find_version_in_bytes()` match compiler strings, build paths, and copyright notices. E.g., "GCC: (GNU) 12.2.0" → component "gcc" version "12.2.0".

**Files:**
- Modify: `src/binary.rs` — add exclusion patterns
- Test: `src/binary.rs` — add test

**Step 1: Write the failing test**

```rust
#[test]
fn test_compiler_strings_excluded() {
    // GCC version string should not produce a component
    let bytes = b"GCC: (GNU) 12.2.0 (Ubuntu 12.2.0-3ubuntu1)";
    let pairs = find_name_version_pairs(bytes, bytes.len());
    let gcc_pair = pairs.iter().find(|(n, _)| n == "gcc");
    assert!(gcc_pair.is_none(), "gcc compiler string should be excluded, got {:?}", gcc_pair);
}

#[test]
fn test_copyright_strings_excluded() {
    let bytes = b"Copyright (C) 2024 Free Software Foundation, Inc.";
    let ver = find_version_in_bytes(bytes, bytes.len());
    // "2024" should not be treated as a version
    assert!(ver.is_none() || ver.as_deref() != Some("2024"),
        "copyright year should not be a version");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib -- tests::test_compiler_strings_excluded tests::test_copyright_strings_excluded -v`
Expected: FAIL — gcc version is currently matched.

**Step 3: Add exclusion patterns**

Near the top of `binary.rs`, add a constant:

```rust
/// Patterns that look like component+version but are actually compiler/toolchain noise.
const FALSE_POSITIVE_PATTERNS: &[&str] = &[
    "gcc",
    "g++",
    "clang",
    "llvm",
    "rustc",
    "copyright",
    "free software foundation",
    "gnu c library",
    "glibc",
    "built with",
    "compiled by",
    "linker version",
];
```

Add a helper function:

```rust
fn is_false_positive_component(name: &str, context: &str) -> bool {
    let name_lower = name.to_lowercase();
    let context_lower = context.to_lowercase();
    FALSE_POSITIVE_PATTERNS.iter().any(|pat| {
        name_lower == *pat || context_lower.contains(pat)
    })
}
```

Apply the filter in `find_name_version_pairs()` — right before inserting into the output, check `is_false_positive_component()` and skip if true.

**Step 4: Run tests**

Run: `cargo test --lib -- tests::test_compiler_strings_excluded tests::test_copyright_strings_excluded -v`
Expected: PASS

**Step 5: Also verify existing tests still pass**

Run: `cargo test --lib -v 2>&1 | tail -20`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/binary.rs
git commit -m "fix: exclude compiler/copyright strings from binary version detection"
```

---

### Task 3: ELF .note/.comment Version Extraction

Currently binary version detection relies on raw string scanning. ELF binaries often embed real version info in `.note` sections (e.g., `.note.ABI-tag`) and `.comment` sections (GCC version, build info).

**Files:**
- Modify: `src/binary.rs:331-343` (ELF branch)
- Test: `src/binary.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_extract_version_from_elf_comment() {
    // Simulate a .comment section containing "OpenSSL 1.1.1w  10 Sep 2024"
    let comment = b"OpenSSL 1.1.1w  10 Sep 2024\0";
    let pairs = parse_elf_comment_section(comment);
    assert!(pairs.iter().any(|(n, v)| n == "openssl" && v == "1.1.1w"),
        "should extract openssl version from .comment section, got {:?}", pairs);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib -- tests::test_extract_version_from_elf_comment -v`
Expected: FAIL — function doesn't exist.

**Step 3: Implement .comment section parsing**

```rust
/// Parse ELF .comment section bytes for component name+version pairs.
/// Common patterns: "OpenSSL 1.1.1w", "zlib 1.2.11", etc.
fn parse_elf_comment_section(data: &[u8]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let text = String::from_utf8_lossy(data);
    // Split on null bytes (multiple strings in .comment)
    for segment in text.split('\0') {
        let segment = segment.trim();
        if segment.is_empty() { continue; }
        if is_false_positive_component("", segment) { continue; }
        // Try "Name Version" pattern
        let re = regex::Regex::new(r"(?i)([a-z][a-z0-9_-]+)\s+(\d+\.\d+(?:\.\d+[a-z]?)*)").unwrap();
        if let Some(caps) = re.captures(segment) {
            let name = caps[1].to_lowercase();
            let ver = caps[2].to_string();
            if !is_false_positive_component(&name, segment) {
                pairs.push((name, ver));
            }
        }
    }
    pairs
}
```

Then in the ELF scanning block (around line 331), after the existing library import loop, add:

```rust
// Also check ELF sections for embedded version info
if let Some(section_headers) = elf.section_headers.as_slice().iter()
    .find(|s| elf.shdr_strtab.get_at(s.sh_name).map_or(false, |n| n == ".comment"))
{
    let offset = section_headers.sh_offset as usize;
    let size = section_headers.sh_size as usize;
    if offset + size <= bytes.len() {
        let comment_data = &bytes[offset..offset + size];
        for (name, ver) in parse_elf_comment_section(comment_data) {
            seen_pairs.insert((name, ver));
        }
    }
}
```

**Step 4: Run tests**

Run: `cargo test --lib -- tests::test_extract_version_from_elf_comment -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/binary.rs
git commit -m "feat: extract component versions from ELF .comment sections"
```

---

## Phase 2: Memory Optimization — OVAL → PostgreSQL

This is the biggest memory win (~400-800MB saved). Cross-repo: Python CronJob + Rust scanner + SQL migration.

### Task 4: SQL Migration — OVAL Tables

**Files:**
- Modify: `scanrook-ui/scripts/vulndb-pg-import.py` (add table creation to `ensure_pg_tables()`)

**Step 1: Add OVAL tables to the Python schema creation**

In `vulndb-pg-import.py`, find the `ensure_pg_tables()` function and add after the existing CREATE TABLE statements:

```sql
CREATE TABLE IF NOT EXISTS oval_definitions_cache (
    id SERIAL PRIMARY KEY,
    rhel_version INT NOT NULL,
    definition_id TEXT NOT NULL,
    cves TEXT[] NOT NULL,
    test_refs TEXT[] NOT NULL,
    severity TEXT,
    issued_date TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(rhel_version, definition_id)
);
CREATE TABLE IF NOT EXISTS oval_test_constraints_cache (
    id SERIAL PRIMARY KEY,
    rhel_version INT NOT NULL,
    test_ref TEXT NOT NULL,
    package TEXT NOT NULL,
    op TEXT NOT NULL,
    evr TEXT NOT NULL,
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(rhel_version, test_ref, package)
);
```

**Step 2: Run the script locally to verify table creation**

Run: `cd scanrook-ui && python3 scripts/vulndb-pg-import.py --dry-run` (or just verify SQL is valid)

**Step 3: Commit**

```bash
cd scanrook-ui
git add scripts/vulndb-pg-import.py
git commit -m "feat: add OVAL cache tables to vulndb-pg-import schema"
```

---

### Task 5: Python OVAL Import Function

**Files:**
- Modify: `scanrook-ui/scripts/vulndb-pg-import.py`

**Step 1: Add `import_redhat_oval()` function**

Add constants near the top:

```python
# Red Hat OVAL V2 data URLs (one per major RHEL version)
OVAL_V2_URLS = {
    7: "https://access.redhat.com/security/data/oval/v2/RHEL7/rhel-7.oval.xml.bz2",
    8: "https://access.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2",
    9: "https://access.redhat.com/security/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2",
}
```

Add `REVALIDATION_HOURS["oval"] = 24` to the revalidation map.

Add `IMPORT_OVAL` env var check (default "1").

Add the import function. Key implementation points:
- Download .bz2, decompress, stream-parse with `xml.etree.ElementTree.iterparse()`
- For each `<definition>`, extract CVEs from `<metadata><advisory><cve>` and test refs from `<criteria>` tree
- For each `<rpminfo_test>`, extract the package name from `<rpminfo_object>` and the EVR constraint from `<rpminfo_state>`
- Batch upsert into `oval_definitions_cache` and `oval_test_constraints_cache` (1000 rows per commit)
- Track timing and counts for logging

```python
def import_redhat_oval(conn):
    """Import Red Hat OVAL V2 definitions for RHEL 7, 8, 9."""
    if not source_is_stale(conn, "oval"):
        return
    log.info("=== Starting Red Hat OVAL import ===")

    import bz2
    import xml.etree.ElementTree as ET

    ns = {"oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
          "red": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
          "ind": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"}

    for rhel_ver, url in OVAL_V2_URLS.items():
        log.info("Downloading OVAL for RHEL %d: %s", rhel_ver, url)
        t0 = time.time()
        try:
            resp = requests.get(url, timeout=300, stream=True)
            resp.raise_for_status()
            raw = bz2.decompress(resp.content)
        except Exception as e:
            log.error("RHEL %d OVAL download failed: %s", rhel_ver, e)
            continue
        log.info("RHEL %d: downloaded + decompressed in %.1fs (%d bytes)",
                 rhel_ver, time.time() - t0, len(raw))

        # Parse with iterparse for low memory
        definitions = []  # (definition_id, cves[], test_refs[], severity, issued_date)
        test_constraints = []  # (test_ref, package, op, evr)

        # Build object_id→package and state_id→(op,evr) maps first
        objects = {}  # object_id → package_name
        states = {}   # state_id → (op, evr)

        root = ET.fromstring(raw)

        # Parse objects
        for obj in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}rpminfo_object"):
            obj_id = obj.get("id", "")
            name_el = obj.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}name")
            if name_el is not None and name_el.text:
                objects[obj_id] = name_el.text.strip()

        # Parse states
        for st in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}rpminfo_state"):
            st_id = st.get("id", "")
            evr_el = st.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}evr")
            if evr_el is not None and evr_el.text:
                op = evr_el.get("operation", "less than")
                op_code = {"less than": "LT", "less than or equal": "LE",
                           "equals": "EQ", "greater than or equal": "GE",
                           "greater than": "GT"}.get(op, "LT")
                states[st_id] = (op_code, evr_el.text.strip())

        # Parse tests → map test_id to (package, op, evr)
        for test in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}rpminfo_test"):
            test_id = test.get("id", "")
            obj_ref = test.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}object")
            state_ref = test.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}state")
            if obj_ref is not None and state_ref is not None:
                obj_id = obj_ref.get("object_ref", "")
                st_id = state_ref.get("state_ref", "")
                pkg = objects.get(obj_id)
                constraint = states.get(st_id)
                if pkg and constraint:
                    op, evr = constraint
                    test_constraints.append((test_id, pkg, op, evr))

        # Parse definitions
        import re
        cve_re = re.compile(r"CVE-\d{4}-\d+")
        defs_el = root.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}definitions")
        if defs_el is not None:
            for defn in defs_el.findall("{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition"):
                def_id = defn.get("id", "")
                # Extract CVEs from metadata
                cves = set()
                metadata = defn.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata")
                if metadata is not None:
                    for cve_el in metadata.iter():
                        if cve_el.tag.endswith("}cve") or cve_el.tag == "cve":
                            if cve_el.text:
                                cves.add(cve_el.text.strip())
                    # Also check title/description for CVEs
                    title_el = metadata.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}title")
                    if title_el is not None and title_el.text:
                        cves.update(cve_re.findall(title_el.text))
                if not cves:
                    continue

                # Extract test refs from criteria tree
                test_refs = set()
                criteria = defn.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria")
                if criteria is not None:
                    for criterion in criteria.iter():
                        if criterion.tag.endswith("}criterion") or criterion.tag == "criterion":
                            tref = criterion.get("test_ref", "")
                            if tref:
                                test_refs.add(tref)

                # Extract severity and date
                severity = None
                issued_date = None
                if metadata is not None:
                    advisory = None
                    for child in metadata:
                        if child.tag.endswith("}advisory") or child.tag == "advisory":
                            advisory = child
                            break
                    if advisory is not None:
                        sev_el = advisory.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}severity")
                        if sev_el is None:
                            for child in advisory:
                                if child.tag.endswith("}severity") or child.tag == "severity":
                                    sev_el = child
                                    break
                        if sev_el is not None and sev_el.text:
                            severity = sev_el.text.strip()
                        issued_el = advisory.find("{http://oval.mitre.org/XMLSchema/oval-definitions-5}issued")
                        if issued_el is None:
                            for child in advisory:
                                if child.tag.endswith("}issued") or child.tag == "issued":
                                    issued_el = child
                                    break
                        if issued_el is not None:
                            date_str = issued_el.get("date", "")
                            if date_str:
                                try:
                                    issued_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                except ValueError:
                                    pass

                definitions.append((def_id, list(cves), list(test_refs), severity, issued_date))

        # Batch upsert into PG
        now = datetime.now(timezone.utc)
        with conn.cursor() as cur:
            # Clear old data for this RHEL version, then bulk insert
            cur.execute("DELETE FROM oval_definitions_cache WHERE rhel_version = %s", (rhel_ver,))
            cur.execute("DELETE FROM oval_test_constraints_cache WHERE rhel_version = %s", (rhel_ver,))

            for i in range(0, len(definitions), 1000):
                batch = definitions[i:i+1000]
                psycopg2.extras.execute_values(cur, """
                    INSERT INTO oval_definitions_cache
                        (rhel_version, definition_id, cves, test_refs, severity, issued_date, last_checked_at)
                    VALUES %s
                    ON CONFLICT (rhel_version, definition_id) DO UPDATE SET
                        cves = EXCLUDED.cves, test_refs = EXCLUDED.test_refs,
                        severity = EXCLUDED.severity, issued_date = EXCLUDED.issued_date,
                        last_checked_at = EXCLUDED.last_checked_at
                """, [(rhel_ver, d[0], d[1], d[2], d[3], d[4], now) for d in batch])

            for i in range(0, len(test_constraints), 1000):
                batch = test_constraints[i:i+1000]
                psycopg2.extras.execute_values(cur, """
                    INSERT INTO oval_test_constraints_cache
                        (rhel_version, test_ref, package, op, evr, last_checked_at)
                    VALUES %s
                    ON CONFLICT (rhel_version, test_ref, package) DO UPDATE SET
                        op = EXCLUDED.op, evr = EXCLUDED.evr,
                        last_checked_at = EXCLUDED.last_checked_at
                """, [(rhel_ver, tc[0], tc[1], tc[2], tc[3], now) for tc in batch])

        conn.commit()
        log.info("RHEL %d: upserted %d definitions, %d test constraints in %.1fs",
                 rhel_ver, len(definitions), len(test_constraints), time.time() - t0)

        del raw, root  # free memory before next version

    log.info("=== Red Hat OVAL import complete ===")
```

Add `import_redhat_oval` call to the `main()` function alongside the other imports, gated by `IMPORT_OVAL`.

**Step 2: Test locally** (if DB is available)

Run: `cd scanrook-ui && IMPORT_OVAL=1 IMPORT_NVD=0 IMPORT_OSV=0 IMPORT_EPSS=0 IMPORT_KEV=0 IMPORT_DEBIAN=0 IMPORT_UBUNTU=0 IMPORT_ALPINE=0 SKIP_SQLITE_EXPORT=1 python3 scripts/vulndb-pg-import.py`

**Step 3: Commit**

```bash
cd scanrook-ui
git add scripts/vulndb-pg-import.py
git commit -m "feat: import Red Hat OVAL V2 definitions into PostgreSQL"
```

---

### Task 6: Rust Scanner — Query OVAL from PostgreSQL

Replace the XML-parsing primary path with a PG query. Keep `quick_xml` streaming as fallback.

**Files:**
- Modify: `src/redhat/oval.rs`
- Modify: `Cargo.toml` — add `quick-xml` dependency
- Test: `src/redhat/oval.rs`

**Step 1: Add `quick-xml` to Cargo.toml**

```toml
quick-xml = "0.36"
```

**Step 2: Write the failing test for PG query path**

In `src/redhat/oval.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_oval_from_pg_result_maps_correctly() {
        // Simulate what query_oval_from_pg would return and verify it
        // builds a valid CachedOvalData
        let cached = CachedOvalData {
            test_constraints: {
                let mut m = HashMap::new();
                m.insert("oval:test:1".to_string(), vec![RpmConstraint {
                    package: "openssl".to_string(),
                    op: CompareOp::LessThan,
                    evr: "1:1.0.2k-26.el7_9".to_string(),
                }]);
                m
            },
            definitions: vec![CachedDefinition {
                cves: vec!["CVE-2023-0286".to_string()],
                test_refs: vec!["oval:test:1".to_string()],
            }],
        };
        assert_eq!(cached.definitions.len(), 1);
        assert_eq!(cached.test_constraints.len(), 1);
        assert_eq!(cached.definitions[0].cves[0], "CVE-2023-0286");
    }
}
```

**Step 3: Implement `query_oval_from_pg()`**

Add to `src/redhat/oval.rs`:

```rust
/// Query OVAL data from PostgreSQL (populated by vulndb-pg-import CronJob).
/// Returns None if no data exists for the given RHEL major version.
pub fn query_oval_from_pg(
    pg: &mut postgres::Client,
    rhel_version: u8,
) -> Option<CachedOvalData> {
    crate::utils::progress("oval.pg.query.start", &format!("rhel={}", rhel_version));
    let started = std::time::Instant::now();

    // Query definitions
    let def_rows = pg.query(
        "SELECT definition_id, cves, test_refs, severity FROM oval_definitions_cache WHERE rhel_version = $1",
        &[&(rhel_version as i32)],
    ).ok()?;

    if def_rows.is_empty() {
        crate::utils::progress("oval.pg.query.empty", &format!("rhel={}", rhel_version));
        return None;
    }

    let definitions: Vec<CachedDefinition> = def_rows.iter().map(|row| {
        let cves: Vec<String> = row.get("cves");
        let test_refs: Vec<String> = row.get("test_refs");
        CachedDefinition { cves, test_refs }
    }).collect();

    // Query test constraints
    let tc_rows = pg.query(
        "SELECT test_ref, package, op, evr FROM oval_test_constraints_cache WHERE rhel_version = $1",
        &[&(rhel_version as i32)],
    ).ok()?;

    let mut test_constraints: HashMap<String, Vec<RpmConstraint>> = HashMap::new();
    for row in &tc_rows {
        let test_ref: String = row.get("test_ref");
        let package: String = row.get("package");
        let op_str: String = row.get("op");
        let evr: String = row.get("evr");
        let op = match op_str.as_str() {
            "LT" => CompareOp::LessThan,
            "LE" => CompareOp::LessThanOrEqual,
            "EQ" => CompareOp::Equal,
            "GE" => CompareOp::GreaterThanOrEqual,
            "GT" => CompareOp::GreaterThan,
            _ => CompareOp::LessThan,
        };
        test_constraints.entry(test_ref).or_default().push(RpmConstraint { package, op, evr });
    }

    crate::utils::progress_timing("oval.pg.query", started);
    crate::utils::progress("oval.pg.query.done",
        &format!("rhel={} defs={} constraints={}", rhel_version, definitions.len(), tc_rows.len()));

    Some(CachedOvalData { test_constraints, definitions })
}
```

**Step 4: Wire it into `load_oval_data()` and `apply_redhat_oval_enrichment()`**

Modify `apply_redhat_oval_enrichment()` to accept an optional `pg: &mut Option<postgres::Client>` parameter. Try PG first:

```rust
// In apply_redhat_oval_enrichment, before XML fallback:
if let Some(ref mut client) = pg {
    if let Some(rhel_ver) = detect_rhel_version(packages) {
        if let Some(cached) = query_oval_from_pg(client, rhel_ver) {
            // Use PG-sourced OVAL data — skip XML entirely
            let (generated, stats) = generate_and_merge_oval_findings(
                findings, packages, &cached
            );
            return Ok((generated, stats));
        }
    }
}
// Fall through to XML path (with quick_xml streaming instead of xmltree)
```

**Step 5: Replace `xmltree` with `quick_xml` streaming in the XML fallback path**

Replace `parse_oval_file()` to use `quick_xml::Reader` instead of `xmltree::Element::parse()`. This is the fallback path — only used when PG has no OVAL data.

Key change: instead of building the full DOM tree in memory, use event-based parsing to extract only what's needed (definitions, test constraints).

**Step 6: Update `Cargo.toml` — remove `xmltree`, keep `quick-xml`**

Don't remove `xmltree` yet if other code uses it. Check first:

Run: `grep -r "xmltree" src/ --include="*.rs" -l`

If only `oval.rs` uses it, remove from Cargo.toml.

**Step 7: Run all tests**

Run: `cargo test --locked --no-fail-fast 2>&1 | tail -20`

**Step 8: Commit**

```bash
git add src/redhat/oval.rs Cargo.toml Cargo.lock
git commit -m "feat: query OVAL from PostgreSQL, quick_xml streaming fallback"
```

---

### Task 7: Update scan pipelines to pass `pg` to OVAL enrichment

**Files:**
- Modify: `src/container/scan.rs:468-494` — pass `pg` to `apply_redhat_oval_enrichment()`
- Modify: `src/container/cli.rs:364-391` — same

**Step 1: Update function signatures and call sites**

Both `build_container_report()` in `scan.rs` and `scan_container()` in `cli.rs` already have `pg: &mut Option<postgres::Client>` in scope. Pass it to `apply_redhat_oval_enrichment()`.

**Step 2: Run tests**

Run: `cargo test --locked --no-fail-fast`

**Step 3: Commit**

```bash
git add src/container/scan.rs src/container/cli.rs
git commit -m "feat: pass pg connection to OVAL enrichment for PG-first lookups"
```

---

## Phase 3: NDJSON Report Streaming

The second-biggest memory win. Breaking change — requires coordinated changes across scanner, worker, and UI.

### Task 8: Scanner — NDJSON Output Format

**Files:**
- Modify: `src/main.rs:66-69` — add `Ndjson` to `OutputFormat` enum
- Modify: `src/report.rs` — add NDJSON streaming writer
- Modify: `src/container/scan.rs` — stream findings during enrichment
- Modify: `src/container/cli.rs` — use NDJSON writer
- Test: `src/report.rs`

**Step 1: Add `Ndjson` variant to `OutputFormat`**

In `src/main.rs:66-69`:
```rust
#[derive(Clone, ValueEnum, Debug)]
pub enum OutputFormat {
    Json,
    Text,
    Ndjson,
}
```

**Step 2: Write failing test for NDJSON writer**

In `src/report.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndjson_writer_produces_valid_lines() {
        let mut buf = Vec::new();
        {
            let mut writer = NdjsonWriter::new(&mut buf);
            let scanner = ScannerInfo { name: "scanrook", version: "1.12.2" };
            let target = TargetInfo { target_type: "container".into(), source: "test.tar".into(), id: None };
            writer.write_header(&scanner, &target).unwrap();
            writer.write_finding(&Finding {
                id: "CVE-2024-0001".into(),
                source_ids: vec![],
                package: Some(PackageInfo { name: "openssl".into(), ecosystem: "rpm".into(), version: "1.0.2k".into() }),
                confidence_tier: ConfidenceTier::ConfirmedInstalled,
                evidence_source: EvidenceSource::InstalledDb,
                accuracy_note: None, fixed: None, fixed_in: None, recommendation: None,
                severity: Some("HIGH".into()), cvss: None, description: None,
                evidence: vec![], references: vec![], confidence: Some("HIGH".into()),
                epss_score: None, epss_percentile: None, in_kev: None,
            }).unwrap();
            writer.write_summary(&Summary::default()).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.trim().lines().collect();
        assert!(lines.len() >= 3, "expected at least 3 lines (header, finding, summary)");
        // Each line should be valid JSON
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line)
                .expect(&format!("invalid JSON line: {}", line));
        }
        // First line should be header
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["type"], "header");
        // Last line should be summary
        let summary: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(summary["type"], "summary");
    }
}
```

**Step 3: Implement `NdjsonWriter`**

In `src/report.rs`:

```rust
use std::io::Write;

/// Streaming NDJSON report writer. Each method writes one JSON line.
pub struct NdjsonWriter<W: Write> {
    writer: std::io::BufWriter<W>,
    finding_count: usize,
    severity_counts: SeverityCounts,
}

struct SeverityCounts {
    critical: usize, high: usize, medium: usize, low: usize,
    confirmed_critical: usize, confirmed_high: usize, confirmed_medium: usize, confirmed_low: usize,
    heuristic_critical: usize, heuristic_high: usize, heuristic_medium: usize, heuristic_low: usize,
}

impl Default for SeverityCounts {
    fn default() -> Self {
        SeverityCounts {
            critical: 0, high: 0, medium: 0, low: 0,
            confirmed_critical: 0, confirmed_high: 0, confirmed_medium: 0, confirmed_low: 0,
            heuristic_critical: 0, heuristic_high: 0, heuristic_medium: 0, heuristic_low: 0,
        }
    }
}

impl<W: Write> NdjsonWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: std::io::BufWriter::new(writer),
            finding_count: 0,
            severity_counts: SeverityCounts::default(),
        }
    }

    pub fn write_header(&mut self, scanner: &ScannerInfo, target: &TargetInfo) -> std::io::Result<()> {
        let line = serde_json::json!({
            "type": "header",
            "scanner": scanner,
            "target": target,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    pub fn write_finding(&mut self, finding: &Finding) -> std::io::Result<()> {
        // Update running counts
        self.finding_count += 1;
        let sev = finding.severity.as_deref().unwrap_or("").to_uppercase();
        let confirmed = matches!(finding.confidence_tier, ConfidenceTier::ConfirmedInstalled);
        match sev.as_str() {
            "CRITICAL" => { self.severity_counts.critical += 1; if confirmed { self.severity_counts.confirmed_critical += 1; } else { self.severity_counts.heuristic_critical += 1; } },
            "HIGH" => { self.severity_counts.high += 1; if confirmed { self.severity_counts.confirmed_high += 1; } else { self.severity_counts.heuristic_high += 1; } },
            "MEDIUM" => { self.severity_counts.medium += 1; if confirmed { self.severity_counts.confirmed_medium += 1; } else { self.severity_counts.heuristic_medium += 1; } },
            "LOW" => { self.severity_counts.low += 1; if confirmed { self.severity_counts.confirmed_low += 1; } else { self.severity_counts.heuristic_low += 1; } },
            _ => {}
        }

        let line = serde_json::json!({
            "type": "finding",
            "data": finding,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    pub fn write_file(&mut self, file: &FileEntry) -> std::io::Result<()> {
        let line = serde_json::json!({
            "type": "file",
            "data": file,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }

    pub fn write_summary(&mut self, extra: &Summary) -> std::io::Result<()> {
        // Merge running counts with any extra data
        let summary = Summary {
            total_findings: self.finding_count,
            critical: self.severity_counts.critical,
            high: self.severity_counts.high,
            medium: self.severity_counts.medium,
            low: self.severity_counts.low,
            confirmed_total_findings: self.severity_counts.confirmed_critical + self.severity_counts.confirmed_high + self.severity_counts.confirmed_medium + self.severity_counts.confirmed_low,
            heuristic_total_findings: self.severity_counts.heuristic_critical + self.severity_counts.heuristic_high + self.severity_counts.heuristic_medium + self.severity_counts.heuristic_low,
            confirmed_critical: self.severity_counts.confirmed_critical,
            confirmed_high: self.severity_counts.confirmed_high,
            confirmed_medium: self.severity_counts.confirmed_medium,
            confirmed_low: self.severity_counts.confirmed_low,
            heuristic_critical: self.severity_counts.heuristic_critical,
            heuristic_high: self.severity_counts.heuristic_high,
            heuristic_medium: self.severity_counts.heuristic_medium,
            heuristic_low: self.severity_counts.heuristic_low,
            warnings: extra.warnings.clone(),
        };
        let line = serde_json::json!({
            "type": "summary",
            "data": summary,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    pub fn write_metadata(
        &mut self,
        scan_status: &ScanStatus,
        inventory_status: &InventoryStatus,
        inventory_reason: &Option<String>,
    ) -> std::io::Result<()> {
        let line = serde_json::json!({
            "type": "metadata",
            "scan_status": scan_status,
            "inventory_status": inventory_status,
            "inventory_reason": inventory_reason,
        });
        serde_json::to_writer(&mut self.writer, &line)?;
        self.writer.write_all(b"\n")
    }
}
```

**Step 4: Run test**

Run: `cargo test --lib -- report::tests::test_ndjson_writer_produces_valid_lines -v`

**Step 5: Wire NDJSON output into cli.rs and the main scan dispatch**

In `cli.rs`, add a `OutputFormat::Ndjson` match arm that uses `NdjsonWriter` instead of `serde_json::to_string_pretty()`. For now, accumulate findings as before but write with the NDJSON writer at the end.

In `build_container_report()` (scan.rs), the function already returns `Option<Report>` — no change needed there. The NDJSON writing happens in the CLI layer.

**Step 6: Commit**

```bash
git add src/report.rs src/main.rs src/container/cli.rs
git commit -m "feat: add NDJSON output format (--format ndjson) for streaming reports"
```

---

### Task 9: Go Worker — NDJSON Report Parsing

**Files:**
- Modify: `rust-scanner-worker/internal/worker/runner.go` — add NDJSON parsing alongside JSON
- Modify: `rust-scanner-worker/internal/model/report.go` — add NDJSON line types

**Step 1: Add NDJSON line type to model**

In `internal/model/report.go`:

```go
// NdjsonLine represents a single line in NDJSON report output.
type NdjsonLine struct {
    Type string          `json:"type"` // "header", "finding", "file", "summary", "metadata"
    Data json.RawMessage `json:"data"`
    // Header fields (only when Type == "header")
    Scanner json.RawMessage `json:"scanner,omitempty"`
    Target  json.RawMessage `json:"target,omitempty"`
    // Metadata fields (only when Type == "metadata")
    ScanStatus      string `json:"scan_status,omitempty"`
    InventoryStatus string `json:"inventory_status,omitempty"`
    InventoryReason string `json:"inventory_reason,omitempty"`
}
```

**Step 2: Add `streamParseNdjsonReport()` to runner.go**

```go
func streamParseNdjsonReport(path string) (*model.ScanReport, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("open ndjson report: %w", err)
    }
    defer f.Close()

    report := &model.ScanReport{}
    scanner := bufio.NewScanner(f)
    scanner.Buffer(make([]byte, 0, 4*1024*1024), 16*1024*1024) // 16MB max line

    for scanner.Scan() {
        line := scanner.Bytes()
        if len(line) == 0 { continue }

        var ndjson model.NdjsonLine
        if err := json.Unmarshal(line, &ndjson); err != nil {
            log.Printf("skipping invalid ndjson line: %v", err)
            continue
        }

        switch ndjson.Type {
        case "finding":
            var f model.Finding
            if err := json.Unmarshal(ndjson.Data, &f); err == nil {
                report.Findings = append(report.Findings, f)
            }
        case "file":
            var f model.FileRow
            if err := json.Unmarshal(ndjson.Data, &f); err == nil {
                report.Files = append(report.Files, f)
            }
        case "summary":
            if err := json.Unmarshal(ndjson.Data, &report.Summary); err != nil {
                log.Printf("failed to parse summary: %v", err)
            }
        case "metadata":
            report.ScanStatus = ndjson.ScanStatus
            report.InventoryStatus = ndjson.InventoryStatus
            report.InventoryReason = ndjson.InventoryReason
        case "header":
            // Currently unused in ingestion
        }
    }

    return report, scanner.Err()
}
```

**Step 3: Update `processJob()` to detect format and dispatch**

In `runner.go`, after the scanner finishes and before `streamParseReport()`, detect the format:

```go
// Detect report format (JSON vs NDJSON) by peeking at first byte
reportFormat := "json"
if f, err := os.Open(reportPath); err == nil {
    buf := make([]byte, 1)
    if n, _ := f.Read(buf); n > 0 && buf[0] == '{' {
        // Could be JSON object or NDJSON — check if first line has "type" field
        f.Seek(0, 0)
        scanner := bufio.NewScanner(f)
        if scanner.Scan() {
            var probe struct{ Type string `json:"type"` }
            if json.Unmarshal(scanner.Bytes(), &probe) == nil && probe.Type != "" {
                reportFormat = "ndjson"
            }
        }
    }
    f.Close()
}

var report *model.ScanReport
if reportFormat == "ndjson" {
    report, err = streamParseNdjsonReport(reportPath)
} else {
    report, err = streamParseReport(reportPath)
}
```

**Step 4: Run tests**

Run: `cd rust-scanner-worker && go test ./... -v`

**Step 5: Commit**

```bash
cd rust-scanner-worker
git add internal/worker/runner.go internal/model/report.go
git commit -m "feat: support NDJSON report parsing in worker alongside JSON"
```

---

### Task 10: UI — NDJSON S3 Fallback Parser

**Files:**
- Modify: `scanrook-ui/src/app/api/jobs/[id]/findings/route.ts:110-134`

**Step 1: Update `parseS3FindingsFallback()` to handle both formats**

Replace the `JSON.parse(text)` with format detection:

```typescript
// Detect format: if first non-empty line starts with {"type": it's NDJSON
const firstLine = text.trim().split('\n')[0];
let allItems: FindingsItem[];
let summary: Record<string, number>;
let scanStatus: string | null = null;
let inventoryStatus: string | null = null;
let inventoryReason: string | null = null;

if (firstLine.includes('"type"')) {
    // NDJSON format
    const lines = text.trim().split('\n');
    allItems = [];
    summary = {};
    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const obj = JSON.parse(line);
            if (obj.type === 'finding' && obj.data) {
                allItems.push(obj.data as FindingsItem);
            } else if (obj.type === 'summary' && obj.data) {
                summary = obj.data as Record<string, number>;
            } else if (obj.type === 'metadata') {
                scanStatus = obj.scan_status ?? null;
                inventoryStatus = obj.inventory_status ?? null;
                inventoryReason = obj.inventory_reason ?? null;
            }
        } catch { /* skip malformed lines */ }
    }
} else {
    // Legacy JSON format
    const parsed = JSON.parse(text) as Record<string, unknown>;
    allItems = Array.isArray(parsed.findings) ? parsed.findings as FindingsItem[] : [];
    summary = (parsed.summary && typeof parsed.summary === "object")
        ? parsed.summary as Record<string, number>
        : {};
    scanStatus = typeof parsed.scan_status === "string" ? parsed.scan_status : null;
    inventoryStatus = typeof parsed.inventory_status === "string" ? parsed.inventory_status : null;
    inventoryReason = typeof parsed.inventory_reason === "string" ? parsed.inventory_reason : null;
}
```

**Step 2: Commit**

```bash
cd scanrook-ui
git add src/app/api/jobs/[id]/findings/route.ts
git commit -m "feat: support NDJSON report format in S3 fallback parser"
```

---

## Phase 4: Clone Reduction (Rc<>)

### Task 11: Rc<> Shared References in OSV Mapping

**Files:**
- Modify: `src/vuln/osv/mapping.rs:105-204`
- Modify: `src/report.rs:86-130` — add Rc-friendly accessors or keep owned but use Rc in mapping only

**Step 1: Refactor `map_osv_results_to_findings()` to use Rc<> for shared data**

The key insight: when one OSV vulnerability maps to multiple CVE IDs (via aliases), the `package`, `severity`, `cvss`, `description`, `evidence`, and `references` are identical. Instead of cloning each, wrap in `Rc<>` and share.

Since `Finding` uses owned types (for serde compatibility), we can't put `Rc<>` directly in the struct. Instead, build shared data once and clone from the `Rc<>` only when creating the Finding — this still clones but from a single allocation rather than building new strings each time.

Actually, the simpler approach: build the `Finding` once (for the first CVE ID), then clone the whole Finding for subsequent CVE IDs and just change the `id` field:

```rust
if !cve_ids.is_empty() {
    let mut cve_iter = cve_ids.into_iter();
    // Build the base finding for the first CVE
    let first_cve = cve_iter.next().unwrap();
    let base_finding = Finding {
        id: first_cve.trim().to_string(),
        source_ids: source_ids.clone(),
        package: package.clone(),
        // ... all other fields ...
    };
    out.push(base_finding);

    // For remaining CVEs, clone the base and update only the id
    let base_ref = out.last().unwrap();
    for cid in cve_iter {
        let mut cloned = base_ref.clone();
        cloned.id = cid.trim().to_string();
        out.push(cloned);
    }
}
```

This avoids re-allocating `source_ids`, `package`, `severity`, `cvss`, `description`, `evidence`, and `references` separately — the `Clone` on Finding does a single pass.

**Step 2: Run tests**

Run: `cargo test --locked --no-fail-fast`

**Step 3: Commit**

```bash
git add src/vuln/osv/mapping.rs
git commit -m "perf: reduce cloning in OSV mapping — build base finding, clone for aliases"
```

---

## Phase 5: Code Quality & Speed

### Task 12: Deduplicate Container Scan/CLI Enrichment Pipelines

`scan.rs:254-640` and `cli.rs:163-508` have nearly identical enrichment logic. Extract to a shared function.

**Files:**
- Create: `src/container/enrich.rs` — shared enrichment pipeline
- Modify: `src/container/mod.rs` — add `mod enrich;`
- Modify: `src/container/scan.rs` — call shared enrichment
- Modify: `src/container/cli.rs` — call shared enrichment

**Step 1: Create `src/container/enrich.rs`**

Extract the common enrichment pipeline:

```rust
//! Shared enrichment pipeline for container scans.
//! Used by both build_container_report() (scan.rs) and scan_container() (cli.rs).

use crate::container::PackageCoordinate;
use crate::report::Finding;
use crate::vuln::CircuitBreaker;

pub struct EnrichmentContext<'a> {
    pub packages: &'a [PackageCoordinate],
    pub pg: &'a mut Option<postgres::Client>,
    pub nvd_api_key: Option<&'a str>,
    pub oval_redhat: Option<&'a str>,
    pub osv_breaker: &'a CircuitBreaker,
    pub nvd_breaker: &'a CircuitBreaker,
    pub epss_breaker: &'a CircuitBreaker,
    pub kev_breaker: &'a CircuitBreaker,
}

/// Run the full enrichment pipeline: OSV → RHEL supplement → OSV enrich →
/// RedHat unfixed CVEs → NVD → OVAL → dedup → RHEL version filter → EPSS/KEV.
/// Returns the enriched findings vec and whether heuristics were used.
pub fn run_enrichment_pipeline(
    ctx: &mut EnrichmentContext,
    tar_path: &str,
    has_container_layout: bool,
    mode: &crate::ScanMode,
    rootfs: &std::path::Path,
) -> (Vec<Finding>, bool) {
    // ... move the shared logic here ...
    // This is the ~300 lines that are duplicated between scan.rs and cli.rs
    todo!()
}
```

**Step 2: Move shared logic from `scan.rs` lines 254-608 into `run_enrichment_pipeline()`**

The pipeline stages in order:
1. OSV batch query + RHEL supplement
2. OSV enrichment
3. RedHat unfixed CVE injection
4. NVD enrichment
5. Heuristic fallback
6. OVAL enrichment
7. Deduplication
8. RHEL version gating
9. EPSS/KEV parallel enrichment

**Step 3: Update `scan.rs` to call `run_enrichment_pipeline()`**

**Step 4: Update `cli.rs` to call `run_enrichment_pipeline()`**

**Step 5: Run tests**

Run: `cargo test --locked --no-fail-fast`

**Step 6: Commit**

```bash
git add src/container/enrich.rs src/container/mod.rs src/container/scan.rs src/container/cli.rs
git commit -m "refactor: extract shared enrichment pipeline from scan.rs and cli.rs"
```

---

### Task 13: Parallel Enrichment (OSV + NVD Concurrent)

Currently OSV and NVD enrichment run sequentially. They're independent and can run concurrently.

**Files:**
- Modify: `src/container/enrich.rs` (the new shared pipeline)

**Step 1: Use `std::thread::scope` for concurrent enrichment**

The EPSS+KEV parallel enrichment already uses `std::thread::scope` (see `src/vuln/parallel.rs`). Follow the same pattern for OSV+NVD:

```rust
// After OSV query + RHEL supplement:
std::thread::scope(|s| {
    // OSV enrichment in one thread
    let osv_handle = s.spawn(|| {
        crate::vuln::osv_enrich_findings(&mut findings_norm, pg, osv_breaker);
    });

    // NVD enrichment in another thread
    // NOTE: NVD enrichment mutates findings in-place, so we can't run it
    // truly in parallel with OSV enrichment on the same vec.
    // Instead: OSV enrichment first (adds metadata), then NVD in parallel
    // with RedHat unfixed CVE injection.
});
```

Actually, OSV enrichment and NVD enrichment both mutate `findings_norm` in place, so they can't run on the same `&mut Vec` simultaneously. The real parallelism opportunity is:

1. **OSV enrichment** and **RedHat unfixed CVE injection** are independent (different data sources, both read packages)
2. **EPSS + KEV** are already parallel

Better approach: run NVD enrichment concurrently with OVAL enrichment (they touch different finding fields).

Identify the actual independent pairs and use `std::thread::scope` for those. The estimated 30-50% speedup comes from overlapping network I/O.

**Step 2: Run tests and benchmark**

Run: `cargo test --locked --no-fail-fast`

**Step 3: Commit**

```bash
git add src/container/enrich.rs
git commit -m "perf: concurrent enrichment stages where data independence allows"
```

---

### Task 14: Circuit Breaker Shared State with TTL

Currently each scan creates 4 fresh circuit breakers. If NVD is down, every scan burns through 5 failures before tripping.

**Files:**
- Modify: `src/vuln/circuit.rs` — add global shared breakers with TTL

**Step 1: Write the failing test**

```rust
#[test]
fn test_global_breaker_survives_across_scans() {
    let registry = GlobalBreakerRegistry::new();
    let b1 = registry.get("test_src", 5, std::time::Duration::from_secs(300));
    for _ in 0..5 { b1.record_failure(); }
    assert!(b1.is_open());

    // Simulating "next scan" — get same breaker
    let b2 = registry.get("test_src", 5, std::time::Duration::from_secs(300));
    assert!(b2.is_open(), "breaker should still be open from previous scan");
}

#[test]
fn test_global_breaker_resets_after_ttl() {
    let registry = GlobalBreakerRegistry::new();
    let b = registry.get("test_src", 5, std::time::Duration::from_millis(50));
    for _ in 0..5 { b.record_failure(); }
    assert!(b.is_open());
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert!(!b.is_open(), "breaker should auto-reset after TTL");
}
```

**Step 2: Implement `GlobalBreakerRegistry`**

```rust
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct GlobalBreakerRegistry {
    breakers: Mutex<HashMap<&'static str, Arc<CircuitBreaker>>>,
}

impl CircuitBreaker {
    // Add TTL field and tripped_at timestamp
    pub fn is_open(&self) -> bool {
        if self.failures.load(Ordering::SeqCst) >= self.threshold {
            // Check TTL
            if let Some(ttl) = self.ttl {
                if let Some(tripped_at) = self.tripped_at() {
                    if tripped_at.elapsed() > ttl {
                        self.failures.store(0, Ordering::SeqCst);
                        return false;
                    }
                }
            }
            true
        } else {
            false
        }
    }
}
```

Use `lazy_static` or `std::sync::OnceLock` for the global registry.

**Step 3: Wire into scan pipelines**

Replace `CircuitBreaker::new("osv", 5)` calls in scan.rs, cli.rs, binary.rs with registry lookups.

**Step 4: Run tests**

Run: `cargo test --locked --no-fail-fast`

**Step 5: Commit**

```bash
git add src/vuln/circuit.rs src/container/scan.rs src/container/cli.rs src/binary.rs
git commit -m "perf: shared circuit breakers with TTL across scans"
```

---

### Task 15: Test Coverage — Binary Scanning + ISO

**Files:**
- Create: `src/binary_tests.rs` or add to `src/binary.rs` tests module
- Create: test fixtures in `tests/fixtures/`

**Step 1: Add binary scanning integration tests**

Tests to add:
1. Small ELF binary with known library imports → expected findings
2. PE binary with single DLL import → version correctly assigned
3. PE binary with multiple DLL imports → version NOT blindly shared
4. Binary with no libraries → empty findings (not crash)
5. Non-binary file (text) → returns None

**Step 2: Add ISO comps.xml filtering test**

Test that the comps.xml status filter correctly handles different package group statuses.

**Step 3: Run tests**

Run: `cargo test --locked --no-fail-fast`

**Step 4: Commit**

```bash
git add src/binary.rs tests/
git commit -m "test: add binary scanning and ISO comps.xml filter tests"
```

---

### Task 16: Continue vuln Module Splitting

**Files:**
- Modify: `src/vuln/mod.rs` — audit remaining code, split if > 100KB

**Step 1: Check current size**

Run: `wc -c src/vuln/mod.rs` — if < 50KB (since it was partially split already), skip this task.

**Step 2: If still large, identify candidates for extraction**

Move functions into submodules based on source (OSV helpers → `osv/`, NVD helpers → `nvd/`, etc.)

**Step 3: Run tests**

Run: `cargo test --locked --no-fail-fast`

**Step 4: Commit**

```bash
git add src/vuln/
git commit -m "refactor: continue splitting vuln module into focused submodules"
```

---

## Phase 6: Version Bump & Release

### Task 17: Bump Version and Tag

**Files:**
- Modify: `Cargo.toml` — version bump to 1.13.0
- Regenerate: `Cargo.lock`

**Step 1: Bump version**

In `Cargo.toml`: `version = "1.13.0"`

**Step 2: Regenerate lockfile**

Run: `cargo generate-lockfile`

**Step 3: Final test**

Run: `cargo test --locked --no-fail-fast`

**Step 4: Commit and tag**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to v1.13.0"
git tag v1.13.0
```

---

## Execution Order Summary

| Phase | Tasks | Repos | Dependencies |
|-------|-------|-------|-------------|
| 1: Accuracy | 1-3 | rust_scanner | None — can start immediately |
| 2: OVAL→PG | 4-7 | scanrook-ui + rust_scanner | Task 4 before 5, Task 6 before 7 |
| 3: NDJSON | 8-10 | all three repos | Task 8 before 9-10, 9 and 10 are independent |
| 4: Rc<> clones | 11 | rust_scanner | None — independent |
| 5: Quality/Speed | 12-16 | rust_scanner | Task 12 before 13, others independent |
| 6: Release | 17 | rust_scanner | After all others |

**Parallelizable:** Phase 1 + Phase 4 can run in parallel. Within Phase 5, Tasks 14-16 are independent of each other.
