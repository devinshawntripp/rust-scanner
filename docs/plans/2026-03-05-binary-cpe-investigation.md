# Binary CPE Matching False Positives — Investigation

**Date:** 2026-03-05
**Status:** Investigation complete, improvements proposed for v1.12
**Scope:** `src/binary.rs`, `src/vuln/nvd/query.rs`

---

## False Positive Root Causes

### 1. vendor == product in CPE queries

**Location:** `binary.rs:318`, `query.rs:226-228`

The scanner uses the extracted component name as both `vendor` and `product` in NVD CPE queries. For example, `libssl.so.1.1` becomes `ssl` which generates `cpe:2.3:a:ssl:ssl:1.1:*:*:*:*:*:*:*`. The real NVD CPE is `cpe:2.3:a:openssl:openssl:1.1.1w:*:...`. This causes both false negatives (missing real matches) and false positives (matching unrelated CPEs).

### 2. .so ABI version != release version

**Location:** `binary.rs:489-495` (`infer_component_from_libname`)

`libssl.so.1.1` extracts version `1.1`, which is the ABI compatibility slot, not the OpenSSL release version (e.g. `1.1.1w`). CVEs are filed against release versions, so the version mismatch causes incorrect range comparisons.

### 3. Single version assigned to all PE DLL imports

**Location:** `binary.rs:282-291`

For PE binaries, every imported DLL (`kernel32.dll`, `user32.dll`, `openssl.dll`) gets paired with the same version from `find_version_in_bytes` — the first version-like string found anywhere in the binary. This version often belongs to the application itself, not to the imported library.

### 4. Regex on raw bytes matches non-component strings

**Location:** `binary.rs:537-555` (`find_name_version_pairs`)

The regex `[A-Za-z][A-Za-z0-9_+.-]{1,40}[ _/-]v?(\d+\.\d+...)` matches compiler strings (`gcc 12.2.0`), build paths, copyright notices, and debug symbols embedded in the binary. These produce spurious component/version pairs.

### 5. Strategy 3 (keyword search) has no version filtering

**Location:** `query.rs:149-213` (`nvd_keyword_findings`)

The last-resort fallback returns all CVEs keyword-matching the component+version string with zero version range verification. Every returned CVE becomes a finding regardless of whether the version is actually affected.

---

## Proposed Improvements (v1.12)

### Proposal A: Vendor lookup table (Medium effort)

Create a mapping from common library names to their NVD vendor:

```
ssl -> openssl:openssl
z -> madler:zlib
curl -> haxx:curl
xml2 -> xmlsoft:libxml2
png -> libpng:libpng
jpeg -> ijg:libjpeg
```

When constructing CPE queries, look up the extracted name in this table. If found, use the correct vendor. If not found, fall back to the current behavior but with lower confidence.

**Estimated effort:** 1-2 days. ~50-line lookup table covers the top libraries.

### Proposal B: Minimum match quality threshold (Low effort)

Add a post-query filter that suppresses findings where:
- The NVD CPE vendor does NOT match the extracted component name (case-insensitive)
- The finding came from strategy 3 (keyword-only, no version check)
- The component was extracted from raw byte regex (not from ELF/PE structured data)

Mark these as `confidence: LOW` instead of `MEDIUM` and add an `accuracy_note` explaining the match is unreliable.

**Estimated effort:** 0.5-1 day. Filter logic at the end of the NVD lookup loop.

### Proposal C: Remove or fix strategy 3 (Low effort)

Option 1: Remove `nvd_keyword_findings` entirely — it's the biggest false positive source.
Option 2: Add version range filtering (parse `configurations.nodes` like strategy 1 does).

**Estimated effort:** 0.5 day for removal, 1 day for adding version filtering.

---

## Recommendation

Implement in this order for v1.12:
1. **Proposal C** first (quick win, eliminates the worst false positives)
2. **Proposal B** next (confidence filtering, low effort)
3. **Proposal A** last (vendor table, highest accuracy improvement but more maintenance)
