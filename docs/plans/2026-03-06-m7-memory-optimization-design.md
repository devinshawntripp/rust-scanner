# M7 Memory Optimization Design

**Date:** 2026-03-06
**Milestone:** M7 — Aggressive Scanner Refactor
**Status:** Approved design, pending implementation planning

## Problem

CentOS 7 container scans OOM-kill scan pods (3Gi limit) due to:
- Red Hat OVAL XML parsing via `xmltree` DOM: **400-800MB** peak
- Report JSON serialization (`serde_json::to_string_pretty`): **50-100MB** spike
- OSV batch results accumulation: **30-60MB**
- Finding `.clone()` in OSV mapping: **15-30MB**

Total peak: ~500-950MB. Target: ~100-150MB.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| OVAL data source | PG primary, streaming XML fallback | OVAL is the only enrichment not in PG. Python CronJob already handles all other sources. |
| OVAL sync location | Add to existing `vulndb-pg-import.py` | Proven infrastructure, same patterns, zero risk to existing sources. No new Go subcommand. |
| Report format | NDJSON (breaking change) | Eliminates Vec<Finding> accumulation. Worker ingests line-by-line. Old scans cleared. |
| Clone reduction | Rc<> shared references | Internal change, no API impact, 15-30MB savings. |
| Migration strategy | Breaking change, clear old scans | Clean break, no backward compat shim needed. |

## Architecture

### Section 1: OVAL Data Pipeline

**Python CronJob addition (`vulndb-pg-import.py`):**
- New `import_redhat_oval()` function
- Downloads OVAL XML from `redhat.com/security/data/oval/v2/` for RHEL 7, 8, 9
- Stream-parses with `xml.etree.ElementTree.iterparse()` (SAX-style, no full DOM)
- Upserts into two new PG tables:

```sql
oval_definitions (
  id SERIAL PRIMARY KEY,
  rhel_version INT NOT NULL,
  definition_id TEXT NOT NULL,
  cves TEXT[] NOT NULL,
  test_refs TEXT[] NOT NULL,
  severity TEXT,
  issued_date TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(rhel_version, definition_id)
)

oval_test_constraints (
  id SERIAL PRIMARY KEY,
  rhel_version INT NOT NULL,
  test_ref TEXT NOT NULL,
  package TEXT NOT NULL,
  op TEXT NOT NULL,            -- LT, LE, EQ, GE, GT
  evr TEXT NOT NULL,           -- epoch:version-release
  UNIQUE(rhel_version, test_ref, package)
)
```

- Included in SQLite export + zstd compression pipeline
- Revalidation schedule: 24 hours
- Follows same patterns as existing sources: staleness check, diff-based updates, error isolation

**Scanner changes (Rust):**
- New `query_oval_from_pg()` → returns same `CachedOvalData` struct, sourced from PG
- Primary path: query PG (fast, ~5MB memory)
- Fallback path: replace `xmltree` (DOM) with `quick_xml` (SAX streaming) — ~30-50MB peak instead of 400-800MB
- Fallback triggers only when PG has no OVAL data for detected RHEL version

### Section 2: NDJSON Report Output

**Scanner (`rust_scanner`):**
- New `--format ndjson` — make it the default
- Output format:
  ```
  {"type":"header","scanner":...,"target":...}
  {"type":"finding","data":{...}}
  {"type":"file","data":{...}}
  {"type":"summary","data":{...}}
  ```
- Findings written as each completes enrichment — no `Vec<Finding>` accumulation
- Summary computed incrementally via running counters
- Files written as collected during `collect_file_tree()`

**Go worker:**
- Read NDJSON line-by-line
- Batch-insert findings into `scan_findings` every N lines
- Batch-insert files into `scan_files`
- Extract summary line → `scan_jobs.summary_json`
- Upload raw NDJSON to S3

**UI (`scanrook-ui`):**
- Update S3 fallback in `src/app/api/jobs/[id]/findings/route.ts` (lines 110-118)
- Replace `JSON.parse(text)` with line-by-line NDJSON parsing
- Breaking change: old scan reports in S3 incompatible, user clears old data

### Section 3: Clone Reduction

**Scanner (`src/vuln/osv/mapping.rs`):**
- Replace `package.clone()`, `severity.clone()`, `cvss.clone()` with `Rc<>` shared references
- `Rc<PackageInfo>` shared across findings for same package
- `Rc<CvssInfo>` shared when multiple findings reference same CVSS
- Estimated savings: 15-30MB
- Internal change, no API/format impact

## Memory Impact Summary

| Component | Before | After | Savings |
|-----------|--------|-------|---------|
| OVAL XML parsing | 400-800MB | 0MB (PG) / 30-50MB (fallback) | 400-750MB |
| Report accumulation | 20-40MB | ~5MB (streaming) | 15-35MB |
| JSON serialization | 50-100MB | 0MB (NDJSON streaming) | 50-100MB |
| Finding cloning | 15-30MB | ~5MB (Rc sharing) | 10-25MB |
| **Total peak** | **~500-950MB** | **~100-150MB** | **~400-800MB** |

## Files to Modify

### Rust Scanner
- `src/redhat/oval.rs` — add PG query path, replace xmltree with quick_xml fallback
- `src/main.rs` — add `--format ndjson` flag
- `src/report.rs` — NDJSON streaming writer
- `src/container/scan.rs` — stream findings during enrichment instead of accumulating
- `src/container/cli.rs` — same streaming changes
- `src/vuln/osv/mapping.rs` — Rc<> shared references
- `Cargo.toml` — add `quick_xml`, remove `xmltree`

### Go Worker
- `internal/worker/runner.go` — NDJSON report parsing
- `internal/worker/ingest.go` (or new file) — streaming DB ingestion

### Python CronJob
- `scripts/vulndb-pg-import.py` — add `import_redhat_oval()` function

### UI
- `src/app/api/jobs/[id]/findings/route.ts` — NDJSON fallback parser

### SQL Migration
- New tables: `oval_definitions`, `oval_test_constraints`

## Relationship to Existing M7 Items

This memory optimization is the highest-priority M7 work (fixes production OOM). The existing 11 M7 items from `m7-refactor-notes.md` complement this:
- Item 1 (sequential enrichment pipeline) — can be done alongside NDJSON streaming
- Item 9 (duplicate scan logic) — deduplicate `scan.rs` vs `cli.rs` while adding streaming
- Items 4-6 (binary accuracy) — independent, can be done in any order
- Item 10 (vuln/mod.rs size) — independent code quality work
