# Phase 2: DB-First Enrichment Pipeline - Context

**Gathered:** 2026-03-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix the #1 bug: scanner checks PostgreSQL/cache before making any live API call, stores all responses back, with HTTP timeouts/circuit breakers and clean standalone/cluster mode separation. No changes to scanning logic, RHEL consolidation, or multi-format support — those are Phases 3-4.

</domain>

<decisions>
## Implementation Decisions

### Cache Lookup Behavior
- Jittered TTL: base 30 days + random jitter of ±7 days per entry — entries expire gradually, no thundering herd
- CronJob refreshes bulk data daily, so per-entry TTL is just a safety net for when CronJob is down
- Red Hat per-package CVE data (no bulk download available) relies on TTL for freshness since it's only fetched at scan time
- osv_batch_query: split batch — check PG/cache for each package first, only send uncached packages to OSV batch API, merge results
- Never waste cached data — always combine cache hits with API results
- One PG table per enrichment source (hard requirement) — OSV, NVD, EPSS, KEV, Red Hat, Debian, Ubuntu, Alpine each get their own table
- Store data matching the original source schema unless performance requires changes

### HTTP Failure Handling
- Retry with exponential backoff on failures: 2s, 4s, 8s, give up after 3 retries
- NVD 403 rate limit: retry with backoff, skip CVE's NVD enrichment on final failure, continue scan
- Circuit breaker: disable an API source after 5 consecutive failures for the remainder of the scan
- When circuit breaker trips: emit a warning progress event AND include a note in the final report summary ("NVD unavailable — results may be incomplete")
- Claude decides HTTP timeout value based on observed API response patterns in the codebase

### Standalone vs Cluster Mode
- Standalone (SCANROOK_CLUSTER_MODE=0): NO PostgreSQL, NO Redis — ever
  - Fallback chain: SQLite vulndb → file cache → live API
  - Write back to file cache after every live API call
  - Standalone users should never touch PG directly
- Cluster (SCANROOK_CLUSTER_MODE=1): PG + Redis only, NO file cache
  - PG is the single source of truth
  - Redis for hot lookups
  - File cache disabled — ephemeral K8s pods make it pointless
- Clean separation: env var controls which path, no cross-contamination

### Cache Write-Back
- Cluster mode: write all API responses back to PG after fetching
- Standalone mode: write all API responses back to file cache after fetching
- Store data in existing PG schema (payload JSONB columns) — match existing field names, add new fields only if needed
- EPSS and KEV get PG tables in cluster mode (consistent with DB-first philosophy)

### Claude's Discretion
- HTTP timeout value (assess from codebase patterns)
- Exact PG table schema for EPSS/KEV (align with existing cache table patterns)
- Redis caching strategy (what to cache, TTL)
- Implementation order within the phase

</decisions>

<specifics>
## Specific Ideas

- "We should try to not hit the API as much as possible" — the daily CronJob downloads all enrichment data, so most scans should complete with zero API calls
- "1 table per enrichment source is a hard requirement" — no combining sources into shared tables
- Store data as closely as possible to existing PG schema — match field names and meanings
- User wants telemetry/logging when circuit breakers trip to help diagnose issues

</specifics>

<code_context>
## Existing Code Insights

### Post-Refactor Module Structure (Phase 1 complete)
- `src/vuln/osv/batch.rs` (322 lines) — osv_batch_query, NO PG parameter (the #1 bug)
- `src/vuln/osv/enrich.rs` (449 lines) — osv_enrich_findings, HAS pg parameter
- `src/vuln/nvd/query.rs` (455 lines) — NVD CPE matching
- `src/vuln/nvd/enrich.rs` (271 lines) — enrich_findings_with_nvd
- `src/vuln/pg.rs` (456 lines) — pg_init_schema, PG cache get/set operations
- `src/vuln/http.rs` (341 lines) — cached_http_json, HTTP client helpers
- `src/vuln/epss.rs` (173 lines) — epss_enrich_findings, uses file cache only
- `src/vuln/kev.rs` (111 lines) — kev_enrich_findings, uses file cache only
- `src/vuln/mod.rs` — SCANROOK_CLUSTER_MODE check function, env_bool helper

### Existing PG Cache Tables (from pg_init_schema)
- `osv_vuln_cache` — vuln_id TEXT PK, payload JSONB, last_checked_at, osv_last_modified
- `nvd_cve_cache` — cve_id TEXT PK, payload JSONB, last_checked_at, nvd_last_modified
- `redhat_cve_cache` — cve_id TEXT PK, payload JSONB, last_checked_at, redhat_last_modified
- `redhat_csaf_cache` — cve_id TEXT PK, payload JSONB, last_checked_at, redhat_last_modified
- No EPSS or KEV tables yet — need to be added

### Cache Infrastructure
- File cache: `src/cache.rs` (62 lines) — SCANNER_SKIP_CACHE env var controls
- SQLite vulndb: `src/vulndb/` — open_vulndb() returns Option<Connection>, query functions
- SCANROOK_CLUSTER_MODE in vuln/mod.rs — boolean check function exists

### Integration Points
- osv_batch_query() needs pg parameter added (signature change)
- Container scan pipeline in container/scan.rs calls enrichment functions — pass PG client through
- epss_enrich_findings and kev_enrich_findings need PG support added for cluster mode
- cached_http_json in http.rs — may need cluster-mode-aware cache routing

</code_context>

<deferred>
## Deferred Ideas

- **Standalone-to-cluster sync endpoint**: CLI scans call a Next.js API endpoint to upload scan-time enrichment data back to cluster PG (prevents exposing PG directly, lets standalone scans contribute data). Needs new Next.js API route + scanner HTTP call. Future phase.
- **PG outside cluster**: If workers move outside the K8s cluster, the mode separation needs revisiting. Current design assumes cluster mode = same-network PG access.
- **Telemetry endpoint**: When circuit breakers trip, report to a telemetry endpoint for operational monitoring. Future phase.

</deferred>

---

*Phase: 02-db-first-enrichment-pipeline*
*Context gathered: 2026-03-03*
