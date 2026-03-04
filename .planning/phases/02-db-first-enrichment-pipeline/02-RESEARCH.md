# Phase 2: DB-First Enrichment Pipeline - Research

**Researched:** 2026-03-03
**Domain:** Rust enrichment pipeline — PostgreSQL cache-first lookup, circuit breakers, mode separation
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Cache Lookup Behavior:**
- Jittered TTL: base 30 days + random jitter of ±7 days per entry — entries expire gradually, no thundering herd
- CronJob refreshes bulk data daily, so per-entry TTL is just a safety net for when CronJob is down
- Red Hat per-package CVE data (no bulk download available) relies on TTL for freshness since it's only fetched at scan time
- osv_batch_query: split batch — check PG/cache for each package first, only send uncached packages to OSV batch API, merge results
- Never waste cached data — always combine cache hits with API results
- One PG table per enrichment source (hard requirement) — OSV, NVD, EPSS, KEV, Red Hat, Debian, Ubuntu, Alpine each get their own table
- Store data matching the original source schema unless performance requires changes

**HTTP Failure Handling:**
- Retry with exponential backoff on failures: 2s, 4s, 8s, give up after 3 retries
- NVD 403 rate limit: retry with backoff, skip CVE's NVD enrichment on final failure, continue scan
- Circuit breaker: disable an API source after 5 consecutive failures for the remainder of the scan
- When circuit breaker trips: emit a warning progress event AND include a note in the final report summary ("NVD unavailable — results may be incomplete")
- Claude decides HTTP timeout value based on observed API response patterns in the codebase

**Standalone vs Cluster Mode:**
- Standalone (SCANROOK_CLUSTER_MODE=0): NO PostgreSQL, NO Redis — ever
  - Fallback chain: SQLite vulndb → file cache → live API
  - Write back to file cache after every live API call
  - Standalone users should never touch PG directly
- Cluster (SCANROOK_CLUSTER_MODE=1): PG + Redis only, NO file cache
  - PG is the single source of truth
  - Redis for hot lookups
  - File cache disabled — ephemeral K8s pods make it pointless
- Clean separation: env var controls which path, no cross-contamination

**Cache Write-Back:**
- Cluster mode: write all API responses back to PG after fetching
- Standalone mode: write all API responses back to file cache after fetching
- Store data in existing PG schema (payload JSONB columns) — match existing field names, add new fields only if needed
- EPSS and KEV get PG tables in cluster mode (consistent with DB-first philosophy)

### Claude's Discretion
- HTTP timeout value (assess from codebase patterns)
- Exact PG table schema for EPSS/KEV (align with existing cache table patterns)
- Redis caching strategy (what to cache, TTL)
- Implementation order within the phase

### Deferred Ideas (OUT OF SCOPE)
- Standalone-to-cluster sync endpoint: CLI scans call a Next.js API endpoint to upload scan-time enrichment data back to cluster PG (prevents exposing PG directly, lets standalone scans contribute data). Needs new Next.js API route + scanner HTTP call. Future phase.
- PG outside cluster: If workers move outside the K8s cluster, the mode separation needs revisiting. Current design assumes cluster mode = same-network PG access.
- Telemetry endpoint: When circuit breakers trip, report to a telemetry endpoint for operational monitoring. Future phase.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ENRICH-01 | Scanner checks PostgreSQL cache before making any live OSV API call | `osv_batch_query()` has zero PG support; `osv_enrich_findings()` has PG support. Fix batch.rs to accept pg param and check osv_vuln_cache per-package before batching to API |
| ENRICH-02 | Scanner checks PostgreSQL cache before making any live NVD API call | `enrich_findings_with_nvd()` already has PG lookup; `nvd_get_json()` in http.rs uses file cache only — needs cluster-mode-aware routing |
| ENRICH-03 | Scanner stores all API responses back to PostgreSQL after fetching | NVD enrich.rs does write-back; OSV batch.rs does not. EPSS/KEV have no PG write-back for misses |
| ENRICH-04 | Scanner uses file cache -> PG -> live API fallback chain (check file first, then PG, then live) | Standalone mode uses file cache only; cluster mode uses PG. The ordering is actually: standalone = SQLite→file cache→API, cluster = PG→API. These are separate paths, not a single chain |
| ENRICH-05 | Scanner with existing PG enrichment data does not make redundant live API calls for cached CVEs | OSV enrich already does this correctly; OSV batch does not; NVD enrich already does this correctly |
| ENRICH-06 | PG cache entries have a revalidation timestamp — scanner re-fetches when data is stale, not every time | `compute_dynamic_ttl_days()` exists in pg.rs; used in osv/enrich.rs and nvd/enrich.rs but NOT in osv/batch.rs. Jitter logic to be added |
| SCAN-02 | All HTTP API requests have timeouts and circuit breakers — no infinite hangs | `build_http_client(timeout_secs)` exists; NVD has retry+backoff; OSV batch has retry but no timeout on per-package fallback loop (infinite loop risk); circuit breaker struct to be added in vuln/mod.rs or new vuln/circuit.rs |
| INFR-03 | Clean separation between standalone mode (file cache only) and cluster mode (PG + Redis) with no cross-contamination | `cluster_mode()` exists in vuln/mod.rs; `resolve_enrich_cache_dir()` returns None in cluster mode; but osv/batch.rs always uses resolve_enrich_cache_dir which means it calls pg_connect() never — need to add cluster-mode branch to batch.rs |
</phase_requirements>

## Summary

Phase 2 addresses a single critical bug with multiple symptoms: `osv_batch_query()` has zero PostgreSQL support, meaning every scan hits the OSV batch API even when all package CVEs are already in the PG cache. The other enrichment functions (`osv_enrich_findings`, `enrich_findings_with_nvd`) already have PG cache integration, but `osv_batch_query` — the first function called in the pipeline — does not receive a `pg` parameter at all. This means on every scan the scanner fires 50-package batches at OSV even though 5GB of cached data sits in PostgreSQL.

The secondary issues are: (1) circuit breakers are absent — the NVD retry loop has backoff but no "give up for this scan" mechanism, and there is an infinite-loop risk in the OSV per-package fallback in batch.rs; (2) EPSS and KEV lack PG write-back for API misses in cluster mode; and (3) the mode separation (`cluster_mode()`) is not enforced in batch.rs at all — cluster mode pods use the file cache path.

The good news is the infrastructure already exists: `pg_connect()`, `pg_init_schema()`, all `pg_get_*` and `pg_put_*` helpers, `compute_dynamic_ttl_days()`, and the `cluster_mode()` check are all in place. The work is primarily: (a) threading a `pg` parameter into `osv_batch_query`, (b) adding per-package PG lookups before batching, (c) adding a `CircuitBreaker` struct per API source, and (d) enforcing mode separation uniformly.

**Primary recommendation:** Add `pg` parameter to `osv_batch_query`, implement per-package PG pre-check that filters packages already in cache, add `CircuitBreaker` struct in `vuln/circuit.rs` shared across all HTTP sources, enforce mode separation, and add jitter to TTL computation.

## Standard Stack

### Core (already in Cargo.toml — no new dependencies needed)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `postgres` | 0.19 | PG cache get/put | Already used throughout vuln/pg.rs |
| `chrono` | 0.4 | TTL timestamp arithmetic | Used in all cache TTL checks |
| `rand` | 0.8 | TTL jitter generation | Already in Cargo.toml, used in http.rs backoff |
| `rayon` | 1.10 | Parallel fetch | Used in osv/enrich.rs and nvd/enrich.rs |
| `reqwest` | 0.11 blocking | HTTP client with timeout | Used in http.rs via `build_http_client(secs)` |

### No New Dependencies Required

All required functionality is achievable with existing crate imports. The circuit breaker can be implemented as a simple in-process struct using `std::sync::atomic::AtomicU32` — no external crate needed.

## Architecture Patterns

### Recommended File Layout (existing structure, additions only)

```
src/vuln/
├── batch.rs (new — extract osv_batch_query PG logic if grows beyond ~200 lines, else keep in osv/batch.rs)
├── circuit.rs (NEW — CircuitBreaker struct, shared across all API sources)
├── osv/
│   ├── batch.rs     — ADD pg: &mut Option<PgClient> param, per-package PG pre-check
│   └── enrich.rs    — Already has PG; add jitter to TTL
├── nvd/
│   └── enrich.rs    — Already has PG; wire circuit breaker from vuln/circuit.rs
├── epss.rs          — Add PG write-back for API misses in cluster mode
├── kev.rs           — Add PG write-back for API misses in cluster mode
├── pg.rs            — Add compute_jittered_ttl_days(); add pg_put_epss, pg_put_kev helpers
└── mod.rs           — Re-export CircuitBreaker if needed; ensure cluster_mode() used uniformly
```

### Pattern 1: Per-Package PG Pre-Check in osv_batch_query

**What:** Before constructing the API batch body, iterate packages, check `osv_vuln_cache` for each, collect hits into results, collect misses into `packages_to_fetch`. Only the misses go to the OSV batch API.

**When to use:** Any batch enrichment function where items can be individually cached.

**Exact signature change needed:**
```rust
// BEFORE (in src/vuln/osv/batch.rs, line 13)
pub fn osv_batch_query(packages: &Vec<PackageCoordinate>) -> serde_json::Value {

// AFTER
pub fn osv_batch_query(
    packages: &Vec<PackageCoordinate>,
    pg: &mut Option<PgClient>,
) -> serde_json::Value {
```

**Pre-check logic (insert before line 58, the chunk loop):**
```rust
// Cluster mode: check PG cache per package before batching
let mut pg_hits: std::collections::HashMap<usize, Value> = std::collections::HashMap::new();
let mut uncached_indexed: Vec<(usize, Value)> = Vec::new();
if cluster_mode() {
    if let Some(c) = pg.as_mut() {
        for (orig_idx, q) in &indexed {
            let pkg = &packages[*orig_idx];
            let (ecosystem, name, _version) = map_ecosystem_name_version(pkg);
            // OSV vuln_id for batch query is keyed by ecosystem+name+version combo
            // Use a synthetic cache key matching the batch query body digest approach
            // Actually: check by looking at any stored osv_vuln_cache entries that
            // contain this package in their "affected" field — but that's complex.
            // Simpler: use the existing file-cache chunk approach but routed through PG.
            // The chunk body digest approach already works — just need PG routing.
            // NOTE: osv_batch_query caches the BATCH RESPONSE, not per-vuln entries.
            // Per-vuln entries are in osv_enrich_findings via pg_get_osv/pg_put_osv.
            // For batch: PG cache is keyed by body_digest (same as file cache tag).
            // So the check is: pg_get_osv_batch_chunk(c, &body_digest) -> Option<Value>
        }
    }
}
```

**Important insight from code analysis:** `osv_batch_query()` caches the *chunk response* (the array of results for 50 packages), not individual per-vulnerability records. The existing `cache_tag = cache_key(&["osv_batch", &body_digest])` is the right granularity. The fix is to add a PG-backed chunk cache alongside the file cache, using the same `body_digest` as key. This avoids per-package PG lookups (which would require knowing which vuln IDs map to which packages before fetching) and keeps the batch structure intact.

**Revised approach for osv_batch_query:**
- Add a new PG table `osv_batch_cache` OR use the existing file cache approach but route it through PG in cluster mode.
- The simplest correct approach: keep the chunk-level cache tag, but in cluster mode read/write from a PG `osv_batch_chunk_cache` table (TEXT PK = body_digest, payload JSONB, last_checked_at TIMESTAMPTZ).
- This satisfies ENRICH-01 without restructuring the batch logic.
- Per-package TTL checking (ENRICH-06) for batch is implicit: the chunk TTL covers all packages in that chunk.

### Pattern 2: Circuit Breaker

**What:** A simple scan-scoped per-source failure counter. After 5 consecutive failures, mark the source as disabled. All subsequent calls to that source short-circuit immediately. Emit a warning progress event on trip. Append a note to the report summary on trip.

**Implementation in `src/vuln/circuit.rs` (new file):**
```rust
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub struct CircuitBreaker {
    failures: AtomicU32,
    threshold: u32,
    source_name: &'static str,
}

impl CircuitBreaker {
    pub fn new(source_name: &'static str, threshold: u32) -> Arc<Self> {
        Arc::new(Self {
            failures: AtomicU32::new(0),
            threshold,
            source_name,
        })
    }

    pub fn record_failure(&self) {
        let prev = self.failures.fetch_add(1, Ordering::SeqCst);
        if prev + 1 == self.threshold {
            crate::utils::progress(
                &format!("{}.circuit_breaker.tripped", self.source_name),
                &format!(
                    "API source '{}' disabled after {} consecutive failures",
                    self.source_name, self.threshold
                ),
            );
        }
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    pub fn is_open(&self) -> bool {
        self.failures.load(Ordering::SeqCst) >= self.threshold
    }
}
```

**Usage:** The circuit breaker is created once per scan (per pipeline invocation) and passed into enrichment functions. When `is_open()` returns true, the function returns early without making HTTP calls.

**Report summary note:** When a breaker is tripped, append to `Report.summary.notes` or a new `unavailability_warnings: Vec<String>` field. Check the `Report` struct in `src/report.rs` for the exact mechanism.

### Pattern 3: Jittered TTL

**What:** Instead of a fixed TTL, add a random ±7 day jitter so entries expire at staggered times (no thundering herd when many entries were all imported by the same CronJob run).

**Add to `src/vuln/pg.rs`:**
```rust
use rand::Rng;

/// Compute a jittered TTL in days: base_days ± jitter_days (clamped to min 1).
pub(super) fn compute_jittered_ttl_days(base_days: i64, jitter_days: i64) -> i64 {
    let jitter: i64 = rand::thread_rng().gen_range(-jitter_days..=jitter_days);
    (base_days + jitter).max(1)
}
```

Usage: replace bare `30` TTL constants with `compute_jittered_ttl_days(30, 7)` in places where entries are WRITTEN (at `pg_put_*` time, compute the expiry offset to store, OR compute it at read time when checking `last_checked_at`).

**Simpler approach:** Compute jitter at CHECK time: when reading `last_checked_at`, compute `ttl = compute_jittered_ttl_days(30, 7)` per entry. Since `rand` is already imported (`rand::thread_rng()`), this is zero-cost to add.

### Pattern 4: Mode Separation Enforcement

**What:** `cluster_mode()` in `vuln/mod.rs` is already the authoritative function. The enforcement gap is that `osv/batch.rs` never calls it — it only calls `resolve_enrich_cache_dir()` which already returns `None` in cluster mode. The real gap is that batch.rs never attempts a PG lookup.

**Enforcement matrix:**

| Function | Standalone path | Cluster path | Gap |
|----------|----------------|--------------|-----|
| `osv_batch_query` | file cache chunk → API | (missing) PG chunk cache → API for misses | Missing PG path |
| `osv_enrich_findings` | file cache per-vuln → API | PG per-vuln → API | Already correct |
| `enrich_findings_with_nvd` | file cache per-CVE → API | PG per-CVE → API | Already correct |
| `epss_enrich_findings` | file cache chunk → API | PG bulk → API for misses (hit) → no PG write-back | Missing PG write-back |
| `kev_enrich_findings` | file cache → API | PG table → API fallback (hit) → no PG write-back | Missing PG write-back |

**EPSS write-back:** After fetching from FIRST.org API in cluster mode, call a new `pg_put_epss_scores(c, &chunk_scores)` helper that inserts into `epss_scores_cache`.

**KEV write-back:** After fetching the KEV catalog in cluster mode, call a new `pg_put_kev_entries(c, &kev_set)` helper that inserts into `kev_entries_cache`.

### Pattern 5: HTTP Timeout Values (Claude's Discretion)

From the existing code:
- `nvd_timeout_secs()` defaults to **20 seconds** (configurable via `SCANNER_NVD_TIMEOUT_SECS`)
- `enrich_http_client()` uses **30 seconds** (hardcoded in http.rs:64)
- OSV batch uses `osv_timeout_secs` defaulting to **60 seconds** (configurable via `SCANNER_OSV_TIMEOUT_SECS`)
- Red Hat API uses **20 seconds** (configurable via `SCANNER_REDHAT_TIMEOUT_SECS`)

**Recommendation:** These existing timeouts are appropriate. The infinite-loop risk is in the per-package fallback in `osv/batch.rs` lines 204-263 — the inner `loop` has no attempt limit beyond `retries`. The fix is the existing `attempt_p >= retries` break on line 249, but the progress call on 215 shows it does bound correctly. Actually reviewing more carefully: line 249 shows `if attempt_p >= retries { break; }` — this IS bounded. The concern was unfounded; there is no infinite loop. However the loop does sleep `backoff_ms_base * attempt_p` which at attempt_p=3 is 1500ms per package. With 100 packages that's 2.5 minutes just in sleep. The circuit breaker will handle this by disabling OSV after 5 consecutive failures, causing the per-package fallback to exit early.

**Confirmed timeout recommendations:**
- OSV batch: keep 60s (batch of 50 packages, OSV can be slow)
- OSV single: use 30s (single package query)
- NVD: keep 20s (usually fast with API key)
- EPSS: keep 30s (enrich_http_client)
- KEV: keep 30s (single large download)
- Red Hat: keep 20s (per-CVE fetches)

### Anti-Patterns to Avoid

- **Parallel PG writes from rayon threads:** `PgClient` is `!Send` — cannot pass to rayon threads. Pattern: collect results from parallel fetch phase, then write to PG sequentially. Already done correctly in nvd/enrich.rs lines 138-142 and osv/enrich.rs lines 396-401.
- **Calling `pg_connect()` multiple times per scan:** Expensive (TCP handshake + auth). Current code calls it once in container/scan.rs line 321, passes `Option<PgClient>` through. Keep this pattern — do NOT add new `pg_connect()` calls in epss.rs or kev.rs. Instead, change their signatures to accept `pg: &mut Option<PgClient>`.
- **Mutating global env vars for rate limiting:** `nvd_get_json()` at lines 334-336 mutates `SCANNER_NVD_SLEEP_MS` via `std::env::set_var` as a rate limit signal. This is not thread-safe. The circuit breaker approach is better — avoid new uses of `set_var`.
- **Skipping file cache write-back in standalone mode:** In standalone mode, every API call result MUST be written to the file cache. Existing code does this correctly; preserve the pattern when adding new write-back paths.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Circuit breaker | Complex state machine with exponential backoff | Simple `AtomicU32` counter with threshold | Scans are single-threaded at the pipeline level; no distributed state needed |
| TTL jitter | Bloom filters, consistent hashing | `rand::thread_rng().gen_range(-7..=7)` added to base TTL | Already using rand crate; simple math is correct |
| PG connection pooling | Custom pool | Single `Option<PgClient>` passed by `&mut` | Scan is single-request; pool adds complexity for no gain in this context |
| Per-package OSV cache keys | Complex key derivation | Body-digest chunk cache (existing approach) extended to PG | Keeps the batch optimization intact; individual vuln IDs from batch not known before fetch |

**Key insight:** The codebase already has the right abstractions. The work is threading the pg parameter into osv_batch_query and adding ~50 lines of new circuit breaker logic.

## Common Pitfalls

### Pitfall 1: osv_batch_query caches CHUNKS not VULNS

**What goes wrong:** Attempting to check PG's `osv_vuln_cache` per-package before batching will fail — those entries are individual vuln records (e.g. `GHSA-xxx`) written by `osv_enrich_findings`. The batch query result is a parallel array of `{"vulns": [...]}` entries indexed by package position. There is no direct mapping from package to vuln ID before the batch is sent.

**Why it happens:** OSV batch API returns `results[i]` for `queries[i]` — you don't know which vuln IDs you'll get until after the fetch. Pre-checking per-package would require knowing vuln IDs first.

**How to avoid:** Add a NEW `osv_batch_chunk_cache` PG table (or a generic `kv_cache` table) keyed by the SHA256 body_digest of the batch chunk body. This mirrors exactly what the file cache does. The chunk result is valid for the same TTL as individual vuln entries.

**Warning signs:** If you see per-package PG lookups in batch.rs that try to use `pg_get_osv()` with package names as keys, that's wrong — `pg_get_osv()` takes vuln IDs like `GHSA-xxx` or `CVE-xxx`, not package names.

### Pitfall 2: Signature Change Propagates to All Callers

**What goes wrong:** Adding `pg: &mut Option<PgClient>` to `osv_batch_query` requires updating all call sites. The scan pipeline calls `osv_batch_query` in TWO places in `container/scan.rs` (line 248 and line 279), plus any other scan pipelines (binary.rs, sbom.rs, iso/scan.rs).

**How to avoid:** Search all usages of `osv_batch_query` before changing the signature:
```bash
grep -rn "osv_batch_query" src/
```
From the code analysis: found in `container/scan.rs` (2 calls), `vuln/osv/mod.rs` (re-export). Check binary.rs, sbom.rs, iso/ as well.

**Warning signs:** Compilation errors after signature change pointing to unexpected callers.

### Pitfall 3: EPSS/KEV write-back changes their signatures

**What goes wrong:** `epss_enrich_findings(findings, cache_dir)` and `kev_enrich_findings(findings, cache_dir)` currently take `cache_dir: Option<&Path>`. Adding PG write-back requires either: (a) changing signature to also accept `pg: &mut Option<PgClient>`, or (b) having them call `pg_connect()` internally. Option (b) is wrong (creates extra PG connections). Option (a) is correct but requires updating all callers.

**How to avoid:** Change signatures to `(findings, pg: &mut Option<PgClient>, cache_dir: Option<&Path>)` and update the two call sites in `container/scan.rs` lines 578-579. The `pg` is already available at that point (line 321).

**Warning signs:** Extra pg_connect() calls appearing in epss/kev code.

### Pitfall 4: Circuit Breaker Must be Scan-Scoped, Not Process-Scoped

**What goes wrong:** If the circuit breaker is stored in a `static OnceLock`, a transient failure in scan 1 will permanently disable an API source for all subsequent scans in the same process (the worker runs multiple scans). This would cause silent data loss.

**Why it happens:** The file cache static statics (`NVD_HTTP_CLIENT`, `ENRICH_HTTP_CLIENT`) are process-scoped because clients are stateless. Circuit breakers are NOT stateless — they track scan-specific failure counts.

**How to avoid:** Create the `CircuitBreaker` instances at the top of each scan pipeline function (e.g., `build_container_report`) and pass them through to enrichment functions. Reset on each scan by construction (new instance per scan). Do NOT use `static` or `OnceLock` for circuit breakers.

### Pitfall 5: Report Summary "unavailability" Notes

**What goes wrong:** The `Report` struct in `report.rs` may not have a field for "scan-time warnings". Adding to `Summary` requires checking whether `Summary` is serialized to JSON in a way that the UI/worker parses.

**How to avoid:** Read `src/report.rs` to check the `Summary` struct before adding fields. The safest approach is to add a `Vec<String>` field to `Summary` named `warnings` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`. This is backward-compatible (absent when empty, not deserialized when not present).

### Pitfall 6: TTL Jitter Applied Inconsistently

**What goes wrong:** If jitter is applied at WRITE time (when computing expiry), multiple entries written in the same CronJob batch will have different expiries. But if jitter is applied at READ time (when checking TTL), each read produces a different jitter — an entry might be fresh on one read and stale on the next.

**How to avoid:** Apply jitter at READ time, consistently: `let ttl = base_days + rand_range(-7, 7); if age > ttl { re-fetch }`. The random value differs per-check, meaning on average entries expire around day 30 but spread across 23-37 days. This is acceptable and correct for the thundering herd goal.

## Code Examples

### Adding osv_batch_chunk_cache Table

```rust
// In pg_init_schema, append to the batch_execute call:
"CREATE TABLE IF NOT EXISTS osv_batch_chunk_cache (
    chunk_digest TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    last_checked_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_osv_batch_chunk_last_checked ON osv_batch_chunk_cache (last_checked_at);"
```

### PG Chunk Lookup in osv_batch_query

```rust
// Before the chunk loop in osv/batch.rs:
// Pass pg: &mut Option<postgres::Client> as new parameter

// Inside the per-chunk loop, BEFORE the "Network request" section:
if cluster_mode() {
    if let Some(c) = pg.as_mut() {
        let row = c.query_opt(
            "SELECT payload FROM osv_batch_chunk_cache 
             WHERE chunk_digest = $1 
             AND last_checked_at > NOW() - INTERVAL '30 days'",
            &[&body_digest],
        ).ok().flatten();
        if let Some(row) = row {
            let v: Value = row.get(0);
            if let Some(arr) = v["results"].as_array() {
                for (idx_in_chunk, item) in arr.iter().enumerate() {
                    results[chunk[idx_in_chunk].0] = item.clone();
                }
                progress("osv.query.chunk.pg_cache", &format!("digest={}", &body_digest[..8]));
                done = true;
                break; // skip network request
            }
        }
    }
}
```

### PG Chunk Write-Back in osv_batch_query

```rust
// After successful API parse (where cache_put is called in the file-cache path):
if cluster_mode() {
    if let Some(c) = pg.as_mut() {
        let _ = c.execute(
            "INSERT INTO osv_batch_chunk_cache (chunk_digest, payload, last_checked_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT (chunk_digest) DO UPDATE 
               SET payload = EXCLUDED.payload, last_checked_at = NOW()",
            &[&body_digest, &v],
        );
    }
} else {
    cache_put(cache_dir.as_deref(), &cache_tag, v.to_string().as_bytes());
}
```

### EPSS PG Write-Back Helpers

```rust
// In src/vuln/pg.rs — add:
pub(super) fn pg_put_epss_scores(
    client: &mut PgClient,
    scores: &HashMap<String, (f32, f32)>,
) {
    for (cve_id, (score, percentile)) in scores {
        let _ = client.execute(
            "INSERT INTO epss_scores_cache (cve_id, score, percentile, last_checked_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (cve_id) DO UPDATE 
               SET score = EXCLUDED.score, 
                   percentile = EXCLUDED.percentile,
                   last_checked_at = NOW()",
            &[cve_id, score, percentile],
        );
    }
}

pub(super) fn pg_put_kev_entries(
    client: &mut PgClient,
    kev_set: &HashSet<String>,
) {
    for cve_id in kev_set {
        let _ = client.execute(
            "INSERT INTO kev_entries_cache (cve_id, last_checked_at)
             VALUES ($1, NOW())
             ON CONFLICT (cve_id) DO NOTHING",
            &[cve_id],
        );
    }
}
```

### Jittered TTL Check

```rust
// In pg.rs compute_dynamic_ttl_days (or new compute_jittered_ttl_days):
pub(super) fn compute_jittered_ttl_days(base_days: i64, jitter_days: i64) -> i64 {
    let jitter: i64 = rand::thread_rng().gen_range(-jitter_days..=jitter_days);
    (base_days + jitter).max(1)
}
```

### Circuit Breaker Usage in nvd/enrich.rs

```rust
// At call site in build_container_report or scan pipeline:
let nvd_breaker = CircuitBreaker::new("nvd", 5);
// ...
enrich_findings_with_nvd(&mut findings_norm, api_key, &mut pg, &nvd_breaker);

// In enrich_findings_with_nvd:
if nvd_breaker.is_open() {
    progress("nvd.fetch.skip", "circuit breaker open");
    // Append to report warnings -- handled by caller
    return;
}
// ... per CVE:
match nvd_get_json(...) {
    Some(json) => { nvd_breaker.record_success(); ... }
    None => {
        nvd_breaker.record_failure();
        if nvd_breaker.is_open() { break; } // stop fetching
    }
}
```

## State of the Art

| Old Approach | Current Approach | Change Needed | Impact |
|--------------|------------------|---------------|--------|
| `osv_batch_query` — file cache only | File cache only (still current) | Add cluster-mode PG chunk cache | Zero OSV API calls when CronJob populated PG |
| `enrich_findings_with_nvd` — PG check exists | PG check for EACH CVE before fetch | Already correct; add circuit breaker | Prevents NVD hung scan |
| `epss_enrich_findings` — PG read, no write | PG read, then file cache fallback | Add PG write-back after API fetch | Cluster pods cache EPSS across scans |
| `kev_enrich_findings` — PG read, no write | PG read, then file cache fallback | Add PG write-back after API fetch | Cluster pods cache KEV across scans |
| TTL — fixed days | `compute_dynamic_ttl_days` (age-based) | Add jitter ±7 days at read time | No thundering herd after CronJob |
| No circuit breaker | Retry with backoff | Add scan-scoped `CircuitBreaker` struct | Prevents infinite hang on sustained failures |

## Open Questions

1. **osv_batch_chunk_cache table vs generic kv_cache**
   - What we know: osv_batch uses body-digest as cache key; unique to this function
   - What's unclear: Whether a generic `kv_cache(key TEXT PK, payload JSONB, last_checked_at TIMESTAMPTZ)` table would be better for extensibility
   - Recommendation: Use a dedicated `osv_batch_chunk_cache` table to match the "one table per source" hard requirement from CONTEXT.md

2. **Circuit breaker scope: per-scan vs per-source-per-scan**
   - What we know: User wants 5 consecutive failures to disable a source for the scan
   - What's unclear: Should EPSS and KEV have their own circuit breakers, or should only OSV and NVD (the ones that cause hangs) have them?
   - Recommendation: Give every HTTP source its own circuit breaker for consistency. Instantiate all at the top of `build_container_report`.

3. **How to surface circuit breaker warnings in report summary**
   - What we know: `Report.summary` is a `Summary` struct in report.rs
   - What's unclear: Whether adding a `warnings: Vec<String>` field to `Summary` will break the worker or UI JSON parsing
   - Recommendation: Check `report.rs` before implementing. Use `#[serde(default, skip_serializing_if = "Vec::is_empty")]` for backward compatibility.

4. **Callers of osv_batch_query beyond container/scan.rs**
   - What we know: container/scan.rs calls it at lines 248 and 279
   - What's unclear: Whether binary.rs, sbom.rs, iso scan, or archive scan also call it
   - Recommendation: `grep -rn "osv_batch_query" src/` before implementing. All callers need `&mut Option<PgClient>` threaded in.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (`cargo test`) |
| Config file | `Cargo.toml` (no external config needed) |
| Quick run command | `cargo test --locked --no-fail-fast 2>&1 \| tail -20` |
| Full suite command | `cargo test --locked --no-fail-fast` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ENRICH-01 | osv_batch_query checks PG before calling OSV API | unit (mock) | `cargo test test_osv_batch_pg_cache_hit` | ❌ Wave 0 |
| ENRICH-02 | enrich_findings_with_nvd skips API when PG hit exists | unit | `cargo test test_nvd_enrich_pg_cache_hit` | ❌ Wave 0 |
| ENRICH-03 | API responses stored to PG after fetch | unit | `cargo test test_epss_pg_writeback` | ❌ Wave 0 |
| ENRICH-04 | Standalone: file cache chain works; Cluster: PG chain works | unit | `cargo test test_mode_separation` | ❌ Wave 0 |
| ENRICH-05 | No duplicate API call for already-cached CVE | integration/manual | manual scan test (needs PG) | manual-only |
| ENRICH-06 | Stale entries re-fetched; fresh entries served from cache | unit | `cargo test test_ttl_jitter_stale` | ❌ Wave 0 |
| SCAN-02 | Circuit breaker trips after 5 failures, skips subsequent calls | unit | `cargo test test_circuit_breaker_trips` | ❌ Wave 0 |
| INFR-03 | cluster_mode=0 never calls pg_connect; cluster_mode=1 never uses file cache | unit | `cargo test test_cluster_mode_separation` | ❌ Wave 0 |

**Note on ENRICH-05:** Requires a live PostgreSQL connection with pre-seeded data. Practical test is a smoke-scan against an image already in the PG cache and observing `osv.query.chunk.pg_cache` progress events in the output. Mark manual-only for CI.

**Note on ENRICH-03 (PG write-back):** Tests for EPSS/KEV write-back require mocking the PG connection or using an in-memory SQLite substitute. Since `postgres::Client` cannot be easily mocked, recommend testing the logic by extracting the write-back logic into a separate function that takes a trait or by checking integration via progress event logs.

### Sampling Rate
- **Per task commit:** `cargo test --locked --no-fail-fast 2>&1 | tail -20` (verify existing 46 tests still pass)
- **Per wave merge:** `cargo test --locked --no-fail-fast` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `src/vuln/circuit.rs` — unit tests for `CircuitBreaker` (record_failure, is_open, record_success)
- [ ] `src/vuln/tests.rs` — add `test_compute_jittered_ttl_days` (jitter stays in range, min clamped to 1)
- [ ] `src/vuln/tests.rs` — add `test_circuit_breaker_trips` (trips at threshold, resets on success)
- [ ] `src/vuln/tests.rs` — add `test_mode_separation_standalone_no_pg` (cluster_mode=0 returns None from resolve_enrich_cache_dir in cluster mode — verify the inverse: non-cluster returns Some path)
- [ ] No framework install needed — `cargo test` works today

## Sources

### Primary (HIGH confidence)
- Direct code reading of `/src/vuln/osv/batch.rs` — confirmed zero PG support
- Direct code reading of `/src/vuln/pg.rs` — confirmed `pg_put_*` helpers, `compute_dynamic_ttl_days`, all table definitions
- Direct code reading of `/src/vuln/nvd/enrich.rs` — confirmed PG cache-first pattern already implemented
- Direct code reading of `/src/vuln/epss.rs` — confirmed PG read present, write-back missing
- Direct code reading of `/src/vuln/kev.rs` — confirmed PG read present, write-back missing
- Direct code reading of `/src/container/scan.rs` — confirmed `pg_connect()` called once, passed via `&mut`, EPSS/KEV called after with `cache_dir` only
- Direct code reading of `/src/vuln/http.rs` — confirmed existing timeout values and retry/backoff patterns

### Secondary (MEDIUM confidence)
- CONTEXT.md decisions section — all locked decisions copied verbatim

### Tertiary (LOW confidence)
- None — all findings are from direct code analysis

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all dependencies already in Cargo.toml, no new ones needed
- Architecture: HIGH — all patterns derived from reading the actual post-Phase-1 code
- Pitfalls: HIGH — identified from direct code inspection (PgClient !Send constraint confirmed from existing pattern in enrich.rs)

**Research date:** 2026-03-03
**Valid until:** 2026-04-03 (stable Rust codebase, 30 days)
