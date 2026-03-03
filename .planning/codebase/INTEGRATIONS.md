# External Integrations

**Analysis Date:** 2026-03-02

## APIs & External Services

**Open Source Vulnerabilities (OSV):**
- Service: Open Source Vulnerability Database
- API: `https://api.osv.dev/v1/querybatch` (batch endpoint), `https://api.osv.dev/v1/query` (single)
- Method: POST JSON with package ecosystem, name, version
- SDK/Client: `reqwest::blocking::Client`
- Auth: None (public)
- Rate limiting: Configurable batch size (default: 50), backoff on failure
- Caching: File cache (SHA256 keyed), PostgreSQL `osv_vuln_cache`, Redis (optional)
- Files: `src/vuln/osv.rs`

**National Vulnerability Database (NVD):**
- Service: NIST NVD CVE metadata
- APIs:
  - `/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=` - Keyword search
  - `/rest/json/cves/2.0?cveId={}` - Exact CVE lookup
  - `/rest/json/cves/2.0?cpeName={}` - CPE exact match
- Base URL: `https://services.nvd.nist.gov`
- Auth: Optional `NVD_API_KEY` env var (400ms rate limit vs 6s without)
- Rate limiting:
  - 400ms sleep (with key) or 6000ms (without) via `SCANNER_NVD_SLEEP_MS`
  - Exponential backoff with jitter on 5xx errors
  - Optional Redis-backed global rate limit via `SCANNER_NVD_GLOBAL_RATE_PER_MINUTE`
  - Separate scope per API key (SHA256 digest)
- Caching: File cache, PostgreSQL `nvd_cve_cache`, Redis
- Timeout: 20s (override: `SCANNER_NVD_TIMEOUT_SECS`)
- Files: `src/vuln/nvd.rs`, `src/vuln/http.rs`

**Exploit Prediction Scoring System (EPSS):**
- Service: First.org EPSS API
- API: `https://api.first.org/data/v1/epss?cve=<comma-separated IDs>`
- Method: GET with CVE IDs
- Auth: None
- Caching: File cache, PostgreSQL `epss_scores_cache`
- Files: `src/vuln/epss.rs`

**CISA Known Exploited Vulnerabilities (KEV):**
- Service: CISA KEV catalog
- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Method: GET JSON download
- Auth: None
- Caching: Full catalog cached as HashSet (24h TTL), PostgreSQL `kev_entries_cache`
- Files: `src/vuln/kev.rs`

**Red Hat Security Data APIs:**
- Service: Red Hat CVE and security advisory data
- APIs:
  - `https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json` - CVE details
  - `https://access.redhat.com/hydra/rest/securitydata/cve.json?package={package}&per_page=10000` - Per-package CVE list
  - `https://access.redhat.com/hydra/rest/securitydata/csaf/{errata_id}.json?isCompressed=false` - CSAF advisory
- Auth: None
- Caching: PostgreSQL `redhat_cve_cache`, `redhat_csaf_cache`, `rhel_cves` (per-package accumulation)
- Parallelization: Rayon for parallel per-package list fetching
- Files: `src/vuln/redhat_enrich.rs`, `src/vuln/pg.rs`

**Debian Security Tracker:**
- Service: Debian DSA vulnerability data
- APIs:
  - `https://security-tracker.debian.org/tracker/data/json` - Full Debian tracker
  - `https://security-tracker.debian.org/tracker/{cve_id}` - CVE details page
- Auth: None
- Caching: File cache, PostgreSQL `debian_tracker_cache`
- Files: `src/vuln/distro.rs`, `src/vuln/debian_legacy.rs`

**Ubuntu Security Notices:**
- Service: Canonical USN (Ubuntu Security Notices)
- API: `https://ubuntu.com/security/notices.json`
- Method: GET JSON
- Auth: None
- Caching: File cache, PostgreSQL `ubuntu_usn_cache`
- Files: `src/vuln/distro.rs`

**Alpine Linux Security Database:**
- Service: Alpine SecDB vulnerability data
- API: `https://secdb.alpinelinux.org/{branch}/{repo}.json`
- Example: `https://secdb.alpinelinux.org/v3.20/main.json`
- Auth: None
- Caching: File cache, PostgreSQL `alpine_secdb_cache`
- Files: `src/vuln/distro.rs`

## Data Storage

**Databases:**

**PostgreSQL (Optional - Distributed CVE Cache):**
- Purpose: Shared vulnerability enrichment cache across worker replicas
- Connection: `SCANROOK_ENRICHMENT_DATABASE_URL` or `DATABASE_URL`
- Client: `postgres` crate (0.19) with `NoTls`
- Tables created by `pg_init_schema()`:
  - `nvd_cve_cache` - NVD CVE metadata (cve_id PK, payload JSONB, timestamps)
  - `osv_vuln_cache` - OSV vulnerabilities (vuln_id PK, payload JSONB, timestamps)
  - `redhat_cve_cache` - Red Hat CVE details (cve_id PK, payload JSONB, timestamps)
  - `redhat_csaf_cache` - Red Hat CSAF advisories (errata_id PK, payload JSONB, timestamps)
  - `rhel_cves` - RHEL per-package CVE state (cve_id, package, rhel_version PK, state/fix_state)
  - `epss_scores_cache` - EPSS scores (cve_id PK, score REAL, percentile REAL)
  - `kev_entries_cache` - CISA KEV list (cve_id PK)
  - `debian_tracker_cache` - Debian DSA (cve_id, package, release PK)
  - `ubuntu_usn_cache` - Ubuntu USN (cve_id, package, release PK)
  - `alpine_secdb_cache` - Alpine SecDB (cve_id, package, branch, repo PK)
- Files: `src/vuln/pg.rs` (connection, schema init), `src/vuln/nvd.rs`, `src/vuln/osv.rs`, etc.

**SQLite (Local Vulnerability Database):**
- Purpose: Fast offline/local CVE lookups without network
- Location: `~/.scanrook/db/scanrook.db` (override: `SCANROOK_DB`)
- Client: `rusqlite` crate (bundled sqlite3)
- Built via: `scanrook db build` (from OSV, NVD, EPSS, KEV, Debian, Ubuntu, Alpine sources)
- Downloaded via: `scanrook db fetch` (from ScanRook cloud API)
- Compression: Zstandard (zstd) with dictionary compression for JSON payloads (schema v2)
- Tables:
  - `osv_packages` - Tracked packages (ecosystem, name)
  - `osv_vulns` - OSV vulns index (id, ecosystem, name, modified)
  - `osv_payloads` - OSV JSON payloads (id PK, payload BLOB zstd-compressed)
  - `nvd_cves` - NVD CVEs (cve_id PK, payload BLOB zstd-compressed, last_modified)
  - `epss_scores` - EPSS (cve_id PK, score REAL, percentile REAL)
  - `kev_entries` - KEV (cve_id PK)
  - `debian_tracker`, `ubuntu_usn`, `alpine_secdb` - Distro-specific metadata
  - `metadata` - Schema version, build date, zstd dictionaries
- Files: `src/vulndb.rs` (open, query, schema), `src/cli/db.rs` (fetch, build, seed)

**Redis (Distributed Rate Limiting):**
- Purpose: Global NVD request rate limiting across worker fleet
- Connection: `SCANNER_REDIS_URL` or `REDIS_URL`
- Client: `redis` crate (0.27)
- Key pattern: `scanner:nvd:rate:{scope}:{minute}` (scope = API key hash or "anon")
- Operations: INCR per minute, EXPIRE 70s
- Fallback: If Redis unavailable, rate limiting is skipped
- Files: `src/vuln/http.rs`

## Authentication & Identity

**API Keys:**
- NVD API Key: Via `NVD_API_KEY` env var (faster rate limit)
- ScanRook API Key: Via `SCANROOK_API_KEY` env var or `~/.scanrook/config.json`
- Auth headers: User-Agent format `scanrook-cli/{version}`

**Auth Provider:**
- None for public APIs (OSV, NVD, Red Hat, Debian, Ubuntu, Alpine, EPSS, KEV, CISA)
- ScanRook cloud: Implicit via API key header
- PostgreSQL: Standard connection string auth
- Redis: Optional password in connection string

**Config File:**
- Location: `~/.scanrook/config.json` (override: `SCANROOK_CONFIG`)
- Fields: `api_base` (ScanRook endpoint), `api_key`, `telemetry_opt_in`
- Persistence: `save_config()` in `src/usercli.rs`

## Monitoring & Observability

**Error Tracking:**
- None (no integration)

**Logs:**
- Stderr: Progress events (NDJSON-formatted) when `--progress` flag set
- File: NDJSON progress file via `--progress-file` (consumed by Go worker for SSE streaming)
- Format: `{stage, detail, ts, level, component}` JSON objects
- Control: `--log-format` (text|json), `--log-level` (error|warn|info|debug)
- Files: `src/progress.rs`, `src/utils.rs`

## CI/CD & Deployment

**Hosting:**
- Kubernetes cluster (home lab, 3 nodes)
- Worker pods with shared PostgreSQL
- Entrypoint: Downloads `scanrook` binary at startup (via internal download mechanism)

**CI Pipeline:**
- GitHub Actions: `.github/workflows/` (build, test, release)
- Build: `cargo build --locked`, `cargo test --locked --no-fail-fast`
- Release: Tag `vX.Y.Z`, regenerate `Cargo.lock`, push

**Deployment Artifacts:**
- Linux binary: `scanrook-linux-amd64` (x86-64)
- Docker image: Multi-stage, published to registry
- S3/MinIO: Latest release available via CDN

## Environment Configuration

**Required env vars (by feature):**
- PostgreSQL caching: `SCANROOK_ENRICHMENT_DATABASE_URL` or `DATABASE_URL`
- Redis rate limiting: `SCANNER_REDIS_URL` or `REDIS_URL`
- NVD enrichment: `NVD_API_KEY` (optional, improves rate limit)
- ScanRook API: `SCANROOK_API_KEY` (for cloud features)

**Secrets location:**
- `NVD_API_KEY` - GitHub Actions secrets, K8s secret, local env
- `SCANROOK_API_KEY` - `~/.scanrook/config.json` (local) or env var
- `DATABASE_URL` - K8s secret `scanrook-secrets`
- `REDIS_URL` - K8s secret `scanrook-secrets`

**Optional configs:**
- Cache dir: `SCANNER_CACHE` (default: `~/.scanrook/cache`)
- SQLite path: `SCANROOK_DB` (default: `~/.scanrook/db/scanrook.db`)
- Log settings: `SCANNER_LOG_FORMAT`, `SCANNER_LOG_LEVEL`
- NVD tuning: `SCANNER_NVD_TIMEOUT_SECS`, `SCANNER_NVD_SLEEP_MS`, `SCANNER_NVD_RETRY_MAX`
- OSV tuning: `SCANNER_OSV_BATCH_SIZE`, `SCANNER_OSV_TIMEOUT_SECS`

## Webhooks & Callbacks

**Incoming:**
- None (scanner is a CLI tool, not a server)

**Outgoing:**
- None (scanner is stateless; output goes to stdout/file, progress to stderr/file)

## Network & Protocol Details

**HTTP Client Configuration:**
- Blocking HTTP client via `reqwest::blocking::Client`
- Timeout: 20s for NVD (override: `SCANNER_NVD_TIMEOUT_SECS`), 30s for others
- IPv4 forced by default (Kubernetes homelab limitation): `SCANNER_FORCE_IPV4` = true
- TLS: Rustls (no OpenSSL dependency)
- User-Agent: `scanrook/{version}`

**Rate Limiting Strategy:**
1. **File cache check** - SHA256 keyed, fast local miss check
2. **PostgreSQL cache check** - Shared across workers, TTL-based expiration
3. **Redis rate limiting** - Global request throttle per API key (only NVD)
4. **Polite sleep** - Deterministic delay between requests (400ms with key, 6s without)
5. **Exponential backoff** - On 5xx errors, jittered up to 7 doublings

---

*Integration audit: 2026-03-02*
