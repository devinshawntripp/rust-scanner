# Technology Stack

**Analysis Date:** 2026-03-02

## Languages

**Primary:**
- Rust 2021 edition - CLI scanner binary (main scanning engine)

**Secondary:**
- YAML - Policy files for SBOM policy checks (`src/sbom.rs` uses `serde_yaml`)

## Runtime

**Environment:**
- Linux (x86_64, aarch64) - Primary deployment target
- Docker runtime via multi-stage build (`Dockerfile`)

**Package Manager:**
- Cargo 1.88+
- Lockfile: `Cargo.lock` (committed)

## Frameworks & Core Libraries

**CLI Framework:**
- Clap 4.4 - Command-line argument parsing with derive macros
- Entry point: `src/main.rs` with subcommands: `scan`, `bin`, `container`, `source`, `license`, `vuln`, `redhat`, `auth`, `db`, `benchmark`, `diff`, `sbom`

**Scanning & Analysis:**
- Goblin 0.7 - Binary parsing (ELF/PE/Mach-O)
- Tar 0.4, Bzip2 0.4, Flate2 1.0 - Archive extraction
- Zip 8.1 - ZIP file handling
- Zstd 0.13 - Zstandard compression (dictionary-based payload compression in SQLite)
- Yara 0.21 (optional feature) - Malware/pattern matching for deep scans

**Vulnerability Databases:**
- Rusqlite 0.31 - SQLite with bundled sqlite3
- PostgreSQL 0.19 - PostgreSQL client (no ORM; raw `postgres` crate)
- Redis 0.27 - Rate limiting and distributed caching

**HTTP & Networking:**
- Reqwest 0.11 - Blocking HTTP client with JSON serialization
- Rustls TLS - No OpenSSL dependency

**Data Processing:**
- Serde 1.0 + Serde_json 1.0 - JSON serialization
- Serde_yaml 0.9.34 - YAML parsing for policies
- Chrono 0.4 - Date/time with clock feature
- Regex 1.10 - Pattern matching
- Rayon 1.10 - Data parallelization (per-package CVE list fetching)

**Utilities:**
- SHA2 0.10 - SHA256 hashing (cache keys, file integrity)
- CVSS 2.2 - CVSS score parsing
- URLEncoding 2.1 - URL parameter encoding
- Anyhow 1.0 - Error handling
- Walkdir 2.5 - Directory traversal
- Tempfile 3.10 - Temporary directory creation
- Memmap2 0.9 - Memory-mapped file I/O (binary scanning)
- Rand 0.8 - Random number generation (backoff jitter)
- XMLTree 0.10 - XML parsing (Red Hat OVAL)
- XMLTree 0.10 - XML parsing (Red Hat OVAL XML CVE definitions)

## Key Dependencies

**Critical:**
- `postgres` 0.19 - Distributed CVE cache across workers
- `redis` 0.27 - Global NVD rate limiting per API key scope
- `rusqlite` 0.31 - Fast local SQLite vuln database (offline scans, fallback)

**Infrastructure:**
- `reqwest` 0.11 - All external API calls (OSV, NVD, Red Hat, Debian, Ubuntu, Alpine, EPSS, KEV, CISA)
- `chrono` 0.4 - Timestamp parsing for last-modified checks
- `rayon` 1.10 - Parallel fetching of per-package Red Hat CVE lists

## Configuration

**Environment Variables:**
- `SCANNER_CACHE` - Override cache directory (default: `~/.scanrook/cache`)
- `SCANNER_SKIP_CACHE` - Disable file caching (`1`/`true`/`yes`/`on`)
- `SCANROOK_DB` - Override SQLite vulndb path (default: `~/.scanrook/db/scanrook.db`)
- `SCANROOK_ENRICHMENT_DATABASE_URL` or `DATABASE_URL` - PostgreSQL connection for caching
- `SCANNER_PG_SCHEMA` - PostgreSQL schema override (or via URL `?schema=...`)
- `SCANNER_REDIS_URL` or `REDIS_URL` - Redis connection for rate limiting
- `NVD_API_KEY` - National Vulnerability Database API key (400ms rate limit vs 6s without)
- `SCANNER_NVD_TIMEOUT_SECS` - NVD request timeout (default: 20s)
- `SCANNER_NVD_SLEEP_MS` - Polite sleep between NVD requests (400ms with key, 6000ms without)
- `SCANNER_NVD_TTL_DAYS` - Cache TTL for NVD CVEs (default: 7 days)
- `SCANNER_NVD_RETRY_MAX` - NVD request retries (default: 5)
- `SCANNER_NVD_RETRY_BASE_MS` - Exponential backoff base (default: 500ms)
- `SCANNER_NVD_CONC` - NVD batch concurrency (default: 5)
- `SCANNER_OSV_BATCH_SIZE` - OSV batch query size (default: 50)
- `SCANNER_OSV_RETRIES` - OSV retry count (default: 3)
- `SCANNER_OSV_BACKOFF_MS` - OSV backoff base (default: 500ms)
- `SCANNER_OSV_TIMEOUT_SECS` - OSV timeout (default: 60s)
- `SCANNER_FORCE_IPV4` - Force IPv4 for outbound requests (default: true)
- `SCANNER_LOG_FORMAT` - Log format: `text` or `json`
- `SCANNER_LOG_LEVEL` - Log verbosity: `error`, `warn`, `info`, `debug`
- `SCANNER_NVD_ENRICH` - Enable NVD enrichment (default: true)
- `SCANNER_OSV_ENRICH` - Enable OSV enrichment (default: true)
- `SCANNER_NVD_SKIP_FULLY_ENRICHED` - Skip refetching CVEs with full enrichment (default: true)
- `SCANNER_REDHAT_UNFIXED_SKIP` - Disable Red Hat unfixed CVE queries (set to `1` to skip)
- `SCANROOK_ENRICHMENT_DATABASE_URL` - Explicit enrichment DB (overrides `DATABASE_URL`)
- `SCANROOK_API_BASE` - ScanRook cloud API base URL (default: `https://scanrook.io`)
- `SCANROOK_API_KEY` - API key for cloud features
- `SCANROOK_CONFIG` - Config file path (default: `~/.scanrook/config.json`)
- `SCANROOK_CLUSTER_MODE` - Enable cluster-wide PostgreSQL caching (default: auto-detect via `DATABASE_URL`)

**Build Configuration:**
- `Cargo.toml` - Package manifest with version 1.9.1, dependencies, optional features
- `Cargo.lock` - Pinned dependencies for reproducible builds
- `Dockerfile` - Multi-stage build: Rust builder → Node.js runtime (for worker integration)

## Platform Requirements

**Development:**
- Rust 1.88+
- Cargo
- libssl-dev / libssl3 (TLS support)
- libarchive-tools (for bsdtar in container extraction)
- rpm library (for RPM package parsing)
- ca-certificates (for TLS)

**Production:**
- Linux kernel with glibc/musl support
- ca-certificates (TLS validation)
- libssl3 (TLS runtime)
- rpm library (RPM scanning)
- libarchive-tools (archive extraction)
- Optional: system libyara (for YARA feature)

**Deployment:**
- Kubernetes cluster with PostgreSQL (CNPG) for shared CVE cache
- Redis for distributed rate limiting
- S3/MinIO for artifact storage (integration via Go worker, not scanner itself)

---

*Stack analysis: 2026-03-02*
