# ScanRook CLI

[![GitHub release](https://img.shields.io/github/v/release/devinshawntripp/rust-scanner)](https://github.com/devinshawntripp/rust-scanner/releases)
[![CI](https://github.com/devinshawntripp/rust-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/devinshawntripp/rust-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Source--Available-blue)](LICENSE-SCANROOK-SOURCE-AVAILABLE.md)

Local-first container image scanner with optional cloud enrichment.

Scan locally first. Add cloud enrichment only when you want deeper context and org workflows.

## Quickstart (under 60 seconds)

```bash
curl -fsSL https://scanrook.sh/install | bash
scanrook scan --file ./image.tar --format text
scanrook scan --file ./image.tar --format json --out report.json
```

Optional cloud auth:

```bash
scanrook auth login --base https://scanrook.io
scanrook limits
```

## Why ScanRook

- Local-first by default: scans run without mandatory cloud auth.
- Installed-state-first approach: prioritize package inventory evidence.
- Cloud enrichment is additive: better context without blocking local scans.
- Freemium-friendly: local scan stays available even when enrichment rate limits are reached.

## Terminal Demo

```bash
scanrook scan --file ./image.tar --mode deep --format json --out report.json
```

Demo GIF will be added in `docs/assets/scanrook-demo.gif` during beta content rollout.

## Comparison (high level)

| Capability | ScanRook | Trivy | Grype | Syft | Snyk Container | Docker Scout |
|---|---|---|---|---|---|---|
| Local-first CLI workflow | Yes | Yes | Yes | Yes (SBOM-focused) | Partial | Partial |
| Optional cloud enrichment | Yes | Partial | Partial | No | Yes | Yes |
| Installed-state-first positioning | Yes | Partial | Partial | No | Partial | Partial |
| Org workflows (history, teams, policies) | Yes (platform) | Partial | No | No | Yes | Yes |

Notes:
- This table is positioning-level and should be backed by benchmarks for strict feature parity claims.
- Benchmark report is planned in the launch content track.

## Benchmark Results

Environment: macOS (darwin/arm64), `scanrook 1.6.0`, `trivy 0.69.1`, `grype 0.109.0`

### Full Matrix (warm-cache)

| Image | Size | ScanRook | Trivy | Grype |
|---|---:|---:|---:|---:|
| **rockylinux:9** | 189 MB | **1.8s / 481** | 0.2s / 176 | 1.7s / 539 |
| **ubuntu:24.04** | 98 MB | 1.2s / 17 | 0.1s / 13 | 1.1s / 26 |
| **debian:12** | 137 MB | 1.3s / 18 | 0.2s / 92 | 1.3s / 86 |
| **alpine:3.20** | 8.7 MB | 3.9s / 0 | 0.1s / 0 | 1.2s / 4 |

### Where ScanRook Excels: RHEL/Rocky Coverage

ScanRook finds **2.7x more CVEs** than Trivy on Rocky Linux 9 by combining three enrichment sources:

1. **OSV batch queries** — broad ecosystem coverage
2. **Red Hat OVAL** — patch-level version comparison for fixable CVEs
3. **Red Hat Security Data API** — surfaces unfixed CVEs (will-not-fix, fix-deferred, affected)

Trivy only finds 176 findings (fixable CVEs). Grype finds 539 (including unfixed). ScanRook finds 481 with strict RHEL-9-version-specific validation — avoiding the false positives that push Grype's count higher.

Every ScanRook finding includes **EPSS scores**, **CISA KEV status**, and a **confidence tier** (`ConfirmedInstalled` or `HeuristicUnverified`) for prioritization — data not provided by Trivy or Grype by default.

### Performance (v1.6.0)

Warm-cache scan times are competitive with Grype and significantly faster than cold scans:

- Cached OVAL data (skip 50MB XML re-parse): **953ms → 74ms**
- Parallel cache reads via rayon: **1256ms → 399ms**
- Deterministic EPSS batch cache keys: **700ms → 0ms**
- Rocky 9 total scan: **15.2s → 1.8s** (8.4x faster than v1.5.3)

### Reproduce

```bash
scanrook benchmark \
  --file ./image.tar \
  --out-dir ./benchmark-out \
  --profile warm
```

Full reports: [`docs/benchmarks/reports/`](docs/benchmarks/reports/)

## Commands

```bash
scanrook scan --file ./image.tar --format json --out report.json
scanrook scan --file ./image.tar --mode deep --progress --log-format text --log-level info
scanrook scan --file ./image.tar --mode deep --progress --log-format json --log-level debug
scanrook benchmark --file ./image.tar --out-dir ./benchmark-out --profile warm
scanrook diff --ours ./scanrook.json --against ./trivy.json --out ./diff.json
scanrook db sources
scanrook db status
scanrook db check
scanrook db update --source all
scanrook db update --source nvd --cve CVE-2021-25219
scanrook db update --source redhat --cve CVE-2021-25219 --errata RHSA-2022:8162
scanrook db clear
scanrook db download --file ./image.tar --mode deep
scanrook db warm --file ./image.tar --mode deep
scanrook auth login --api-key <API_KEY>
scanrook auth logout
scanrook whoami
scanrook limits
scanrook config set telemetry.opt_in true
```

Compatibility note: `scanner` remains as a temporary alias and prints a deprecation warning.

## Data Sources

Active vulnerability and enrichment sources:

- OSV API (`osv`) — 10+ ecosystems including npm, PyPI, Go, Maven, crates.io
- NVD CVE API (`nvd`) — CVSS scoring and CPE matching
- Red Hat Security Data API (`redhat`) — RHEL-specific fix information
- Red Hat OVAL XML (`redhat_oval`) — Optional user-supplied OVAL data
- EPSS (`epss`) — Exploit prediction scores from FIRST.org
- CISA KEV (`kev`) — Known Exploited Vulnerabilities catalog
- Alpine SecDB — Alpine Linux security advisories
- Ubuntu CVE Tracker, Debian Security Tracker

Supported container ecosystems: Ubuntu, Debian, Alpine, RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Amazon Linux, Oracle Linux, Chainguard, Wolfi

## Logging

Progress events are stage-driven and machine-readable (`stage`, `detail`, `ts`) for worker/UI ingestion.

- `--progress` enables stderr log output.
- `--log-format text|json` controls stderr style.
- `--log-level error|warn|info|debug` controls stderr verbosity.
- `--progress-file` always writes NDJSON event lines for workflow consumption.

## Release Artifacts

Each release should include:

- `scanrook-<version>-linux-amd64.tar.gz`
- `scanrook-<version>-linux-arm64.tar.gz`
- `scanrook-<version>-darwin-amd64.tar.gz`
- `scanrook-<version>-darwin-arm64.tar.gz`
- `scanrook-<version>-checksums.txt`

Install script expects GitHub release assets in this exact format.

## CI/CD Example (GitHub Actions)

Marketplace-style action (this repo):

```yaml
- name: Scan artifact
  uses: devinshawntripp/rust-scanner@v1
  with:
    artifact_path: app-image.tar
    mode: deep
    format: json
    out_file: scanrook-report.json
    api_key: ${{ secrets.SCANROOK_API_KEY }}
```

Full guide: `docs/guides/github-actions.md`

```yaml
name: scanrook
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ScanRook
        run: curl -fsSL https://scanrook.sh/install | bash
      - name: Scan image tar
        run: scanrook scan --file ./artifact.tar --mode deep --format json --out report.json
```

## Benchmarks and Launch Docs

- Benchmark methodology + reproducibility: `docs/benchmarks/README.md`
- Package manager publishing runbook: `docs/distribution/package-managers.md`
- Local comparison helper script: `scripts/benchmark-compare.sh`
- Public launch post: [https://scanrook.io/blog/why-we-built-scanrook](https://scanrook.io/blog/why-we-built-scanrook)

## Cloud Enrichment Limits

- Local scan logic continues without auth.
- Cloud enrichment is checked via `/api/cli/enrich`.
- On `429`, CLI continues local scan and returns upgrade context.

## Distribution Status

- GitHub Releases: active.
- Install script (`scanrook.sh/install`): active.
- Homebrew tap: planned.
- crates.io package: planned.

## Platform

- Website: [scanrook.sh](https://scanrook.sh)
- Dashboard/API: [scanrook.io](https://scanrook.io)

## License

Current policy uses a provisional source-available model.
See `LICENSE-SCANROOK-SOURCE-AVAILABLE.md`.
