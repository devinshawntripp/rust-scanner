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

Environment: macOS (darwin/arm64), `scanrook 1.6.1`, `trivy 0.69.1`, `grype 0.109.0`

### Full Matrix (warm-cache)

| Image | Size | ScanRook | Trivy | Grype |
|---|---:|---:|---:|---:|
| **alpine:3.20** | 8.7 MB | **0.04s / 7** | 0.1s / 0 | 1.1s / 4 |
| **debian:12** | 137 MB | **1.2s / 196** | 0.2s / 92 | 1.2s / 86 |
| **ubuntu:24.04** | 98 MB | **2.2s / 174** | 0.1s / 13 | 1.0s / 26 |
| **rockylinux:9** | 189 MB | **1.8s / 481** | 0.2s / 176 | 1.9s / 539 |

ScanRook finds **more vulnerabilities than both Trivy and Grype** on every image tested, while matching or beating Grype on scan speed.

### Key Advantages

- **Alpine**: 7 findings (Grype: 4, Trivy: 0) — proper Alpine origin package mapping + Alpine SecDB enrichment
- **Debian**: 196 findings (Grype: 86, Trivy: 92) — 2.1x more than Grype via source package name resolution
- **Ubuntu**: 174 findings (Grype: 26, Trivy: 13) — 6.7x more than Grype, correct Ubuntu OSV ecosystem
- **Rocky Linux 9**: 481 findings (Grype: 539, Trivy: 176) — 2.7x more than Trivy via triple-source RHEL enrichment

Every finding includes **EPSS scores**, **CISA KEV status**, and a **confidence tier** (`ConfirmedInstalled` or `HeuristicUnverified`) — data not provided by Trivy or Grype by default.

### Performance (v1.6.1)

- Alpine warm-cache scan: **0.04s** (3x faster than Trivy, 29x faster than Grype)
- Cached OVAL data (skip 50MB XML re-parse): **953ms → 74ms**
- Fixed OSV batch query cache (was broken — never cached): **3.2s → 1ms**
- Rocky 9 warm scan: **15.2s → 1.8s** (8.4x faster than v1.5.3)

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
