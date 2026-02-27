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

## Benchmark Snapshot (Real Run)

Artifact:
- `ubuntu:22.04` saved tar (`benchmark-artifacts/ubuntu-22.04.tar`, ~69MB)

Environment:
- macOS (darwin/amd64)
- `scanrook 1.3.2`
- `trivy 0.69.1`
- `grype 0.109.0`

Results (warm-cache local run):

| Tool | Duration (s) | Total Findings |
|---|---:|---:|
| ScanRook | 0.172 | 33 |
| Trivy | 0.176 | 28 |
| Grype | 1.056 | 34 |

Note:
- ScanRook now defaults to `~/.scanrook/cache` for repeatable warm-cache performance.

Findings graph (relative count):

```text
ScanRook  33 | ██████████████████████████████
Trivy     28 | █████████████████████████
Grype     34 | ███████████████████████████████
```

Duration graph (seconds):

```text
ScanRook  0.172s | █████
Trivy     0.176s | █████
Grype     1.056s | ██████████████████████████████
```

Data source:
- [`docs/benchmarks/reports/ubuntu-22.04/summary.csv`](docs/benchmarks/reports/ubuntu-22.04/summary.csv)
- [`docs/benchmarks/reports/ubuntu-22.04/scanrook.json`](docs/benchmarks/reports/ubuntu-22.04/scanrook.json)
- [`docs/benchmarks/reports/ubuntu-22.04/trivy.json`](docs/benchmarks/reports/ubuntu-22.04/trivy.json)
- [`docs/benchmarks/reports/ubuntu-22.04/grype.json`](docs/benchmarks/reports/ubuntu-22.04/grype.json)
- [`docs/benchmarks/reports/ubuntu-22.04/diff-vs-trivy.json`](docs/benchmarks/reports/ubuntu-22.04/diff-vs-trivy.json)
- [`docs/benchmarks/reports/ubuntu-22.04/diff-vs-grype.json`](docs/benchmarks/reports/ubuntu-22.04/diff-vs-grype.json)

Reproduce:

```bash
SCANNER_NVD_ENRICH=0 SCANNER_OSV_ENRICH=0 SCANNER_REDHAT_ENRICH=0 \
  scanrook benchmark \
  --file ./benchmark-artifacts/ubuntu-22.04.tar \
  --out-dir ./docs/benchmarks/reports/ubuntu-22.04 \
  --profile warm

scanrook diff \
  --ours ./docs/benchmarks/reports/ubuntu-22.04/scanrook.json \
  --against ./docs/benchmarks/reports/ubuntu-22.04/trivy.json \
  --out ./docs/benchmarks/reports/ubuntu-22.04/diff-vs-trivy.json
```

Cleanup benchmark tools after run:

```bash
brew uninstall trivy grype
```

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

Current active vulnerability sources in ScanRook:

- OSV API (`osv`)
- NVD CVE API (`nvd`)
- Red Hat Security Data API (`redhat`)
- Optional user-supplied Red Hat OVAL XML (`redhat_oval`)

Roadmap sources are exposed via `scanrook db sources` and currently include Ubuntu CVE Tracker, Debian Security Tracker, and Alpine SecDB.

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
