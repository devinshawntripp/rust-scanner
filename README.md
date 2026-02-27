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

## Commands

```bash
scanrook scan --file ./image.tar --format json --out report.json
scanrook auth login --api-key <API_KEY>
scanrook auth logout
scanrook whoami
scanrook limits
scanrook config set telemetry.opt_in true
```

Compatibility note: `scanner` remains as a temporary alias and prints a deprecation warning.

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
- Distribution/launch playbook: `docs/marketing/launch-pack.md`
- Launch post draft: `docs/marketing/launch-blog-draft.md`
- Package manager publishing runbook: `docs/distribution/package-managers.md`
- Local comparison helper script: `scripts/benchmark-compare.sh`

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
