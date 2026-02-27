# ScanRook CLI

Installed-state-first scanner engine used by the ScanRook platform.

## Commands

```bash
scanrook scan --file ./image.tar --format json --out report.json
scanrook auth login --api-key <API_KEY>
scanrook auth logout
scanrook whoami
scanrook limits
scanrook config set telemetry.opt_in true
```

## Install helper

```bash
./scripts/install-scanrook.sh
```

Compatibility note: `scanner` is kept as a temporary alias and prints a deprecation warning.

## Licensing

Current policy uses a provisional source-available model.
See `LICENSE-SCANROOK-SOURCE-AVAILABLE.md`.

## Cloud enrichment limits

- Local scan logic continues without auth.
- Cloud enrichment is checked via `/api/cli/enrich`.
- On `429`, CLI disables cloud enrichment for the current run and continues local scan.
