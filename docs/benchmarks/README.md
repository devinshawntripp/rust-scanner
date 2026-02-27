# Benchmark Pack: ScanRook vs Trivy vs Grype

This pack is for public, reproducible comparison content.

## Goal

Show:

- Scan duration
- Finding counts
- Resource profile (optional extension)

for the same local artifact across tools.

## Inputs

Use at least:

1. A medium container image tar (`~300MB`)
2. A large enterprise image tar (`~1GB+`)
3. One RHEL-derived image tar (for applicability discussion)

## Run

```bash
chmod +x scripts/benchmark-compare.sh
./scripts/benchmark-compare.sh ./artifacts/image.tar ./benchmark-out
```

Outputs:

- `benchmark-out/summary.csv`
- `benchmark-out/scanrook.json`
- `benchmark-out/trivy.json`
- `benchmark-out/grype.json`

## Publish Checklist

1. Include hardware/runner details (`CPU`, `RAM`, `OS`).
2. Include exact tool versions (`scanrook --version`, `trivy --version`, `grype version`).
3. Run at least 3 times and report median.
4. State cache behavior (cold vs warm).
5. Share raw JSON artifacts and summary CSV in the blog/repo.

## Claim Boundaries

- Do not claim “better detection” from one run.
- Treat findings counts as signal, not absolute truth.
- Emphasize ScanRook’s installed-state-first + confidence tier model.
