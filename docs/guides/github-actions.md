# GitHub Actions Integration

Use the ScanRook GitHub Action from this repository:

```yaml
uses: devinshawntripp/rust-scanner@v1
```

## Example Workflow

```yaml
name: scanrook
on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create sample artifact (replace with real build output)
        run: tar -cf app-image.tar Dockerfile

      - name: Run ScanRook
        id: scan
        uses: devinshawntripp/rust-scanner@v1
        with:
          artifact_path: app-image.tar
          mode: deep
          format: json
          out_file: scanrook-report.json
          refs: true
          api_base: https://scanrook.io
          api_key: ${{ secrets.SCANROOK_API_KEY }}

      - name: Upload report
        if: ${{ steps.scan.outputs.report_path != '' }}
        uses: actions/upload-artifact@v4
        with:
          name: scanrook-report
          path: ${{ steps.scan.outputs.report_path }}
```

## Inputs

- `artifact_path` (required)
- `mode` (`light|deep`, default `deep`)
- `format` (`json|text`, default `json`)
- `out_file` (default `scanrook-report.json`)
- `refs` (`true|false`, default `true`)
- `version` (`latest` or release version)
- `api_base` (default `https://scanrook.io`)
- `api_key` (optional secret)

## Outputs

- `report_path`: populated for `format=json`.

## Notes

- Without `api_key`, local scan still runs.
- If enrichment is rate-limited, scan continues local mode.
- Pin to tagged versions (`@v1` or exact tag) for stable CI behavior.
