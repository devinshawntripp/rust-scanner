# Launch Pack (Track 4 Distribution)

This is the execution pack for first public distribution.

## 1) Channels

Primary:

- LinkedIn (founder + company page)
- Blog on `scanrook.sh`
- Dev.to (cross-post)

Secondary:

- Hacker News (`Show HN`)
- Reddit (`r/rust`, `r/devops`, `r/netsec`, `r/docker`) with technical framing

## 2) First 3 Posts

1. Why ScanRook exists (local-first + cloud enrichment model)
2. ScanRook vs Trivy/Grype benchmark (with raw data)
3. GitHub Actions integration guide

Each post should have one CTA:

- “Install CLI” (`curl -fsSL https://scanrook.sh/install | bash`)
- or “Start pilot” (`https://scanrook.io/signin`)

## 3) GitHub Action Marketplace Prep

Checklist:

1. Keep `action.yml` stable at repo root.
2. Tag release (`v1.x.y`) after smoke workflow passes.
3. Add release notes with usage snippet.
4. Submit/verify listing in Actions marketplace.

## 4) Outreach Message Template

```
We built ScanRook for teams that want local-first image scanning with optional cloud enrichment.
No forced cloud upload to start, and findings include confidence/evidence context.
Would you be open to a 20-minute pilot walkthrough?
```

## 5) Weekly Cadence

- 2 technical posts/month
- 1 case study/month
- 20 direct outreach messages/week
- 1 benchmark refresh/month

## 6) Success Metrics (Beta)

- Installer conversion: visits -> install command runs
- Activation: installs -> first successful scan
- Product interest: scans -> sign-in/pilot requests
- Pipeline: meetings booked/week
