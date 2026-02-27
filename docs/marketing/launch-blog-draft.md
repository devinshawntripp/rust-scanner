# Draft: Why We Built ScanRook

Most container scanners force a cloud-first workflow or overload teams with findings they cannot trust quickly.
We built ScanRook to start local, stay fast, and add cloud enrichment only when you need it.

## The Problem

Security teams face three recurring issues:

1. Too many findings with unclear applicability.
2. Slow, opaque scan workflows.
3. Friction to adopt in developer pipelines.

## Our Approach: Local-First + Cloud Enrichment

ScanRook separates concerns:

- Local scan engine runs without mandatory cloud auth.
- Cloud enrichment adds extra context, org workflows, and scaling controls.

You can run:

```bash
curl -fsSL https://scanrook.sh/install | bash
scanrook scan --file ./image.tar --mode deep --format json --out report.json
```

and get results immediately.

## What Makes ScanRook Different

1. Installed-state-first model.
2. Confidence tiering for findings (confirmed vs heuristic).
3. Workflow visibility from queue to completion.
4. API and org controls for teams that need managed operations.

## Where We’re Going

Next launch milestones:

- Reproducible benchmark reports vs common tools.
- CI integrations (GitHub Actions first).
- Expanded distribution (Homebrew, crates.io, Docker).

## CTA

Try it locally:

```bash
curl -fsSL https://scanrook.sh/install | bash
```

Then sign in for cloud workflows:

- [https://scanrook.io/signin](https://scanrook.io/signin)
