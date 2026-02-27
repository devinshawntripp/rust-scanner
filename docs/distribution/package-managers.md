# Package Manager Distribution Runbook

This runbook covers publishing ScanRook to common install channels.

## 1) GitHub Releases (source of truth)

Required assets per version:

- `scanrook-<version>-linux-amd64.tar.gz`
- `scanrook-<version>-linux-arm64.tar.gz`
- `scanrook-<version>-darwin-amd64.tar.gz`
- `scanrook-<version>-darwin-arm64.tar.gz`
- `scanrook-<version>-checksums.txt`

Tag format: `v<version>` (example: `v1.3.1`).

## 2) Homebrew (tap)

Recommended:

1. Create `scanrook/homebrew-tap` repo.
2. Add formula `Formula/scanrook.rb`.
3. Pull checksums from release assets.
4. Test install:

```bash
brew tap scanrook/tap
brew install scanrook
scanrook --version
```

## 3) crates.io

Current package name in `Cargo.toml` is `scanner`. If publishing to crates.io,
choose one:

1. Keep crate package as `scanner` and document `cargo install scanner`.
2. Rename package to `scanrook` before publishing for name parity.

Publish:

```bash
cargo login <CRATES_IO_TOKEN>
cargo publish
```

## 4) Docker Hub

Publish a CLI image for CI:

```bash
docker build -t scanrook/scanrook-cli:<version> .
docker push scanrook/scanrook-cli:<version>
docker tag scanrook/scanrook-cli:<version> scanrook/scanrook-cli:latest
docker push scanrook/scanrook-cli:latest
```

## 5) Validation Checklist

1. Install from `scanrook.sh/install`.
2. Install from Homebrew.
3. Pull and run Docker image.
4. Verify checksums and signatures in release notes.
