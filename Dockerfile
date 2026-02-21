# ---- build stage ----
FROM rust:1.87-slim AS builder
WORKDIR /app

# (optional) proxies
ARG http_proxy
ARG https_proxy
ARG DATABASE_URL
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}
ENV DATABASE_URL=${DATABASE_URL}
ENV SCANNER_NVD_TTL_DAYS=7
ENV SCANNER_NVD_CONC=5
# scanner --progress --progress-file /tmp/scan.ndjson scan --file /Users/devintripp/Downloads/ubuntu-14.04.tar --format json --out /tmp/report.json

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# Cache cargo dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release || true

# Build + install the binary into /usr/local using cargo (single build)
COPY . .
RUN cargo install --path . --root /usr/local --locked

# ---- runtime stage with Node.js ----
FROM node:20-bookworm-slim
WORKDIR /app

# Minimal runtime deps for scanner
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 rpm && \
    rm -rf /var/lib/apt/lists/*

# Copy scanner binary installed in builder
COPY --from=builder /usr/local/bin/scanner /usr/local/bin/scanner
ENV PATH="/usr/local/bin:${PATH}"

# Reasonable defaults; override at runtime
ENV SCANNER_NVD_TTL_DAYS=7 \
    SCANNER_NVD_CONC=5

# Default command runs scanner; downstream images can override CMD easily
CMD ["scanner"]
