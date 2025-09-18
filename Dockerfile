# ---- build stage ----
FROM rust:1.83-slim AS builder
WORKDIR /app

# (optional) proxies
ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# cache deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release && rm -rf target/release/deps/scanner*

# real source & build
COPY . .
RUN cargo build --release

# ---- runtime stage ----
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/scanner /app/scanner
ENTRYPOINT ["/app/scanner"]
