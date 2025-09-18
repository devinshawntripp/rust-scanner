FROM rust:1.81-slim AS builder

# Set up proxy for builds (optional)
ENV http_proxy=http://10.10.10.2:3128
ENV https_proxy=http://10.10.10.2:3128

# deps for reqwest default-tls; add build-essential for native crates
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# cache deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release && rm -rf target/release/deps/scanner*

# real source
COPY . .
RUN cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/scanner /app/scanner
ENTRYPOINT ["/app/scanner"]