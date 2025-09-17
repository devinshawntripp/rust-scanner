FROM rust:1.75-slim

# Set up proxy for builds (optional)
ENV http_proxy=http://10.10.10.2:3128
ENV https_proxy=http://10.10.10.2:3128

WORKDIR /app
COPY . .

RUN apt update && apt install -y pkg-config libssl-dev curl
RUN cargo build --release

ENTRYPOINT ["./target/release/scanner"]
