# Build stage (use latest Rust for crates.io compatibility)
FROM rust:bookworm AS builder

WORKDIR /app

# Copy manifests (omit Cargo.lock to avoid version conflicts with Docker's Rust)
COPY Cargo.toml ./

# Create dummy main to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only
RUN cargo build --release 2>/dev/null || true

# Copy actual source
COPY src ./src
COPY config ./config

# Touch main to ensure rebuild
RUN touch src/main.rs

# Build the binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/zero-trust-admission-controller /app/
COPY config /etc/policy/

EXPOSE 8443

ENTRYPOINT ["/app/zero-trust-admission-controller"]
