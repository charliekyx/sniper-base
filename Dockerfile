# Stage 1: Prepare cargo-chef
FROM rust:1.83-bookworm AS chef
# [Fix] Add --locked to use the tested dependencies found in Cargo.lock
# avoiding the broken globset 0.4.18 update
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Compute dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build dependencies and application
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    lld \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Build dependencies - this is the caching layer
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --release

# Stage 4: Runtime environment
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/base_sniper /usr/local/bin/base_sniper

# Ensure it is executable
RUN chmod +x /usr/local/bin/base_sniper

CMD ["base_sniper"]