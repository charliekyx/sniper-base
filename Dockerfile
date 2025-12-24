# --- Phase 1: Builder ---
FROM rust:latest as builder

WORKDIR /usr/src/app

# 1. Install Clang, libclang, and llvm-dev
# We install 'clang' and 'libclang-dev' to get the libraries.
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    llvm-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# 2. [CRITICAL FIX] Locate libclang and create a symlink
# Debian Bookworm installs libclang in /usr/lib/llvm-14/lib/, but bindgen sometimes
# fails to find it. We find the actual file and symlink it to /usr/lib/libclang.so
# so it is globally discoverable.
RUN LIBCLANG_PATH=$(find /usr/lib/llvm-* -name "libclang.so*" | head -n 1 | xargs dirname) && \
    echo "Found libclang at $LIBCLANG_PATH" && \
    ln -s "$LIBCLANG_PATH/libclang.so.1" /usr/lib/libclang.so || true && \
    ln -s "$LIBCLANG_PATH/libclang.so" /usr/lib/libclang.so.1 || true

# 3. Explicitly set LIBCLANG_PATH just in case
# We point to the standard llvm-14 directory, which is the default in Debian Bookworm (rust:latest)
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

# 4. Copy Lockfiles (Make sure Cargo.lock is NOT in .dockerignore)
COPY Cargo.toml Cargo.lock ./

# 5. Create dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 6. Build dependencies (Release mode)
# This step triggers the c-kzg compilation. With the symlink above, it should work.
RUN cargo build --release

# 7. Build the actual project
RUN rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

# --- Phase 2: Runner ---
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper

CMD ["./base_sniper"]