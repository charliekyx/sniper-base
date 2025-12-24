# Stage 1: Prepare cargo-chef
FROM rust:1.83-bookworm AS chef
# 使用 --locked 避免安装 cargo-chef 时遇到 globset 等工具链的依赖破坏
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Compute dependency recipe
FROM chef AS planner
COPY . .
# 注意：这里会基于你修改后的 Cargo.toml 重新计算依赖
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build dependencies and application
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# 安装编译所需的系统库
RUN apt-get update && apt-get install -y \
    clang \
    lld \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# 编译依赖缓存 (Cook)
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 4: Build Application
COPY . .
# 正式编译
RUN cargo build --release

# Stage 5: Runtime environment
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# 安装运行时库 (OpenSSL等)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# 复制编译好的二进制文件
COPY --from=builder /app/target/release/base_sniper /usr/local/bin/base_sniper

RUN chmod +x /usr/local/bin/base_sniper

CMD ["base_sniper"]