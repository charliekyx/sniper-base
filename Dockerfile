# --- 第一阶段：构建环境 (Builder) ---
FROM rust:1.76-bullseye as builder

WORKDIR /usr/src/app

# 安装依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
# 依然保持不复制 Cargo.lock

# [关键修改]
# 1. 强制 home 使用 0.5.9 (避开 0.5.12 的 edition2024)
# 2. 强制 ruint 使用 1.16.0 (避开 1.17.0 的 edition2024)
# 我们使用 sed 在 [dependencies] 部分注入这两行限制
RUN sed -i '/\[dependencies\]/a home = "=0.5.9"' Cargo.toml && \
    sed -i '/\[dependencies\]/a ruint = "=1.16.0"' Cargo.toml

# 创建 dummy main.rs 并构建
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

RUN cargo build --release

# 复制真正源码并最终构建
RUN rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 ---
FROM debian:bullseye-slim

WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper
CMD ["./base_sniper"]