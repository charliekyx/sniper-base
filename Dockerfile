# --- 第一阶段：构建环境 (Builder) ---
FROM rust:latest as builder

WORKDIR /usr/src/app

# 1. 安装 Clang 16 (解决 c-kzg 编译问题)
# 这一步是必须的，否则 c-kzg 会报 unresolved imports
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang-16 \
    libclang-16-dev \
    llvm-16-dev \
    lld \
    && rm -rf /var/lib/apt/lists/*

# 设置环境变量确保 bindgen 找到 clang
ENV CC=clang-16 CXX=clang++-16 LIBCLANG_PATH=/usr/lib/llvm-16/lib

# 2. [核心修复] 只复制 Cargo.toml，不复制 Cargo.lock
# 我们不要用你本地那个“太超前”的锁文件
COPY Cargo.toml ./

# 3. [核心修复] 生成新锁文件并强制降级不兼容的库
# base64ct 1.8.1 -> 1.6.0 (解决 edition2024 报错)
# ruint 1.17.0 -> 1.16.0 (解决 edition2024 报错)
# home 0.5.12 -> 0.5.9 (解决 edition2024 报错)
RUN cargo generate-lockfile && \
    cargo update -p base64ct --precise 1.6.0 && \
    cargo update -p ruint --precise 1.16.0 && \
    cargo update -p home --precise 0.5.9

# 4. 预编译依赖
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

RUN cargo build --release

# 5. 编译正式项目
RUN rm -rf src
COPY src ./src
# 更新时间戳触发重编
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
FROM debian:bookworm-slim

WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper

CMD ["./base_sniper"]