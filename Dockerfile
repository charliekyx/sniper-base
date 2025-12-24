# --- 第一阶段：构建环境 (Builder) ---
FROM rust:latest as builder

WORKDIR /usr/src/app

# 1. 安装系统默认的 Clang (Debian Bookworm 默认为 v14)
# 这一步绝对不会报错，因为我们用的是通用包名
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    llvm-dev \
    lld \
    && rm -rf /var/lib/apt/lists/*

# 2. 设置环境变量
# Debian Bookworm 的 clang 默认是 llvm-14
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

# 3. 只复制 Cargo.toml，扔掉有问题的 Cargo.lock
COPY Cargo.toml ./

# 4. [关键步骤] 生成锁文件并强制降级不兼容的库
# 这一步是为了让 Docker 使用 Stable Rust 能跑通，避开 edition2024 错误
RUN cargo generate-lockfile && \
    cargo update -p base64ct --precise 1.6.0 && \
    cargo update -p ruint --precise 1.16.0 && \
    cargo update -p home --precise 0.5.9

# 5. 预编译依赖
RUN mkdir src && \
    echo "fn main() {println!(\"dummy\")}" > src/main.rs

RUN cargo build --release

# 6. 编译正式项目
RUN rm -rf src
COPY src ./src
# 更新时间戳触发重编
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper

CMD ["./base_sniper"]