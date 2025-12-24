# --- 第一阶段：构建环境 (Builder) ---
FROM rust:latest as builder

WORKDIR /usr/src/app

# 1. 安装 Clang (Debian Bookworm 默认为 v14)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    llvm-dev \
    lld \
    && rm -rf /var/lib/apt/lists/*

# 2. 设置环境变量
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

# 3. 复制 Cargo.toml
COPY Cargo.toml ./

# 4. [关键修正] 先创建 dummy main.rs，再操作 Cargo
# 之前报错是因为 Cargo 找不到 src/main.rs，认为项目无效
RUN mkdir src && \
    echo "fn main() {println!(\"dummy\")}" > src/main.rs

# 5. [核心修复] 现在可以安全生成锁文件并降级不兼容的库了
# 这一步避开 edition2024 错误
RUN cargo generate-lockfile && \
    cargo update -p base64ct --precise 1.6.0 && \
    cargo update -p ruint --precise 1.16.0 && \
    cargo update -p home --precise 0.5.9

# 6. 预编译依赖
RUN cargo build --release

# 7. 编译正式项目
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