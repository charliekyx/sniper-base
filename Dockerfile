# --- 第一阶段：构建环境 (Builder) ---
# 必须使用 bullseye (Debian 11) 以配合 c-kzg 0.1.1
FROM rust:1.76-bullseye as builder

# 设置工作目录
WORKDIR /usr/src/app

# 安装编译所需的系统依赖
# clang 和 libclang-dev 对 c-kzg 至关重要
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# 1. 复制依赖定义文件
COPY Cargo.toml ./
# COPY Cargo.lock ./  <-- 继续保持注释状态，不复制旧 lock 文件

# [关键修复]
# home v0.5.12 需要 Rust 2024 Edition (Cargo 1.85+)，会导致 Cargo 1.76 报错。
# 我们通过 sed 命令向 Cargo.toml 的 [dependencies] 部分强制插入 home = "=0.5.9"
# 这样 Cargo 解析依赖时会被迫使用旧版 home，从而兼容 Rust 1.76。
RUN sed -i '/\[dependencies\]/a home = "=0.5.9"' Cargo.toml

# 2. 创建一个空的 main.rs 来预编译依赖
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 3. 编译依赖 (Release模式)
RUN cargo build --release

# 4. 删除假的源码，复制真正的源码
RUN rm -rf src
COPY src ./src

# 5. 修改 mtime 并编译真正的项目
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
# 运行时也保持 bullseye 环境一致性
FROM debian:bullseye-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper

CMD ["./base_sniper"]