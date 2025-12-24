# --- 第一阶段：构建环境 (Builder) ---
# 使用 latest 以支持 Rust 2024 Edition (解决 home/ruint 等新库报错)
FROM rust:latest as builder

# 设置工作目录
WORKDIR /usr/src/app

# [关键修复] 安装 Clang 和 LLVM
# c-kzg 依赖 bindgen，bindgen 必须要有 libclang 才能生成 C 语言绑定
# 我们显式安装 llvm-dev 并设置 LIBCLANG_PATH，确保 bindgen 能找到库
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    llvm-dev \
    && rm -rf /var/lib/apt/lists/*

# 设置环境变量，帮助 bindgen 找到 libclang
# Debian Bookworm (rust:latest) 默认通常是 llvm-14 或 llvm-16，这里指向 llvm-14
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

# [关键修复] 复制锁文件
# 这一步能保证服务器完全复刻你本地的依赖版本，杜绝“本地能跑服务器挂了”的问题
COPY Cargo.toml Cargo.lock ./

# 创建一个空的 main.rs 来预编译依赖
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 编译依赖 (Release模式)
RUN cargo build --release

# 删除假的源码，复制真正的源码
RUN rm -rf src
COPY src ./src

# 修改 mtime 并编译真正的项目
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制编译好的二进制文件
COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper

CMD ["./base_sniper"]