# --- 第一阶段：构建环境 (Builder) ---
# 使用明确的 rust:1.83-bookworm 镜像，确保基础系统是 Debian 12
FROM rust:1.83-bookworm as builder

WORKDIR /usr/src/app

# 1. [核弹级修复] 强制安装 Clang 16 和相关工具
# 我们不使用默认的 'clang'，而是指定 'clang-16'，避免版本混淆
# 同时安装 lld (更快的链接器) 和 llvm-16
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang-16 \
    libclang-16-dev \
    llvm-16-dev \
    lld \
    && rm -rf /var/lib/apt/lists/*

# 2. [关键] 设置确定的环境变量
# 直接硬编码路径，不让 bindgen 猜
ENV CC=clang-16
ENV CXX=clang++-16
ENV LIBCLANG_PATH=/usr/lib/llvm-16/lib
ENV LLVM_CONFIG_PATH=/usr/bin/llvm-config-16

# 3. [双重保险] 手动创建 bindgen 需要的 symlink
# bindgen 有时候只认 libclang.so，不认 .so.1
RUN ln -s /usr/lib/llvm-16/lib/libclang.so.1 /usr/lib/llvm-16/lib/libclang.so || true

# 4. 复制依赖文件 (确保 .dockerignore 没把 Cargo.lock 忽略掉！)
COPY Cargo.toml Cargo.lock ./

# 5. 预编译依赖
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 6. 编译依赖 (Release模式)
RUN cargo build --release

# 7. 编译正式项目
RUN rm -rf src
COPY src ./src
# 更新时间戳触发重编
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖 (保持与 builder 一致的系统库版本)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制二进制
COPY --from=builder /usr/src/app/target/release/base_sniper .
RUN chmod +x base_sniper

CMD ["./base_sniper"]