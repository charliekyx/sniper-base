# --- 第一阶段：构建环境 (Builder) ---
# 1. 使用 latest，确保 Rust 版本足够新，能支持 ruint/base64ct 等新库
FROM rust:latest as builder

# 设置工作目录
WORKDIR /usr/src/app

# 2. [关键步骤] 安装 Clang
# c-kzg 依赖 bindgen，而 bindgen 必须有 clang 才能工作。
# rust:latest 默认没有 clang，这是导致你最开始编译失败的根本原因。
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# 3. [关键步骤] 复制 Cargo.lock
# 必须要复制锁文件！这能确保服务器下载的依赖版本和你本地完全一致。
# 这样你就不用担心服务器去拉取不兼容的新版库了。
COPY Cargo.toml Cargo.lock ./

# 4. 创建一个空的 main.rs 来预编译依赖
# 这一步能利用 Docker 缓存，避免每次改代码都重编所有依赖
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 5. 编译依赖 (Release模式)
RUN cargo build --release

# 6. 删除假的源码，复制真正的源码
RUN rm -rf src
COPY src ./src

# 7. 修改 mtime 并编译真正的项目
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
# 建议使用 bookworm-slim (Debian 12)，与 rust:latest (基于 Bookworm) 保持系统库一致
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