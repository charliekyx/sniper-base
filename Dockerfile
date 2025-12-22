# --- 第一阶段：构建环境 (Builder) ---
FROM rust:1.75-slim-bookworm as builder

# 设置工作目录
WORKDIR /usr/src/app

# 安装编译所需的系统依赖 (OpenSSL 是 ethers 必须的)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 1. 为了利用 Docker 缓存，我们先复制依赖定义文件
COPY Cargo.toml Cargo.lock ./

# 2. 创建一个空的 main.rs 来预编译依赖
# 这样如果你只改了代码没改依赖，下一次 build 就不需要重新下载编译 crates
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 3. 编译依赖 (Release模式)
RUN cargo build --release

# 4. 删除假的源码，复制真正的源码
RUN rm -rf src
COPY src ./src

# 5. 修改 mtime 确保 cargo 知道源码变了，并编译真正的项目
# 注意：这里我们指名编译你的 binary，防止缓存干扰
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖 (SSL证书用于HTTPS/WSS，OpenSSL库)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /usr/src/app/target/release/base_sniper .

# 确保二进制文件可执行
RUN chmod +x base_sniper

# 容器启动命令
CMD ["./base_sniper"]