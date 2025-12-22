# --- 第一阶段：构建环境 (Builder) ---
# 使用 latest 以避免 lock file 版本问题
FROM rust:latest as builder

# 设置工作目录
WORKDIR /usr/src/app

# 安装编译所需的系统依赖
# 新增: clang, libclang-dev (解决 c-kzg/bindgen 报错)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# 1. 复制依赖定义文件
# 注意：我们去掉了 Cargo.lock，让它自动生成，避免版本冲突
COPY Cargo.toml ./

# 2. 创建一个空的 main.rs 来预编译依赖
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

# 3. 编译依赖 (Release模式)
# 这一步最慢，但会被缓存
RUN cargo build --release

# 4. 删除假的源码，复制真正的源码
RUN rm -rf src
COPY src ./src

# 5. 修改 mtime 确保 cargo 知道源码变了，并编译真正的项目
RUN touch src/main.rs && cargo build --release

# --- 第二阶段：运行环境 (Runner) ---
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖 (SSL证书)
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