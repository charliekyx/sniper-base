# --- 第一阶段：构建环境 (Builder) ---
FROM rust:latest as builder

WORKDIR /usr/src/app

# 1. 安装基础依赖
# 安装 clang, libclang-dev, llvm-dev 以确保库文件存在
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    libclang-dev \
    llvm-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# 2. [绝杀] 自动寻找并修复 libclang 路径
# 不再去猜是 llvm-14 还是 llvm-15，直接用 find 命令找出来，并建立软链接
RUN export LIBCLANG_LOC=$(find /usr/lib/llvm-* -name "libclang.so*" | head -n 1 | xargs dirname) && \
    echo "Detected libclang at: $LIBCLANG_LOC" && \
    # 强制在 /usr/lib 下建立软链，确保 bindgen 能找到
    ln -s "$LIBCLANG_LOC/libclang.so.1" /usr/lib/libclang.so || true && \
    ln -s "$LIBCLANG_LOC/libclang.so" /usr/lib/libclang.so.1 || true

# 3. 设置通用环境变量
# 因为上面我们把库链到了 /usr/lib，这里直接指向 /usr/lib 即可
ENV LIBCLANG_PATH=/usr/lib

# 4. 复制 Cargo.toml (不复制 Cargo.lock)
COPY Cargo.toml ./

# 5. [顺序修复] 先创建 dummy main.rs，再操作 Cargo
# 必须先有 src/main.rs，cargo generate-lockfile 才能工作
RUN mkdir src && \
    echo "fn main() {println!(\"dummy\")}" > src/main.rs

# 6. [版本修复] 生成锁文件并强制降级不兼容的库
# 解决 base64ct/ruint/home 的 edition2024 报错
RUN cargo generate-lockfile && \
    cargo update -p base64ct --precise 1.6.0 && \
    cargo update -p ruint --precise 1.16.0 && \
    cargo update -p home --precise 0.5.9

# 7. 预编译依赖
# 这一步会编译 c-kzg，现在有了上面的 path 修复，应该能通过了
RUN cargo build --release

# 8. 编译正式项目
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