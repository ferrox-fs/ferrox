# Multi-stage Docker build for ferroxd.
#
# Stage 1 (builder): Compile a fully static musl binary.
#   - Uses ring (pure Rust + asm) as the TLS crypto backend so no cmake/C++
#     is needed in the final binary.
#   - All Rust deps are pure Rust or use the bundled C vendored into ring.
#
# Stage 2 (runtime): Copy the binary into a scratch image.
#   - Zero runtime dependencies, minimal attack surface.
#
# Build:
#   docker build -t ferroxd:latest .
#
# Run:
#   docker run -p 9000:9000 -v /data:/data ferroxd:latest \
#       --data-dir /data \
#       --access-key minioadmin \
#       --secret-key minioadmin

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM --platform=linux/amd64 rust:latest AS builder

# musl toolchain for static linking + C compiler for ring's asm glue.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        musl-tools \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Add the musl target.
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# Copy manifests first so dependency compilation is cached separately
# from source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/ferrox-error/Cargo.toml       crates/ferrox-error/Cargo.toml
COPY crates/ferrox-crypto/Cargo.toml      crates/ferrox-crypto/Cargo.toml
COPY crates/ferrox-iam/Cargo.toml         crates/ferrox-iam/Cargo.toml
COPY crates/ferrox-meta/Cargo.toml        crates/ferrox-meta/Cargo.toml
COPY crates/ferrox-storage/Cargo.toml     crates/ferrox-storage/Cargo.toml
COPY crates/ferrox-s3-api/Cargo.toml      crates/ferrox-s3-api/Cargo.toml
COPY crates/ferrox-gateway/Cargo.toml     crates/ferrox-gateway/Cargo.toml
COPY crates/ferrox-cli/Cargo.toml         crates/ferrox-cli/Cargo.toml

# Create empty lib/bin stubs so `cargo build` can cache dependency compilation.
# Also stub bench files referenced by manifests — the .dockerignore excludes
# `**/benches/` to keep the build context tight, but cargo still validates
# every `[[bench]]` path during `build`.
RUN for crate in ferrox-error ferrox-crypto ferrox-iam ferrox-meta \
                 ferrox-storage ferrox-s3-api ferrox-gateway; do \
        mkdir -p crates/$crate/src && \
        echo "// stub" > crates/$crate/src/lib.rs; \
    done && \
    mkdir -p crates/ferrox-cli/src/bin && \
    echo "fn main(){}" > crates/ferrox-cli/src/bin/ferroxd.rs && \
    echo "fn main(){}" > crates/ferrox-cli/src/bin/ferroxctl.rs && \
    echo "// stub" > crates/ferrox-cli/src/lib.rs && \
    mkdir -p crates/ferrox-meta/benches crates/ferrox-gateway/benches && \
    echo "fn main(){}" > crates/ferrox-meta/benches/sled_bench.rs && \
    echo "fn main(){}" > crates/ferrox-gateway/benches/sigv4_bench.rs

RUN cargo build --release --target x86_64-unknown-linux-musl --bin ferroxd \
    2>&1 | tail -5 || true

# Now copy the real sources and rebuild (only changes compile).
COPY crates/ crates/

# Re-create bench stubs (the .dockerignore drops real benches/, so cargo
# still needs *something* at those paths to satisfy the manifest).
RUN mkdir -p crates/ferrox-meta/benches crates/ferrox-gateway/benches && \
    echo "fn main(){}" > crates/ferrox-meta/benches/sled_bench.rs && \
    echo "fn main(){}" > crates/ferrox-gateway/benches/sigv4_bench.rs

# Touch files to ensure they are newer than stubs and get rebuilt.
RUN find crates -name "*.rs" -exec touch {} +

RUN cargo build --release --target x86_64-unknown-linux-musl --bin ferroxd

# Verify the binary is statically linked.
RUN file target/x86_64-unknown-linux-musl/release/ferroxd | grep -E -q "statically linked|static-pie linked"

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM scratch

# Copy CA certificates from the builder for TLS (needed when ferroxd acts as
# a client, e.g. future replication).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The ferroxd binary.
COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/ferroxd \
    /ferroxd

# Default data directory inside the container.
VOLUME ["/data"]

# Plain HTTP.
EXPOSE 9000
# HTTPS (optional, requires --tls-bind etc.).
EXPOSE 9443

ENTRYPOINT ["/ferroxd"]
CMD ["--data-dir", "/data"]
