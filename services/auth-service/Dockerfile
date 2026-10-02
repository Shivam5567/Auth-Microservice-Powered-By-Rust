# Build stage: compile with a full toolchain, then ship only the binary.
FROM rust:1-bookworm AS builder

WORKDIR /build

# Dependencies are copied first so the layer is reused whenever only our own
# source changes. Every workspace member needs a stub target, even when building
# just one of them, or cargo cannot load the workspace at all.
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/
COPY services/auth-service/Cargo.toml services/auth-service/
COPY services/orders-service/Cargo.toml services/orders-service/
RUN mkdir -p crates/common/src services/auth-service/src services/orders-service/src \
    && echo "" > crates/common/src/lib.rs \
    && echo "fn main() {}" > services/auth-service/src/main.rs \
    && echo "" > services/auth-service/src/lib.rs \
    && echo "fn main() {}" > services/orders-service/src/main.rs \
    && echo "" > services/orders-service/src/lib.rs \
    && cargo build --release --locked -p auth-service \
    && rm -rf crates/common/src services/auth-service/src services/orders-service/src

COPY crates crates
COPY services services
# `sqlx::migrate!` embeds ./migrations at compile time, so it must be present.
COPY services/auth-service/migrations services/auth-service/migrations
# The stub sources from the cache step have older timestamps than the real ones
# restored above, so every crate has to be nudged or cargo treats it as fresh.
RUN touch crates/common/src/lib.rs \
        services/auth-service/src/lib.rs \
        services/auth-service/src/main.rs \
        services/orders-service/src/lib.rs \
        services/orders-service/src/main.rs \
    && cargo build --release --locked -p auth-service

# Runtime stage: no compiler, no source.
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The service never needs root; the keys directory is its only write target.
RUN useradd --system --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /app/keys \
    && chown -R app:app /app

WORKDIR /app

COPY --from=builder /build/target/release/auth-service /usr/local/bin/auth-service

USER app

ENV BIND_ADDR=0.0.0.0:8080 \
    JWT_PRIVATE_KEY_PATH=/app/keys/private.pem \
    JWT_PUBLIC_KEY_PATH=/app/keys/public.pem \
    RUST_LOG=auth_service=info,tower_http=info

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/auth-service", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/auth-service"]
