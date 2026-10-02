# Same two-stage shape as the auth service: compile with a toolchain, ship only
# the binary.
FROM rust:1-bookworm AS builder

WORKDIR /build

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
    && cargo build --release --locked -p orders-service \
    && rm -rf crates/common/src services/auth-service/src services/orders-service/src

COPY crates crates
COPY services services
# `sqlx::migrate!` embeds ./migrations at compile time, so it must be present.
COPY services/orders-service/migrations services/orders-service/migrations
RUN touch crates/common/src/lib.rs \
        services/orders-service/src/lib.rs \
        services/orders-service/src/main.rs \
    && cargo build --release --locked -p orders-service

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /build/target/release/orders-service /usr/local/bin/orders-service

USER app

ENV BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=orders_service=info,tower_http=info

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=3 \
    CMD ["/usr/local/bin/orders-service", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/orders-service"]
