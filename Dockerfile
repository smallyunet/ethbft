FROM rust:1.91.0-alpine AS builder

WORKDIR /build
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests ./tests
RUN cargo build --locked --release --bin ethbft

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

WORKDIR /app
RUN apk add --no-cache ca-certificates netcat-openbsd \
    && adduser -D -g '' ethbft \
    && mkdir -p /app/data \
    && chown -R ethbft:ethbft /app
COPY --from=builder /build/target/release/ethbft /app/ethbft
COPY config/docker-config.yaml /app/config.yaml
USER ethbft
CMD ["/app/ethbft"]
