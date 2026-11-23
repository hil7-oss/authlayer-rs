# AuthLayer production image.
#
# Build:  docker build -t authlayer:0.1.0 .
# Run:    see docker-compose.yml (recommended) or deploy/README.md

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM rust:1.100-bookworm AS builder

WORKDIR /build

# Copy all compile-time inputs before building. Do NOT pre-build a dummy
# main.rs: Cargo's mtime-based fingerprint can keep that dummy artifact after
# the real sources are copied, producing an image whose "app" is an empty
# binary. This single build is less cache-friendly but always ships the real
# application. include_str! files (static/) and sqlx migrations must be present.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY static ./static

RUN cargo build --release --locked --bin authlayer

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates is required for outbound TLS. curl is used only by the
# container healthcheck; no build tools are present in the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 authlayer \
    && useradd --uid 10001 --gid authlayer \
        --home-dir /data --no-create-home --shell /usr/sbin/nologin authlayer \
    && install -d -m 0700 -o authlayer -g authlayer /data

COPY --from=builder /build/target/release/authlayer /usr/local/bin/authlayer
RUN chmod 0755 /usr/local/bin/authlayer

WORKDIR /data

# Container-safe defaults. APP_URL, RP_ID and OTP_SECRET must still be set for
# a real deployment (docker-compose.yml passes them through). DEV_MODE is
# explicitly off and cookies are secure, so a bare `docker run` fails closed
# instead of exposing the dev outbox.
ENV BIND_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/authlayer.db?mode=rwc \
    COOKIE_SECURE=true \
    DEV_MODE=false \
    RUST_LOG=authlayer=info,tower_http=info

# Never run as root. The named Docker volume inherits ownership of /data from
# the image the first time it is created.
USER authlayer:authlayer

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["authlayer"]
