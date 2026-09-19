# syntax=docker/dockerfile:1
#
# Static x86_64 musl binary in an empty image, running as nobody.
# Build on any machine with:  docker build --platform linux/amd64 -t my-socks-server .

# ---- build ----------------------------------------------------------------------------
FROM rust:1-alpine AS build
# musl-dev: libc headers for the C part of mimalloc.
RUN apk add --no-cache musl-dev
WORKDIR /src

# Dependencies first: editing the sources does not rebuild them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl --bin my-socks-server

# ---- runtime --------------------------------------------------------------------------
FROM scratch
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/my-socks-server /my-socks-server
# Settings are read from $HOME/.mysocksserver: mount the file there.
ENV HOME=/home/socks
USER 65534:65534
EXPOSE 1080
ENTRYPOINT ["/my-socks-server"]
