# You can override this `--build-arg BASE_IMAGE=...` to use different
# version of Rust or OpenSSL.
ARG BASE_IMAGE=nasqueron/rust-musl-builder:latest

# Our first FROM statement declares the build environment.
FROM ${BASE_IMAGE} AS builder

ARG BUILD_ID
LABEL stage=builder
LABEL build=${BUILD_ID}

# Add our source code.
ADD --chown=rust:rust ./Cargo.lock ./
ADD --chown=rust:rust ./Cargo.toml ./
ADD --chown=rust:rust ./main.rs ./

# Build our application.
RUN cargo build --release --target=x86_64-unknown-linux-musl
RUN chmod +x /home/rust/src/target/x86_64-unknown-linux-musl/release/nftp

CMD sleep 5