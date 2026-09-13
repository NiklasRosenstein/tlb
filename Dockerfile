FROM clux/muslrust:1.98.1-stable AS build
# Use the image's toolchain, which includes its musl target.
ENV RUSTUP_TOOLCHAIN=stable
RUN --mount=type=bind,source=./,target=/volume \
    --mount=type=cache,target=/cargo-target-dir \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    CARGO_TARGET_DIR=/cargo-target-dir cargo build --locked --release --bin controller && \
    cp /cargo-target-dir/*/release/controller /controller

FROM cgr.dev/chainguard/static
COPY --from=build --chown=nonroot:nonroot /controller /app/
EXPOSE 8080
ENTRYPOINT ["/app/controller"]
