FROM clux/muslrust:stable AS build
RUN --mount=type=bind,source=./,target=/volume \
    --mount=type=cache,target=/cargo-target-dir \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    CARGO_TARGET_DIR=/cargo-target-dir cargo build --release --bin controller && \
    cp /cargo-target-dir/*/release/controller /controller

FROM cgr.dev/chainguard/static
COPY --from=build --chown=nonroot:nonroot /controller /app/
EXPOSE 8080
ENTRYPOINT ["/app/controller"]
