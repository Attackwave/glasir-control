# Build a pinned, reproducible control-plane image. Policy, credentials and
# audit storage are always mounted at runtime.
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin glasir
COPY --from=build /src/target/release/glasir-control /usr/local/bin/glasir-control
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/glasir-control"]
