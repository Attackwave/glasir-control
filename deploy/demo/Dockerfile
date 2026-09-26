# Demo only: Glasir Core and Control in one container, with fixed demo
# credentials. Never expose it beyond localhost.
ARG GLASIR_VERSION=v0.3.0
ARG CONTROL_VERSION=v0.2.0
FROM ghcr.io/attackwave/glasir:${GLASIR_VERSION} AS core
FROM ghcr.io/attackwave/glasir-control:${CONTROL_VERSION} AS control
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git socat curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 65532 --create-home --shell /usr/sbin/nologin glasir \
 && mkdir /work && chown 65532:65532 /work
COPY --from=core /usr/local/bin/glasir /usr/local/bin/glasir
COPY --from=control /usr/local/bin/glasir-control /usr/local/bin/glasir-control
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
USER 65532:65532
ENV HOME=/home/glasir
EXPOSE 8800 7878
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
