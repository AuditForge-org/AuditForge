# Source prebuilt solc binaries from the already-built slither image (which
# installs them via solc-select) so aderyn's svm backend resolves solc OFFLINE
# at run time. The analysis sandbox runs --network none; aderyn otherwise
# downloads solc from binaries.soliditylang.org and dies ("Failed to Derive AST
# & EVM Info"). We reuse slither's binaries rather than re-running solc-select
# here, whose GitHub version-list call gets HTTP 403 rate-limited in builds.
# (Requires forensiq/slither:0.10.4 to be built first — it always is.)
FROM forensiq/slither:0.10.4 AS solc

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/Cyfrin/aderyn"
LABEL forensiq.tool="aderyn"
# NOTE: pinned to 0.5.13 — aderyn 0.5.5 was never published to crates.io and has
# no GitHub release, so the original `cargo install aderyn --version 0.5.5` could
# not resolve. 0.5.13 is the latest of the same 0.5.x line, so its JSON output
# still matches the aderyn normalizer. The compose image tag stays
# forensiq/aderyn:0.5.5 (an identifier the runner references); only the contents
# are 0.5.13.
LABEL forensiq.version="0.5.13"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Use the prebuilt release binary instead of a cargo build: no Rust toolchain,
# no MSRV pitfalls, and far faster. The gnu (glibc) build matches debian.
RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o aderyn.tar.xz \
      "https://github.com/Cyfrin/aderyn/releases/download/aderyn-v0.5.13/aderyn-x86_64-unknown-linux-gnu.tar.xz"; \
    tar -xJf aderyn.tar.xz; \
    bin="$(find . -type f -name aderyn | head -1)"; \
    test -n "$bin"; \
    install -m 0755 "$bin" /usr/local/bin/aderyn; \
    rm -rf /tmp/aderyn.tar.xz /tmp/aderyn*; \
    aderyn --version

RUN id -u auditor >/dev/null 2>&1 || useradd -m auditor

# Seed svm-rs's on-disk layout (~/.svm/<ver>/solc-<ver>) from the prefetched
# binaries and point SVM_HOME at it, so aderyn's compiler backend finds solc
# with zero network access.
COPY --from=solc /home/auditor/.solc-select/artifacts/ /tmp/solc-artifacts/
RUN mkdir -p /home/auditor/.svm \
 && for v in 0.8.24 0.8.20 0.8.17 0.7.6 0.6.12; do \
      mkdir -p "/home/auditor/.svm/$v"; \
      cp "/tmp/solc-artifacts/solc-$v/solc-$v" "/home/auditor/.svm/$v/solc-$v"; \
      chmod 0755 "/home/auditor/.svm/$v/solc-$v"; \
    done \
 && rm -rf /tmp/solc-artifacts \
 && chown -R auditor:auditor /home/auditor/.svm
ENV SVM_HOME=/home/auditor/.svm

USER auditor
WORKDIR /input

ENTRYPOINT ["aderyn"]
