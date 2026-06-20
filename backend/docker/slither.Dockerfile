FROM python:3.11-slim
LABEL org.opencontainers.image.source="https://github.com/crytic/slither"
LABEL forensiq.tool="slither"
LABEL forensiq.version="0.10.4"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
 && rm -rf /var/lib/apt/lists/*

# solc-select + slither from PyPI (PyPI isn't UA-gated, so pip is fine at build)
RUN pip install --no-cache-dir solc-select==1.0.4 slither-analyzer==0.10.4

# Non-root user for safety
RUN id -u auditor >/dev/null 2>&1 || useradd -m auditor
USER auditor

# solc-select's own downloader uses urllib, which Cloudflare (fronting
# binaries.soliditylang.org) intermittently 403s. Pre-place solc from GitHub
# *release assets* (stable URLs, curl UA accepted, no GitHub API) into the
# per-user solc-select artifacts dir, so the `solc` shim resolves a version at
# runtime under --network none with nothing left to download.
RUN set -eux; \
    for v in 0.8.24 0.8.20 0.8.17 0.7.6 0.6.12; do \
      d="$HOME/.solc-select/artifacts/solc-$v"; mkdir -p "$d"; \
      curl -fsSL "https://github.com/ethereum/solidity/releases/download/v$v/solc-static-linux" -o "$d/solc-$v"; \
      chmod +x "$d/solc-$v"; \
    done; \
    echo "0.8.24" > "$HOME/.solc-select/global-version"
WORKDIR /input

ENTRYPOINT ["slither"]
