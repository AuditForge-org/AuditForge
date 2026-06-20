FROM python:3.11-slim
LABEL org.opencontainers.image.source="https://github.com/ConsenSys/mythril"
LABEL forensiq.tool="mythril"
LABEL forensiq.version="0.24.8"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    curl \
    ca-certificates \
    git \
 && rm -rf /var/lib/apt/lists/*

# solc-select + mythril from PyPI (PyPI isn't UA-gated, so pip is fine at build)
RUN pip install --no-cache-dir solc-select==1.0.4
# Mythril pinned. Z3 (SMT solver) is pulled transitively.
RUN pip install --no-cache-dir mythril==0.24.8

RUN id -u auditor >/dev/null 2>&1 || useradd -m auditor
USER auditor

# Pre-place solc from GitHub release assets (see slither.Dockerfile for the why:
# solc-select / py-solc-x urllib downloads get Cloudflare-403'd, and engines run
# --network none so nothing can be fetched at runtime). Populate BOTH the
# py-solc-x store (~/.solcx, which mythril's --solv uses) and solc-select.
RUN set -eux; \
    mkdir -p "$HOME/.solcx"; \
    for v in 0.8.24 0.8.20 0.7.6 0.6.12; do \
      curl -fsSL "https://github.com/ethereum/solidity/releases/download/v$v/solc-static-linux" -o "$HOME/.solcx/solc-v$v"; \
      chmod +x "$HOME/.solcx/solc-v$v"; \
      d="$HOME/.solc-select/artifacts/solc-$v"; mkdir -p "$d"; \
      cp "$HOME/.solcx/solc-v$v" "$d/solc-$v"; chmod +x "$d/solc-$v"; \
    done; \
    echo "0.8.24" > "$HOME/.solc-select/global-version"
WORKDIR /input

ENTRYPOINT ["myth"]
