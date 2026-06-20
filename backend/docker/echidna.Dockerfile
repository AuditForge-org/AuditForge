FROM ghcr.io/crytic/echidna/echidna:v2.2.4
LABEL forensiq.tool="echidna"
LABEL forensiq.version="2.2.4"

# The official image includes echidna + crytic-compile + solc-select
# We just add a non-root user and set workdir
USER root
RUN id -u auditor >/dev/null 2>&1 || useradd -m auditor 2>/dev/null || adduser -D auditor
USER auditor
WORKDIR /input

ENTRYPOINT ["echidna"]
