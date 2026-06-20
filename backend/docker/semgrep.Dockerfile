FROM returntocorp/semgrep:1.85.0
LABEL forensiq.tool="semgrep"
LABEL forensiq.version="1.85"

USER root
# Bake the p/smart-contracts ruleset into the image so semgrep runs OFFLINE.
# The analysis sandbox is --network none; `--config=p/smart-contracts` would
# otherwise fetch from semgrep.dev and produce no output. The /c/ endpoint
# returns the whole pack as a single YAML.
RUN mkdir -p /opt/semgrep-rules \
 && ( wget -qO /opt/semgrep-rules/smart-contracts.yaml "https://semgrep.dev/c/p/smart-contracts" \
      || curl -fsSL "https://semgrep.dev/c/p/smart-contracts" -o /opt/semgrep-rules/smart-contracts.yaml ) \
 && test -s /opt/semgrep-rules/smart-contracts.yaml \
 && head -1 /opt/semgrep-rules/smart-contracts.yaml | grep -q "rules:"
# No network at run time → skip semgrep's version check.
ENV SEMGREP_ENABLE_VERSION_CHECK=0
RUN id -u auditor >/dev/null 2>&1 || adduser -D auditor
USER auditor
WORKDIR /input

ENTRYPOINT ["semgrep"]
