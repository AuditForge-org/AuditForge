FROM node:20-alpine
LABEL forensiq.tool="solhint"
LABEL forensiq.version="5.0.5"

RUN npm install --global --no-audit --no-fund solhint@5.0.5

RUN id -u auditor >/dev/null 2>&1 || adduser -D auditor
USER auditor
WORKDIR /input

ENTRYPOINT ["solhint"]
