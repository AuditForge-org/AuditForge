#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Pin every FROM line in our Dockerfiles to a digest. Run this whenever
# you bump a base image version, then commit the result.
#
# Requirements:
#   - docker installed and logged in to the relevant registries
#   - bash 4+, awk
#
# Usage:
#   ./scripts/pin-images.sh                     # update everything
#   ./scripts/pin-images.sh backend/Dockerfile.app   # update one file
#
# How it works:
#   For each FROM line, strip any existing @sha256:... digest, resolve
#   the canonical digest via `docker buildx imagetools inspect`, and
#   write it back. Verifies the result is non-empty before committing
#   to file.

set -euo pipefail

FILES=("$@")
if [[ ${#FILES[@]} -eq 0 ]]; then
  mapfile -t FILES < <(find backend -name 'Dockerfile*' -type f)
fi

resolve_digest() {
  local image_ref="$1"
  # Strip any existing @sha256:...
  local clean="${image_ref%@*}"
  # buildx returns multi-arch manifests for the index digest, which is
  # what we want — k8s will pull the right per-arch layer from it.
  docker buildx imagetools inspect --format '{{ json . }}' "$clean" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('manifest',{}).get('digest',''))"
}

for file in "${FILES[@]}"; do
  echo "→ $file"
  awk -v file="$file" '
    /^FROM / {
      # Match: FROM <image>[:tag][@sha256:...] [AS stage]
      match($0, /FROM[[:space:]]+([^[:space:]]+)/, m)
      original = m[1]
      print "  FROM " original > "/dev/stderr"
    }
    { print }
  ' "$file"

  # Two-pass: first list FROM lines, then resolve and rewrite in place
  python3 <<PYEOF
import re, subprocess, sys
path = "$file"
with open(path) as f:
    text = f.read()

def resolve(ref):
    clean = ref.split('@')[0]
    try:
        out = subprocess.check_output(
            ['docker', 'buildx', 'imagetools', 'inspect', '--format', '{{ json . }}', clean],
            stderr=subprocess.DEVNULL, timeout=30,
        )
        import json
        d = json.loads(out)
        digest = d.get('manifest', {}).get('digest')
        return digest
    except Exception as e:
        print(f"  ! could not resolve {clean}: {e}", file=sys.stderr)
        return None

def replacer(match):
    full_from = match.group(0)
    ref = match.group(1)
    # If already digest-pinned and non-placeholder, leave alone
    if '@sha256:' in ref and '00000000' not in ref:
        return full_from
    base = ref.split('@')[0]
    digest = resolve(base)
    if not digest:
        return full_from
    # Preserve everything after the image ref (e.g. AS builder)
    tail = full_from[match.end(1):]
    return f"FROM {base}@{digest}{tail}"

new_text = re.sub(r'^FROM\s+(\S+)', replacer, text, flags=re.M)
with open(path, 'w') as f:
    f.write(new_text)
PYEOF

done

echo
echo "Done. Run 'git diff' to review the digest updates."
