#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# FORENSIQ — smoke test.
#
# Submits the known-vulnerable test contracts to a running instance and
# checks the findings match what we expect. This is the single most
# important validation step: it exercises the REAL engine execution path
# (docker run slither/mythril/etc. → parse real output → consensus), which
# the unit tests only cover with mocked output.
#
# Run against a local instance:
#   ./test/smoke-test.sh
#
# Run against a remote instance:
#   FORENSIQ_URL=https://forensiq.example.com ./test/smoke-test.sh
#
# What it does for each contract:
#   1. POST /api/audits with the source
#   2. Poll /api/audits/:id until complete
#   3. Assert the expected severity findings are present (or absent)
#   4. Print the score + finding summary
#
# Exit code 0 = all expectations met. Non-zero = something to investigate.

set -uo pipefail

URL="${FORENSIQ_URL:-http://127.0.0.1:3000}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS="$DIR/contracts"
POLL_TIMEOUT="${POLL_TIMEOUT:-600}"   # Echidna can take minutes
FAILURES=0

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$1"; }
bold()  { printf '\033[1m%s\033[0m\n' "$1"; }

need() { command -v "$1" >/dev/null 2>&1 || { red "Missing dependency: $1"; exit 1; }; }
need curl
need jq

bold "Forensiq smoke test → $URL"
echo

# Confirm the instance is up
if ! curl -fsS "$URL/api/health" >/dev/null 2>&1; then
  red "Instance not reachable at $URL/api/health"
  exit 1
fi
green "✓ Instance is up"
echo

# ─── Helper: submit + poll one contract ─────────────────────────────────
# Args: <file> <enable_fuzzing true|false>
# Echoes the final report JSON to stdout.
run_audit() {
  local file="$1"
  local fuzz="$2"
  local code
  code=$(jq -Rs . < "$file")   # JSON-encode the source

  local payload
  payload=$(cat <<EOF
{
  "source": { "type": "paste", "code": $code, "filename": "$(basename "$file")" },
  "enableFuzzing": $fuzz
}
EOF
)

  local submit
  submit=$(curl -fsS -X POST "$URL/api/audits" \
    -H 'Content-Type: application/json' \
    -d "$payload" 2>/dev/null) || { red "  submit failed"; return 1; }

  local id
  id=$(echo "$submit" | jq -r '.id // empty')
  if [ -z "$id" ]; then
    red "  no audit id returned: $submit"
    return 1
  fi

  # Poll
  local waited=0
  while [ "$waited" -lt "$POLL_TIMEOUT" ]; do
    local status_json
    status_json=$(curl -fsS "$URL/api/audits/$id" 2>/dev/null) || true
    local status
    status=$(echo "$status_json" | jq -r '.status // empty')
    case "$status" in
      complete) echo "$status_json"; return 0 ;;
      failed)   red "  audit failed: $(echo "$status_json" | jq -r '.error // .failedReason // "unknown"')"; return 1 ;;
    esac
    sleep 4
    waited=$((waited + 4))
    printf '.' >&2
  done
  red "  timed out after ${POLL_TIMEOUT}s"
  return 1
}

# ─── Helper: assert a finding category/severity is present ───────────────
# Args: <report_json> <severity> <substring of title or category>
assert_finding() {
  local report="$1" sev="$2" needle="$3"
  local hits
  hits=$(echo "$report" | jq --arg sev "$sev" --arg n "$needle" \
    '[.report.consensusFindings[]
       | select(.severity==$sev)
       | select((.title|ascii_downcase|contains($n|ascii_downcase))
             or (.category|ascii_downcase|contains($n|ascii_downcase)))]
     | length')
  if [ "${hits:-0}" -ge 1 ]; then
    green "  ✓ found $sev finding matching '$needle'"
    return 0
  else
    red   "  ✗ expected a $sev finding matching '$needle' — NOT found"
    FAILURES=$((FAILURES + 1))
    return 1
  fi
}

# Args: <report_json> — assert NO critical/high findings
assert_clean() {
  local report="$1"
  local bad
  bad=$(echo "$report" | jq '[.report.consensusFindings[]
        | select(.severity=="critical" or .severity=="high")] | length')
  if [ "${bad:-0}" -eq 0 ]; then
    green "  ✓ no critical/high findings (as expected for a clean contract)"
  else
    yellow "  ⚠ $bad critical/high finding(s) on the clean contract — possible false positive"
    echo "$report" | jq -r '.report.consensusFindings[]
      | select(.severity=="critical" or .severity=="high")
      | "      [\(.severity)] \(.title) — \(.tools|join("+"))"'
    FAILURES=$((FAILURES + 1))
  fi
}

summarize() {
  local report="$1"
  local score grade n
  score=$(echo "$report" | jq -r '.report.score')
  grade=$(echo "$report" | jq -r '.report.grade')
  n=$(echo "$report" | jq -r '.report.consensusFindings | length')
  local tools
  tools=$(echo "$report" | jq -r '.report.toolsRun | join(", ")')
  echo "      score=$score grade=\"$grade\" findings=$n tools=[$tools]"
}

# ─── Test 1: Reentrancy ──────────────────────────────────────────────────
bold "1. Reentrancy (expect critical/high reentrancy finding)"
if report=$(run_audit "$CONTRACTS/01_reentrancy.sol" false); then
  echo
  summarize "$report"
  # Slither calls it "reentrancy-eth"/"reentrancy"; accept either severity
  assert_finding "$report" critical reentran || assert_finding "$report" high reentran
fi
echo

# ─── Test 2: tx.origin ───────────────────────────────────────────────────
bold "2. tx.origin authorization (expect high finding)"
if report=$(run_audit "$CONTRACTS/02_txorigin.sol" false); then
  echo
  summarize "$report"
  assert_finding "$report" high "tx.origin" || assert_finding "$report" medium "tx.origin"
fi
echo

# ─── Test 3: delegatecall ────────────────────────────────────────────────
bold "3. Arbitrary delegatecall (expect critical finding)"
if report=$(run_audit "$CONTRACTS/03_delegatecall.sol" false); then
  echo
  summarize "$report"
  assert_finding "$report" critical delegate || assert_finding "$report" high delegate
fi
echo

# ─── Test 4: clean contract (negative control) ───────────────────────────
bold "4. Clean contract (expect NO critical/high — false-positive check)"
yellow "   Note: imports OpenZeppelin; if your engine images can't resolve"
yellow "   imports, this may error. That's a known limitation, not a bug."
if report=$(run_audit "$CONTRACTS/04_clean.sol" false); then
  echo
  summarize "$report"
  assert_clean "$report"
fi
echo

# ─── Summary ─────────────────────────────────────────────────────────────
bold "─────────────────────────────────────────"
if [ "$FAILURES" -eq 0 ]; then
  green "All expectations met. The real engine path is working."
  exit 0
else
  red "$FAILURES expectation(s) not met."
  yellow "This usually means a normalizer needs adjusting to match the actual"
  yellow "tool output format. Check the worker logs:"
  echo "  docker compose -f docker-compose.prod.yml logs worker | tail -100"
  exit 1
fi
