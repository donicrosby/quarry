#!/usr/bin/env bash
# Run the local Quarry demo scan against the vulnerable-fastapi example.
# Checks prerequisites and prints guidance if they are not met.
set -euo pipefail

REPO="${QUARRY_DEMO_REPO:-examples/vulnerable-fastapi}"
TARGET="${QUARRY_DEMO_TARGET:-http://localhost:9000}"
SERVER="${QUARRY_SERVER_URL:-http://localhost:8000}"

fail=0

check_http() {
    local label="$1" url="$2"
    if curl -sf --max-time 2 "$url" > /dev/null 2>&1; then
        echo "  [ok] $label reachable at $url"
    else
        echo "  [missing] $label not reachable at $url"
        fail=1
    fi
}

echo "Checking prerequisites..."
check_http "Temporal server" "http://localhost:8233"
check_http "Quarry server" "$SERVER/healthz"
check_http "Vulnerable-FastAPI target" "$TARGET/health"

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "One or more prerequisites are missing. Start them first:"
    echo ""
    echo "  # 1. Temporal server"
    echo "  docker compose -f docker-compose.temporal.yml up -d"
    echo ""
    echo "  # 2. Vulnerable-FastAPI target (in a separate terminal)"
    echo "  task target"
    echo ""
    echo "  # 3. Quarry server + worker (in a separate terminal)"
    echo "  uv run quarry server"
    echo ""
    echo "Then re-run: task demo"
    exit 1
fi

echo ""
echo "Running demo scan..."
echo "  repo:   $REPO"
echo "  target: $TARGET"
echo ""

uv run quarry scan run --repo "$REPO" --target "$TARGET"
