#!/usr/bin/env bash
# The only way to put this connector in production: from a clean, pushed main branch whose tests pass,
# with no secret from .env in any tracked file (the repository is public).
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "Deploy stopped: $*" >&2; exit 1; }

[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || fail "deploy from main only."
[ -z "$(git status --porcelain --untracked-files=no)" ] || fail "commit or stash your changes first."
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || fail "push main first, so GitHub and production match."

if [ -f .env ]; then
  for name in ODOO_API_KEY MCP_SECRET MCP_ADMIN_TOKEN; do
    value=$(grep -E "^${name}=" .env | head -1 | cut -d= -f2- | tr -d "\"'" || true)
    if [ ${#value} -ge 12 ] && git grep -qF -- "$value"; then
      fail "the value of $name from .env is in a tracked file."
    fi
  done
fi

echo "Running the tests..."
.venv/bin/python -m pytest -q || fail "tests failed."

vercel deploy --prod --yes
url=$(grep -E '^MCP_PUBLIC_URL=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)
url=${url:-https://sahajta-odoo-mcp.vercel.app}
curl -fsS -m 20 "$url/healthz" >/dev/null || fail "deployed, but $url/healthz does not answer. Roll back in Vercel."
echo "Deployed and healthy: $url"
