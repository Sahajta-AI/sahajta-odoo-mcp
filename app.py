"""Vercel entrypoint: the company connector (OAuth sign-in, Redis-backed state).

Vercel serves the ASGI `app` below. Configuration comes from the project's environment variables;
see docs/DEPLOY_VERCEL.md.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sahajta_odoo_mcp.config import Settings  # noqa: E402
from sahajta_odoo_mcp.server import create_http_app  # noqa: E402

_settings = Settings()
if not _settings.mcp_redis_url:
    raise RuntimeError(
        "No Redis configured. On Vercel, add Upstash Redis to this project (Storage / Marketplace) so REDIS_URL is set."
    )
app = create_http_app(_settings)
