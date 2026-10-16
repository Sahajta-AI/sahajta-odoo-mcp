"""Command line entry point.

  sahajta-odoo-mcp stdio    run for one person (Claude Desktop / Claude Code), credentials from env
  sahajta-odoo-mcp http     run the company-wide connector (OAuth sign-in per person)
  sahajta-odoo-mcp check    test the Odoo connection and print the active safety settings
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from pydantic import ValidationError

from .config import Settings


def _settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        missing = ", ".join(".".join(str(p) for p in err["loc"]).upper() for err in exc.errors())
        raise SystemExit(f"Configuration error: check {missing} (see .env.example)") from None


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sahajta-odoo-mcp", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["stdio", "http", "check"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = _settings()

    if args.mode == "stdio":
        from .server import create_stdio_server

        create_stdio_server(settings).run("stdio")
    elif args.mode == "http":
        import uvicorn

        from .server import create_http_app

        app = create_http_app(settings)
        uvicorn.run(
            app,
            host=settings.mcp_host,
            port=settings.mcp_port,
            proxy_headers=settings.mcp_trust_proxy_headers,
            forwarded_allow_ips="*" if settings.mcp_trust_proxy_headers else None,
            server_header=False,
            log_level="info",
            # Exactly one process: single-use confirm tokens, rate limits and caches live in memory.
            workers=1,
        )
    else:
        asyncio.run(_check(settings))


async def _check(settings: Settings) -> None:
    from .odoo_client import OdooClient, OdooCredentials, new_http_client

    settings.require_stdio_settings()
    async with new_http_client(verify=settings.odoo_verify_tls) as http:
        client = OdooClient(
            OdooCredentials(settings.odoo_url, settings.odoo_db, settings.odoo_login or "", settings.odoo_api_key.get_secret_value()),
            http,
            protocol=settings.odoo_protocol,
            timeout=settings.odoo_timeout_seconds,
        )
        identity = await client.verify_login_matches()
    print(json.dumps({
        "connected_as": {"uid": identity.uid, "login": identity.login, "name": identity.name, "internal_user": identity.is_internal_user},
        "company": identity.company_name,
        "odoo_version": identity.server_version,
        "protocol": identity.protocol,
        "mode": settings.mcp_access_mode,
        "require_preview": settings.mcp_require_preview,
        "allow_archive": settings.mcp_allow_archive,
        "allow_cancel_actions": settings.mcp_allow_cancel_actions,
        "allow_outbound_messages": settings.mcp_allow_outbound_messages,
    }, indent=2))


if __name__ == "__main__":
    main()
