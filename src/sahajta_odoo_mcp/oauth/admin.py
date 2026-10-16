"""Manage people's Claude connections (OAuth grants) from the server's shell.

    python -m sahajta_odoo_mcp.oauth.admin list [--all]
    python -m sahajta_odoo_mcp.oauth.admin revoke --login someone@example.com
    python -m sahajta_odoo_mcp.oauth.admin revoke --grant <grant id>
    python -m sahajta_odoo_mcp.oauth.admin revoke-all --yes

Settings are read from the environment (or .env), exactly as the server reads them. Revoking
takes effect on the person's next request: Claude then has to sign in again. Nothing here ever
prints an API key or token.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime

from pydantic import ValidationError

from ..config import Settings
from . import database_path, make_store
from .store import Grant, OAuthStore


def _when(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _status(grant: Grant) -> str:
    if grant.active:
        return "active"
    return f"revoked: {grant.revoked_reason or 'unknown'}"


def _print_table(grants: list[Grant], include_status: bool) -> None:
    headers = ["GRANT ID", "LOGIN", "NAME", "CLIENT", "CREATED", "LAST USED"] + (["STATUS"] if include_status else [])
    rows = [
        [g.grant_id, g.login, g.display_name, g.client_name, _when(g.created_at), _when(g.last_used_at)]
        + ([_status(g)] if include_status else [])
        for g in grants
    ]
    widths = [max(len(str(cell)) for cell in column) for column in zip(headers, *rows, strict=False)]
    for row in [headers, *rows]:
        print("  ".join(str(cell).ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip())


def main(argv: Sequence[str] | None = None, settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sahajta_odoo_mcp.oauth.admin",
        description="List or revoke the Claude connections people have made to Odoo through this server.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    list_cmd = commands.add_parser("list", help="list active connections")
    list_cmd.add_argument("--all", action="store_true", help="include revoked and expired connections")
    revoke_cmd = commands.add_parser("revoke", help="revoke one person's connections, or one connection")
    target = revoke_cmd.add_mutually_exclusive_group(required=True)
    target.add_argument("--login", help="revoke every active connection of this Odoo login")
    target.add_argument("--grant", help="revoke one connection by its grant id (see 'list')")
    revoke_all_cmd = commands.add_parser("revoke-all", help="revoke every active connection")
    revoke_all_cmd.add_argument("--yes", action="store_true", help="confirm; required")
    args = parser.parse_args(argv)

    if settings is None:
        try:
            settings = Settings()
        except ValidationError as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2
    if settings.mcp_redis_url:
        store = make_store(settings)
    else:
        path = database_path(settings)
        if not path.exists():
            print(f"No connection database at {path}; nobody has connected yet.")
            return 0
        store = OAuthStore(path)
    try:
        now = time.time()
        if args.command == "list":
            grants = store.list_grants(include_inactive=args.all)
            if not grants:
                print("No connections." if args.all else "No active connections.")
                return 0
            _print_table(grants, include_status=args.all)
            return 0
        if args.command == "revoke":
            if args.grant:
                count = int(store.revoke_grant(args.grant, "revoked by an administrator", now))
            else:
                count = store.revoke_grants_for_login(args.login, "revoked by an administrator", now)
            print(f"Revoked {count} connection(s).")
            return 0 if count else 1
        if not args.yes:
            active = len(store.list_grants())
            print(f"This would revoke all {active} active connection(s). Re-run with --yes to confirm.")
            return 1
        count = store.revoke_all("revoked by an administrator (revoke-all)", now)
        print(f"Revoked {count} connection(s).")
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
