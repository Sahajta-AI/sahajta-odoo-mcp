"""Audit trail: one JSON line per tool call. Field names and record ids only, never values or keys."""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

_logger = logging.getLogger("sahajta_odoo_mcp.audit")


class AuditLog:
    def __init__(self, file_path: str | None = None, usage=None):
        self._file = file_path
        self._usage = usage  # optional 30-day history in Redis (see usage.py)
        if not _logger.handlers:
            handler = logging.StreamHandler(sys.stderr)  # never stdout: stdio mode uses it for the protocol
            handler.setFormatter(logging.Formatter("%(message)s"))
            _logger.addHandler(handler)
            _logger.setLevel(logging.INFO)
            _logger.propagate = False

    def record(
        self,
        *,
        user: str,
        uid: int | None,
        tool: str,
        outcome: str,
        model: str | None = None,
        ids: list[int] | None = None,
        fields: list[str] | None = None,
        method: str | None = None,
        detail: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "odoo_mcp_call",
            "user": user,
            "uid": uid,
            "tool": tool,
            "outcome": outcome,
        }
        if model:
            entry["model"] = model
        if ids:
            entry["ids"] = ids[:50]
        if fields:
            entry["fields"] = sorted(fields)[:100]
        if method:
            entry["method"] = method
        if detail:
            entry["detail"] = detail[:300]
        if self._usage is not None:
            self._usage.record(entry)
        line = json.dumps(entry, default=str)
        _logger.info(line)
        if self._file:
            try:
                with open(self._file, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                _logger.warning(json.dumps({"event": "audit_file_write_failed", "path": self._file}))
