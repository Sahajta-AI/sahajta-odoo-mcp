"""30-day usage history in Redis, for "how is the connector being used, and did anyone hit problems?".

Each event holds only metadata: when, who (Odoo login), which tool, model, method, how many records,
field NAMES, and the outcome. Never field values, record contents, or keys. Error details are kept
short and have every quoted fragment (where Odoo and this server put names and values) blanked out.

Events live in one sorted set scored by time; anything older than the retention window is dropped
on every write, and the set is capped so a runaway loop cannot fill Redis.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime

import redis

logger = logging.getLogger(__name__)

RETENTION_DAYS = 30
MAX_EVENTS = 50_000
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_CHANGE_TOOLS = {"odoo_create": "created", "odoo_update": "updated", "odoo_run_action": "buttons", "odoo_add_note": "notes",
                 "odoo_send_message": "messages"}


def sanitize_detail(detail: str | None) -> str | None:
    """Keeps the gist of an error ("Blocked by safety policy: ... is read-only") without names or values."""
    if not detail:
        return None
    text = _QUOTED.sub("'…'", str(detail)).replace("\n", " ")
    return re.sub(r"\s+", " ", text).strip()[:200]


class UsageLog:
    def __init__(self, client: redis.Redis, *, prefix: str = "sahajta-odoo-mcp:", retention_days: int = RETENTION_DAYS):
        self._r = client
        self._key = f"{prefix}usage:events"
        self._retention = retention_days * 86400

    def record(self, entry: dict) -> None:
        """Stores one event. Never raises: usage history must not break a request."""
        now = time.time()
        event = {
            "id": secrets.token_hex(6),
            "ts": round(now, 3),
            "user": entry.get("user"),
            "tool": entry.get("tool"),
            "outcome": entry.get("outcome"),
            "model": entry.get("model"),
            "method": entry.get("method"),
            "records": len(entry.get("ids") or []) or None,
            "fields": sorted(entry.get("fields") or [])[:30] or None,
            "detail": sanitize_detail(entry.get("detail")) if entry.get("outcome") != "ok" else None,
        }
        event = {k: v for k, v in event.items() if v is not None}
        try:
            with self._r.pipeline() as pipe:
                pipe.zadd(self._key, {json.dumps(event, separators=(",", ":")): now})
                pipe.zremrangebyscore(self._key, "-inf", now - self._retention)
                pipe.zremrangebyrank(self._key, 0, -(MAX_EVENTS + 1))
                pipe.execute()
        except Exception:  # noqa: BLE001 - usage history must never break a tool call
            logger.warning("could not store a usage event")

    def events(self, days: int) -> list[dict]:
        since = time.time() - max(1, min(days, 30)) * 86400
        out = []
        for raw in self._r.zrangebyscore(self._key, since, "+inf"):
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        return out

    def report(self, days: int = 7) -> dict:
        days = max(1, min(int(days), 30))
        events = self.events(days)
        is_tool = lambda e: str(e.get("tool", "")).startswith("odoo_")  # noqa: E731
        tool_events = [e for e in events if is_tool(e)]
        by_day: dict[str, Counter] = defaultdict(Counter)
        by_tool: dict[str, Counter] = defaultdict(Counter)
        changes: Counter = Counter()
        for e in events:
            day = datetime.fromtimestamp(e["ts"], UTC).strftime("%Y-%m-%d")
            by_day[day]["calls" if is_tool(e) else "connections"] += 1
            if e.get("outcome") != "ok":
                by_day[day][e.get("outcome", "error")] += 1
            by_tool[e.get("tool", "?")][e.get("outcome", "?")] += 1
            if e.get("outcome") == "ok" and e.get("tool") in _CHANGE_TOOLS:
                changes[_CHANGE_TOOLS[e["tool"]]] += e.get("records", 1) if e["tool"] == "odoo_update" else 1
        problems = [e for e in events if e.get("outcome") != "ok"][-25:]
        return {
            "period_days": days,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "tool_calls": len(tool_events),
            "errors": sum(1 for e in events if e.get("outcome") == "error"),
            "blocked": sum(1 for e in events if e.get("outcome") == "blocked"),
            "last_activity": datetime.fromtimestamp(events[-1]["ts"], UTC).isoformat(timespec="seconds") if events else None,
            "changes": dict(changes),
            "by_day": {day: dict(counts) for day, counts in sorted(by_day.items())},
            "by_tool": {tool: dict(counts) for tool, counts in sorted(by_tool.items(), key=lambda kv: -sum(kv[1].values()))},
            "by_user": dict(Counter(e.get("user", "?") for e in tool_events).most_common()),
            "top_models": Counter(e["model"] for e in tool_events if e.get("model")).most_common(10),
            "problems": problems,
        }


def format_report(report: dict, tz: str = "Asia/Kolkata") -> str:
    """Plain-text version of report() for the terminal."""
    from zoneinfo import ZoneInfo

    zone = ZoneInfo(tz)

    def local(iso_or_ts) -> str:
        moment = datetime.fromtimestamp(iso_or_ts, UTC) if isinstance(iso_or_ts, (int, float)) else datetime.fromisoformat(iso_or_ts)
        return moment.astimezone(zone).strftime("%d %b %H:%M")

    lines = [f"Sahajta Odoo connector: usage over the last {report['period_days']} day(s)", ""]
    lines.append(
        f"Tool calls: {report['tool_calls']}   errors: {report['errors']}   blocked by safety rules: {report['blocked']}"
    )
    lines.append(f"Last activity: {local(report['last_activity']) if report['last_activity'] else 'none in this period'}")
    if report["changes"]:
        lines.append("Changes made in Odoo: " + ", ".join(f"{n} {kind}" for kind, n in report["changes"].items()))
    if report["by_day"]:
        lines += ["", "By day:"]
        for day, counts in report["by_day"].items():
            extra = ", ".join(f"{n} {k}" for k, n in counts.items() if k not in ("calls", "connections"))
            lines.append(f"  {day}  {counts.get('calls', 0):4} calls" + (f"  ({extra})" if extra else ""))
    if report["by_tool"]:
        lines += ["", "By tool:"]
        for tool, counts in report["by_tool"].items():
            total = sum(counts.values())
            bad = ", ".join(f"{n} {k}" for k, n in counts.items() if k != "ok")
            lines.append(f"  {tool:24} {total:4}" + (f"  ({bad})" if bad else ""))
    if report["by_user"]:
        lines += ["", "By person: " + ", ".join(f"{u} ({n})" for u, n in report["by_user"].items())]
    if report["top_models"]:
        lines.append("Most-used models: " + ", ".join(f"{m} ({n})" for m, n in report["top_models"]))
    lines += ["", "Recent problems:" if report["problems"] else "Recent problems: none"]
    for e in reversed(report["problems"]):
        what = " ".join(x for x in (e.get("tool"), e.get("model"), e.get("method")) if x)
        lines.append(f"  {local(e['ts'])}  {e.get('outcome'):7} {what}")
        if e.get("detail"):
            lines.append(f"      {e['detail']}")
    return "\n".join(lines)
