"""Odoo's official accounting reports (account.report), read as compact lines of numbers.

OdooService.report asks Odoo for a report the way its own Reporting screens do (get_options, then
get_report_information, and get_expanded_lines to open one line); this module holds the parts that need no
Odoo: which reports exist here, the dates, finding a line by name and trimming Odoo's answer.

Checked on Odoo 19 Enterprise (a copy of the company database): the report names below, the tax report
opening another variant unless one is chosen, each line's raw value in `no_format`, the draft warning key, and
ledgers fully opened being far too long for one answer (over 200 KB), so they are opened one line at a time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from .errors import ValidationFailed

DRAFT_WARNING = "account_reports.common_warning_draft_in_period"
MAX_LINES = 400  # lines in one answer; the size cap (OdooService) may cut more
SHOWN_CHOICES = 30  # line names listed when a line to open is not found or not clear


@dataclass(frozen=True)
class Report:
    key: str  # the name the AI passes, e.g. "profit and loss"
    names: tuple[str, ...]  # account.report names in English, as Odoo ships them
    aliases: tuple[str, ...] = ()
    ledger: str = ""  # "account" or "partner": the report must be opened at one line


CATALOG: tuple[Report, ...] = (
    Report("profit and loss", ("Profit and Loss",), ("p&l", "pnl", "p and l", "pl", "income statement", "profit")),
    Report("balance sheet", ("Balance Sheet",), ("bs",)),
    Report("trial balance", ("Trial Balance",), ("tb",)),
    Report("general ledger", ("General Ledger",), ("gl", "ledger"), ledger="account"),
    Report("partner ledger", ("Partner Ledger",), ("customer ledger", "vendor ledger", "supplier ledger"), ledger="partner"),
    Report("aged receivable", ("Aged Receivable",), ("aged receivables", "receivables ageing", "receivable ageing",
                                                      "ageing receivable", "debtors ageing")),
    Report("aged payable", ("Aged Payable",), ("aged payables", "payables ageing", "payable ageing",
                                                "ageing payable", "creditors ageing")),
    Report("tax report", ("Generic Tax report", "Tax Report", "Tax Return"),
           ("tax", "taxes", "tax return", "gst", "gst report", "gst summary", "gstr", "gstr1", "gstr 1", "gstr3b",
            "gstr 3b", "gst return", "gst returns")),
)
NAMES = ", ".join(r.key for r in CATALOG)
GST_RETURN_NOTE = (
    "This Odoo has no GSTR-1 or GSTR-3B report, so the return itself cannot be read here. These are the GST "
    "figures from Odoo's tax report, grouped by tax; file the return from them outside Odoo."
)


def _plain(text: str) -> str:
    text = text.lower().replace("&", " and ").replace("-", " ").replace("_", " ")
    return " ".join(re.sub(r"[^a-z0-9 ]", " ", text).split())


def find_report(name: Any) -> tuple[Report, bool]:
    """The catalog entry for what the AI asked, and whether it asked for a GST return."""
    if not isinstance(name, str) or not name.strip():
        raise ValidationFailed(f"report must name one of: {NAMES}")
    asked = _plain(name)
    shorter = asked[: -len(" report")] if asked.endswith(" report") else asked  # "profit and loss report"
    for report in CATALOG:
        known = (_plain(report.key), *map(_plain, report.names), *map(_plain, report.aliases))
        if asked in known or shorter in known:
            return report, asked.startswith("gst")
    raise ValidationFailed(f"there is no report '{name}' here. Reports Claude can read: {NAMES}")


def day(value: Any, what: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()):
        raise ValidationFailed(f"{what} must be a date written YYYY-MM-DD, e.g. 2026-04-01")
    try:
        return date.fromisoformat(value.strip()).isoformat()
    except ValueError:
        raise ValidationFailed(f"{what} '{value}' is not a real date") from None


def date_option(date_from: str | None, date_to: str | None, ranged: bool) -> dict:
    """previous_options["date"] for get_options. Balance sheet and aged reports are 'as of' one day."""
    if not date_to:
        raise ValidationFailed("date_to is needed: the last day of the period (YYYY-MM-DD)")
    if not ranged:
        return {"date_to": date_to, "filter": "custom", "mode": "single"}
    if not date_from:
        raise ValidationFailed("date_from is needed for this report: the first day of the period (YYYY-MM-DD)")
    if date_from > date_to:
        raise ValidationFailed("date_from is after date_to")
    return {"date_from": date_from, "date_to": date_to, "filter": "custom", "mode": "range"}


def column_labels(options: dict) -> list[str]:
    """One label per column. A label used twice (trial balance: opening and closing Balance) gets its group's
    header in front, e.g. "End Balance: Balance"."""
    columns = [c for c in options.get("columns") or [] if isinstance(c, dict)]
    names = [str(c.get("name") or c.get("expression_label") or f"column {i + 1}") for i, c in enumerate(columns)]
    groups = options.get("column_groups") or {}
    headers = [h for h in (options.get("column_headers") or [[]])[0] or [] if isinstance(h, dict)]
    # a header's forced_options are part of its group's (the group adds keys; their orders differ: trial balance)
    group_names = {}
    for key, group in groups.items():
        matching = [h for h in headers if isinstance(group, dict) and h.get("forced_options")
                    and _within(h["forced_options"], group.get("forced_options"))]
        if len(matching) == 1:
            group_names[key] = str(matching[0].get("name") or "")
    labels = []
    for i, (name, column) in enumerate(zip(names, columns, strict=True)):
        if names.count(name) > 1:
            head = group_names.get(column.get("column_group_key"), "")
            name = f"{head}: {name}" if head else f"{name} ({names[:i + 1].count(name)})"
        labels.append(name)
    return labels


def _within(part: Any, whole: Any) -> bool:
    if isinstance(part, dict):
        return isinstance(whole, dict) and all(k in whole and _within(v, whole[k]) for k, v in part.items())
    return part == whole


def _value(raw: Any) -> Any:
    if isinstance(raw, float):
        return round(raw, 2)
    return raw


def trim_line(line: dict, labels: list[str]) -> dict:
    """name, level and {column label: raw value}; empty cells are left out. can_open: Odoo can show its detail."""
    values = {}
    for label, cell in zip(labels, line.get("columns") or [], strict=False):
        raw = cell.get("no_format") if isinstance(cell, dict) else None
        if raw is None or raw == "" or raw is False:
            continue
        values[label] = _value(raw)
    shown: dict[str, Any] = {"name": str(line.get("name") or ""), "level": line.get("level"), "values": values}
    if line.get("unfoldable"):
        shown["can_open"] = True
    return shown


def is_zero(line: dict) -> bool:
    numbers = [v for v in line["values"].values() if isinstance(v, int | float) and not isinstance(v, bool)]
    return not line.get("can_open") and all(v == 0 for v in numbers) and len(numbers) == len(line["values"])


def is_load_more(line: dict) -> bool:
    """Odoo's "Load more..." line: ledgers give 80 entries per opened line (load_more_limit), then this one."""
    marks = re.sub(r"[^a-z]", "", f"{line.get('id')} {line.get('class')}".lower())
    return "loadmore" in marks or str(line.get("name") or "").lower().startswith("load more")


def pick_line(lines: list[dict], wanted: str, what: str) -> dict:
    """The one line that can be opened whose name matches wanted (exact, account code, or part of the name)."""
    text = " ".join(wanted.lower().split())
    openable = [line for line in lines if line.get("unfoldable") and line.get("name")]

    def name(line: dict) -> str:
        return " ".join(str(line["name"]).lower().split())

    def code_and_rest(line: dict) -> tuple[str, str]:
        first, _, rest = name(line).partition(" ")
        return (first, rest) if any(ch.isdigit() for ch in first) else ("", name(line))

    for test in (
        lambda line: name(line) == text,
        lambda line: code_and_rest(line)[0] == text,
        lambda line: code_and_rest(line)[1] == text,
        lambda line: text in name(line),
    ):
        found = [line for line in openable if test(line)]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            shown = ", ".join(str(line["name"]) for line in found[:SHOWN_CHOICES])
            raise ValidationFailed(f"several {what}s match '{wanted}': {shown}. Ask the person which one they mean")
    if not openable:
        raise ValidationFailed(f"this report has no {what} with entries in this period, so there is nothing to open")
    shown = ", ".join(str(line["name"]) for line in openable[:SHOWN_CHOICES])
    more = f" (and {len(openable) - SHOWN_CHOICES} more)" if len(openable) > SHOWN_CHOICES else ""
    raise ValidationFailed(
        f"no {what} named '{wanted}' has entries in this report for this period. Ones that do: {shown}{more}"
    )


def action_link(url: str, actions: Any, report_id: int) -> str | None:
    """The address of Odoo's own screen for this report, from its client actions (context {'report_id': N})."""
    for action in actions if isinstance(actions, list) else []:
        if not isinstance(action, dict):
            continue
        found = re.search(r"['\"]report_id['\"]\s*:\s*(\d+)", str(action.get("context") or ""))
        if found and int(found.group(1)) == report_id:
            path = action.get("path")
            if isinstance(path, str) and re.fullmatch(r"[a-z0-9_-]+", path):
                return f"{url}/odoo/{path}"
            return f"{url}/odoo/action-{int(action['id'])}"
    return None
