"""Checks everything the AI sends before it reaches Odoo.

The point is twofold:
  * anti-hallucination: field names, selection values and record ids must really
    exist in this Odoo, otherwise the request is rejected with a helpful hint;
  * safety: relational "commands" that would delete or detach existing records
    (one2many/many2many commands 2, 3, 5, 6 and friends) are refused. The one exception is removing a
    line from a document that is still a draft (policy.LINE_REMOVAL), whose state is asked from Odoo.
"""

from __future__ import annotations

import ast
import difflib
import json
import math
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import OdooError, PolicyViolation, ValidationFailed
from .odoo_client import OdooClient
from .policy import (
    ANALYTIC_FIELD,
    AUTOMATION_MODEL,
    HIDDEN_FIELDS,
    LIMITED_MODELS,
    SERVER_ACTION_MODEL,
    SafetyPolicy,
    is_sensitive_field,
)
from .schema import SchemaCache

DOMAIN_OPERATORS = frozenset(
    {
        "=", "!=", ">", ">=", "<", "<=", "=?", "like", "not like", "ilike", "not ilike", "=like", "=ilike",
        "in", "not in", "child_of", "parent_of", "any", "not any",
    }
)
RELATIONAL = frozenset({"many2one", "one2many", "many2many"})
CHOICE_OPERATORS = frozenset({"=", "!=", "=?", "in", "not in"})  # operators that compare with selection keys
DAY_OPERATORS = frozenset({"=", "!=", "=?", "<", "<=", ">", ">="})  # operators that accept a whole day
_NO_CHOICE = object()
MAX_DOMAIN_TERMS = 100
MAX_PATH_DEPTH = 4
MAX_NESTING = 3
MAX_STRING_CHARS = 100_000
MAX_VALUES_PER_RECORD = 150
MAX_IDS_PER_COMMAND = 500
MAX_NESTED_COMMANDS = 100  # line creations/edits inside one change
MAX_ANALYTIC_KEYS = 100
ANALYTIC_ACCOUNT_MODEL = "account.analytic.account"
# What an automation rule's existing actions are checked on.
_ACTION_CHECK_FIELDS = (
    "name", "state", "model_id", "evaluation_type", "update_path", "value", "html_value", "resource_ref",
    "update_boolean_value", "update_m2m_operation", "mail_post_method",
)
_HIDDEN = "is hidden for safety (secret addresses and Python code)"


def suggest(name: str, fields: dict[str, dict]) -> str:
    candidates = difflib.get_close_matches(name, list(fields), n=3, cutoff=0.6)
    lowered = name.replace("_", " ").lower()
    for fname, meta in fields.items():
        if str(meta.get("string", "")).lower() == lowered and fname not in candidates:
            candidates.insert(0, fname)
    return f" Did you mean: {', '.join(candidates[:3])}?" if candidates else ""


def user_zone(tz: str | None, default: str | None = "UTC") -> ZoneInfo:
    """The Odoo user's time zone; default (MCP_DEFAULT_TIMEZONE) when it is empty or invalid, then UTC."""
    for name in (tz, default):
        if name:
            try:
                return ZoneInfo(name)
            except (ZoneInfoNotFoundError, ValueError):
                pass
    return ZoneInfo("UTC")


def to_utc_string(value: str, zone: ZoneInfo) -> str:
    """Accepts ISO-8601. Naive values are the Odoo user's local time; Odoo stores UTC."""
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


class Validator:
    def __init__(
        self, *, client: OdooClient, schema: SchemaCache, policy: SafetyPolicy, tz: str | None, default_tz: str = "UTC"
    ):
        self.client = client
        self.schema = schema
        self.policy = policy
        self.zone = user_zone(tz, default_tz)

    async def fields_of(self, model: str, *, refresh: bool = False) -> dict[str, dict]:
        """Field metadata, without the fields hidden for safety: to every tool they do not exist."""
        fields = await self.schema.fields(self.client, model, refresh=refresh)
        hidden = HIDDEN_FIELDS.get(model)
        return {name: meta for name, meta in fields.items() if name not in hidden} if hidden else fields

    async def _fields_with(self, model: str, names: list) -> dict[str, dict]:
        """Fields of model, asked again from Odoo once if a name is unknown: it may have been added since caching."""
        fields = await self.fields_of(model)
        hidden = HIDDEN_FIELDS.get(model, ())
        if any(isinstance(name, str) and name not in fields and name not in hidden for name in names):
            fields = await self.fields_of(model, refresh=True)
        return fields

    async def _fresh_meta(self, model: str, name: str, meta: dict) -> dict:
        """The field's metadata asked again from Odoo, e.g. for a choice added since caching."""
        fresh = (await self.fields_of(model, refresh=True)).get(name)
        return fresh if fresh and fresh.get("type") == meta.get("type") else meta

    # ------------------------------------------------------------------ field lists

    async def check_field_names(self, model: str, names: list[str]) -> list[str]:
        if not isinstance(names, list):
            raise ValidationFailed("fields must be a list of field names")
        fields = await self._fields_with(
            model, [n for n in names if isinstance(n, str) and n and "." not in n and not is_sensitive_field(n)]
        )
        problems: list[str] = []
        seen: list[str] = []
        for name in names:
            if not isinstance(name, str) or not name:
                problems.append(f"invalid field name {name!r}")
            elif "." in name:
                problems.append(f"'{name}': dotted paths are not readable directly; read the related record instead")
            elif is_sensitive_field(name):
                problems.append(f"'{name}' looks like a credential/secret and is never returned")
            elif name in HIDDEN_FIELDS.get(model, ()):
                problems.append(f"'{name}' on {model} {_HIDDEN} and is never returned")
            elif name not in fields:
                problems.append(f"'{name}' is not a field of {model}.{suggest(name, fields)}")
            elif fields[name].get("relation") and self.policy.model_read_block_reason(fields[name]["relation"]):
                problems.append(f"'{name}' points to a blocked model ({fields[name]['relation']}) and cannot be read")
            elif name not in seen:
                seen.append(name)
        if problems:
            raise ValidationFailed(problems)
        return seen

    async def resolve_path(self, model: str, path: str) -> tuple[str, dict]:
        """Follow a dotted path like 'partner_id.country_id.code'; returns (owning model, field meta)."""
        if not isinstance(path, str) or not path:
            raise ValidationFailed(f"invalid field path {path!r}")
        parts = path.split(".")
        if len(parts) > MAX_PATH_DEPTH:
            raise ValidationFailed(f"'{path}' is nested too deeply (max {MAX_PATH_DEPTH} levels)")
        current = model
        meta: dict = {}
        for index, part in enumerate(parts):
            fields = await self.fields_of(current)
            if is_sensitive_field(part):
                raise ValidationFailed(f"'{path}' refers to a credential/secret field, which cannot be searched")
            if part in HIDDEN_FIELDS.get(current, ()):
                raise ValidationFailed(f"'{path}': {current}.{part} {_HIDDEN} and cannot be searched")
            if part not in fields:
                fields = await self.fields_of(current, refresh=True)
            if part not in fields:
                raise ValidationFailed(f"'{part}' (in '{path}') is not a field of {current}.{suggest(part, fields)}")
            meta = fields[part]
            if meta.get("searchable") is False:
                # Odoo would fail with a technical error; say what to do instead
                hint = _search_alternatives(part, fields)
                raise ValidationFailed(
                    f"'{path}' cannot be searched: Odoo works out {current}.{part} when it shows a record and does not "
                    "store it. Search on a stored field instead"
                    + (f", e.g. {', '.join(hint)}." if hint else " (odoo_describe_model lists them).")
                )
            if meta.get("relation"):
                # covers the last segment too: no filtering on, or name-searching of, blocked models
                self.policy.check_read(meta["relation"])
            if index < len(parts) - 1:
                if meta.get("type") not in RELATIONAL or not meta.get("relation"):
                    raise ValidationFailed(f"'{part}' in '{path}' is not a relation, so it cannot be followed with '.'")
                current = meta["relation"]
        return current, meta

    # ------------------------------------------------------------------ domains

    async def normalize_domain(self, model: str, domain: Any, _depth: int = 0) -> list:
        if domain is None:
            return []
        if not isinstance(domain, list):
            raise ValidationFailed("domain must be a list, e.g. [[\"state\", \"=\", \"sale\"]]")
        if len(domain) > MAX_DOMAIN_TERMS:
            raise ValidationFailed(f"domain is too long (max {MAX_DOMAIN_TERMS} elements)")
        _check_domain_arity(domain)
        out: list = []
        for element in domain:
            if element in ("&", "|", "!"):
                out.append(element)
                continue
            if not (isinstance(element, (list, tuple)) and len(element) == 3):
                raise ValidationFailed(
                    f"invalid domain element {element!r}; each condition is [field, operator, value] or '&', '|', '!'"
                )
            path, operator, value = element
            if not isinstance(operator, str) or operator.lower() not in DOMAIN_OPERATORS:
                raise ValidationFailed(
                    f"unknown domain operator {operator!r}; use one of: {', '.join(sorted(DOMAIN_OPERATORS))}"
                )
            operator = operator.lower()
            owner, meta = await self.resolve_path(model, path)
            if operator in ("any", "not any"):
                if meta.get("type") not in RELATIONAL:
                    raise ValidationFailed(f"'{operator}' only works on relational fields, not '{path}'")
                if _depth >= MAX_NESTING:
                    raise ValidationFailed("domain is nested too deeply")
                value = await self.normalize_domain(meta["relation"], value, _depth + 1)
            elif meta.get("type") == "selection" and operator in CHOICE_OPERATORS:
                value = await self._domain_choices(owner, path, meta, value)
            elif meta.get("type") == "datetime":
                # one condition may become a prefix group ('&' or '!'), which stays a single operand
                out.extend(self._datetime_terms(path, operator, value))
                continue
            out.append([path, operator, value])
        return out

    async def _domain_choices(self, owner: str, path: str, meta: dict, value: Any) -> Any:
        """Selection keys only: an unknown key would silently match nothing. An exact label is mapped to its key."""
        values = value if isinstance(value, (list, tuple)) else [value]
        keys = [v if v is False or v is None else _choice(meta, v, by_label=True) for v in values]
        if _NO_CHOICE in keys:
            meta = await self._fresh_meta(owner, path.rsplit(".", 1)[-1], meta)
            keys = [v if v is False or v is None else _choice(meta, v, by_label=True) for v in values]
        bad = [v for v, key in zip(values, keys, strict=True) if key is _NO_CHOICE]
        if bad:
            raise ValidationFailed(f"'{path}': {bad[0]!r} is not a valid choice. Valid values: {_choices_shown(meta)}")
        return keys if isinstance(value, (list, tuple)) else keys[0]

    def _datetime_terms(self, path: str, operator: str, value: Any) -> list:
        """Datetime conditions in UTC. A bare date (YYYY-MM-DD) means that whole day in the user's time zone."""
        values = value if isinstance(value, (list, tuple)) else [value]
        days = [_day(v) for v in values]
        if any(days) and (operator not in DAY_OPERATORS or isinstance(value, (list, tuple))):
            raise ValidationFailed(
                f"'{path}' is a date-time, so '{operator}' with a date only is ambiguous. Use a range instead: "
                f"[\"{path}\", \">=\", \"YYYY-MM-DD\"], [\"{path}\", \"<=\", \"YYYY-MM-DD\"]"
            )
        try:
            if not any(days):
                return [[path, operator, self._domain_value(value)]]
            start = to_utc_string(days[0].isoformat(), self.zone)
            end = to_utc_string((days[0] + timedelta(days=1)).isoformat(), self.zone)
        except (ValueError, OverflowError) as exc:
            raise ValidationFailed(f"'{path}': {value!r} is not a valid date/time (use YYYY-MM-DD HH:MM:SS)") from exc
        if operator in ("=", "=?"):
            return ["&", [path, ">=", start], [path, "<", end]]
        if operator == "!=":
            return ["!", "&", [path, ">=", start], [path, "<", end]]
        if operator in ("<", ">="):
            return [[path, operator, start]]
        return [[path, "<" if operator == "<=" else ">=", end]]

    def _domain_value(self, value: Any) -> Any:
        if isinstance(value, str) and value:
            return to_utc_string(value, self.zone)
        if isinstance(value, (list, tuple)):
            return [to_utc_string(v, self.zone) if isinstance(v, str) and v else v for v in value]
        return value

    # ------------------------------------------------------------------ values for create / write

    async def normalize_values(self, model: str, values: Any, *, mode: str, record_ids: list[int] | None = None) -> dict:
        self.policy.check_change(model, mode)  # e.g. accounting setup: create only; e-mail templates: edit only
        refs: dict[str, set[int]] = defaultdict(set)
        result = await self._normalize_values(model, values, mode=mode, record_ids=record_ids, depth=0, refs=refs, inverse=None)
        if model == AUTOMATION_MODEL:
            await self._check_automation(result, mode=mode, record_ids=record_ids, refs=refs)
        await self._verify_refs(refs)
        return result

    async def _normalize_values(
        self,
        model: str,
        values: Any,
        *,
        mode: str,
        record_ids: list[int] | None,
        depth: int,
        refs: dict[str, set[int]],
        inverse: str | None,
    ) -> dict:
        if depth > MAX_NESTING:
            raise ValidationFailed("values are nested too deeply")
        if not isinstance(values, dict) or not values:
            raise ValidationFailed(f"values for {model} must be a non-empty object of field: value")
        if len(values) > MAX_VALUES_PER_RECORD:
            raise ValidationFailed(f"too many fields in one record (max {MAX_VALUES_PER_RECORD})")
        fields = await self._fields_with(model, list(values))
        problems: list[str] = []
        out: dict = {}
        for name, value in values.items():
            if isinstance(name, str) and name in HIDDEN_FIELDS.get(model, ()):
                problems.append(f"{model}.{name} {_HIDDEN} and can never be set")
                continue
            if not isinstance(name, str) or name not in fields:
                problems.append(f"'{name}' is not a field of {model}.{suggest(str(name), fields)}")
                continue
            meta = fields[name]
            if inverse and name == inverse:
                problems.append(f"{model}.{name} is set automatically from the parent record; leave it out")
                continue
            reason = self.policy.field_write_block_reason(name, meta, model=model, creating=mode == "create")
            if reason:
                problems.append(f"{model}.{name} {reason}")
                continue
            try:
                out[name] = await self._value(model, name, meta, value, mode=mode, record_ids=record_ids, depth=depth, refs=refs)
            except ValidationFailed as exc:
                problems.extend(exc.problems)
        if problems:
            raise ValidationFailed(problems)
        if len(json.dumps(out, default=str)) > 1_000_000:
            raise ValidationFailed("the values are too large")
        return out

    async def _value(self, model, name, meta, value, *, mode, record_ids, depth, refs) -> Any:
        ftype = meta.get("type")
        label = f"{model}.{name}"
        if value is None or (value is False and ftype != "boolean"):
            if meta.get("required"):
                raise ValidationFailed(f"{label} is required and cannot be emptied")
            return False
        if ftype in ("char", "text", "html"):
            if not isinstance(value, str):
                raise ValidationFailed(f"{label} must be text")
            if meta.get("required") and not value.strip():
                raise ValidationFailed(f"{label} is required and cannot be emptied")
            if len(value) > MAX_STRING_CHARS:
                raise ValidationFailed(f"{label} is too long (max {MAX_STRING_CHARS} characters)")
            return value
        if ftype == "selection":
            key = _choice(meta, value)
            if key is _NO_CHOICE:
                meta = await self._fresh_meta(model, name, meta)
                key = _choice(meta, value)
            if key is _NO_CHOICE:
                raise ValidationFailed(f"{label}: {value!r} is not a valid choice. Valid values: {_choices_shown(meta)}")
            return key
        if ftype == "boolean":
            if not isinstance(value, bool):
                raise ValidationFailed(f"{label} must be true or false")
            return value
        if ftype in ("integer", "many2one_reference"):
            if not _is_int(value):
                raise ValidationFailed(f"{label} must be a whole number")
            return value
        if ftype in ("float", "monetary"):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValidationFailed(f"{label} must be a number")
            return value
        if ftype == "date":
            text = value.strip() if isinstance(value, str) else ""
            try:
                if len(text) != 10:
                    raise ValueError(text)
                return date.fromisoformat(text).isoformat()
            except ValueError as exc:
                raise ValidationFailed(f"{label}: {value!r} is not a valid date (use YYYY-MM-DD)") from exc
        if ftype == "datetime":
            if not isinstance(value, str):
                raise ValidationFailed(f"{label} must be a date-time string")
            try:
                return to_utc_string(value, self.zone)
            except ValueError as exc:
                raise ValidationFailed(f"{label}: {value!r} is not a valid date-time (YYYY-MM-DD HH:MM:SS)") from exc
        if ftype == "many2one":
            if isinstance(value, list) and value and _is_int(value[0]):
                value = value[0]
            if not _is_int(value) or value <= 0:
                raise ValidationFailed(
                    f"{label} must be the numeric id of a {meta.get('relation')} record "
                    "(look it up with odoo_find or odoo_search; never guess ids)"
                )
            refs[meta["relation"]].add(value)
            return value
        if ftype == "reference":
            if not isinstance(value, str) or "," not in value:
                raise ValidationFailed(f"{label} must look like 'model.name,ID'")
            ref_model, _, ref_id = value.partition(",")
            reason = self.policy.model_read_block_reason(ref_model.strip())
            if reason or not (ref_id.strip().isascii() and ref_id.strip().isdigit()):
                raise ValidationFailed(f"{label}: invalid reference {value!r}")
            refs[ref_model.strip()].add(int(ref_id))
            return f"{ref_model.strip()},{int(ref_id)}"
        if ftype == "json" and name == ANALYTIC_FIELD:
            return _analytic_distribution(label, value, refs)
        if ftype == "many2many":
            commands = await self._many2many(model, name, label, meta, value, depth=depth, refs=refs)
            if meta.get("required") and commands in ([[6, 0, []]], [[5, 0, 0]]):
                raise ValidationFailed(f"{label} is required and cannot be emptied")
            return commands
        if ftype == "one2many":
            return await self._one2many(model, name, label, meta, value, mode=mode, record_ids=record_ids, depth=depth, refs=refs)
        raise ValidationFailed(f"{label}: fields of type '{ftype}' cannot be written through this server")

    async def _many2many(self, model, name, label, meta, value, *, depth, refs) -> list:
        comodel = meta["relation"]
        if not isinstance(value, list):
            raise ValidationFailed(f"{label} must be a list of ids or of commands")
        if all(_is_int(v) for v in value):
            ids = list(dict.fromkeys(value))
            _check_ids(label, ids)
            refs[comodel].update(ids)
            return [[6, 0, ids]]
        commands: list = []
        for command in value:
            code = _command_code(label, command)
            if code == 0:
                self.policy.check_nested_write(model, name, comodel, creating=True)
                _spend(refs, label)
                vals = await self._normalize_values(comodel, _command_vals(label, command), mode="create", record_ids=None, depth=depth + 1, refs=refs, inverse=None)
                commands.append([0, 0, vals])
            elif code == 1:
                raise ValidationFailed(
                    f"{label}: command 1 would edit the linked {comodel} record itself, which may be shared with other "
                    f"records; change it directly on {comodel} instead"
                )
            elif code == 2:
                raise ValidationFailed(f"{label}: command 2 would DELETE the linked {comodel} record; deleting is not allowed")
            elif code in (3, 4):
                rid = _command_id(label, command)
                refs[comodel].add(rid)
                commands.append([code, rid, 0])
            elif code == 5:
                commands.append([5, 0, 0])
            elif code == 6:
                ids = command[2] if len(command) > 2 else None
                if not isinstance(ids, list) or not all(_is_int(i) for i in ids):
                    raise ValidationFailed(f"{label}: command 6 needs a list of ids: [6, 0, [ids]]")
                _check_ids(label, ids)
                refs[comodel].update(ids)
                commands.append([6, 0, list(dict.fromkeys(ids))])
            else:
                raise ValidationFailed(f"{label}: unknown command {code}")
        return commands

    async def _one2many(self, model, name, label, meta, value, *, mode, record_ids, depth, refs) -> list:
        comodel = meta["relation"]
        inverse = meta.get("relation_field")
        if not isinstance(value, list):
            raise ValidationFailed(f"{label} must be a list of new lines (objects) or of [0, 0, {{...}}] / [1, id, {{...}}] commands")
        commands: list = []
        existing: set[int] | None = None
        touched: set[int] = set()  # lines removed or edited: each at most once
        removing = False  # the document's state was checked for removing lines
        for command in value:
            if isinstance(command, dict):
                command = [0, 0, command]
            if _is_int(command):
                raise ValidationFailed(
                    f"{label}: a plain list of ids would replace (and delete) the existing lines; "
                    "add lines with objects or [0, 0, {...}], edit them with [1, id, {...}]"
                )
            code = _command_code(label, command)
            if code == 0:
                self.policy.check_nested_write(model, name, comodel, creating=True)
                _spend(refs, label)
                vals = await self._normalize_values(comodel, _command_vals(label, command), mode="create", record_ids=None, depth=depth + 1, refs=refs, inverse=inverse)
                commands.append([0, 0, vals])
            elif code == 1:
                self.policy.check_nested_write(model, name, comodel, creating=False)
                rid = _command_id(label, command)
                if mode != "write" or not record_ids:
                    raise ValidationFailed(f"{label}: existing lines can only be edited on an existing record")
                if existing is None:
                    existing = await self._current_line_ids(model, name, record_ids)
                if rid not in existing:
                    raise ValidationFailed(f"{label}: line {rid} does not belong to the record(s) being changed")
                if rid in touched:
                    raise ValidationFailed(f"{label}: line {rid} is listed twice; give each line one command")
                touched.add(rid)
                _spend(refs, label)
                vals = await self._normalize_values(comodel, _command_vals(label, command), mode="write", record_ids=[rid], depth=depth + 1, refs=refs, inverse=inverse)
                commands.append([1, rid, vals])
            elif code == 2 and depth == 0 and self.policy.line_removal_states(model, name) is not None:
                # removing a line deletes it: only from a document that is still a draft (asked from Odoo each time)
                self.policy.check_nested_write(model, name, comodel, creating=False)
                rid = _command_id(label, command)
                if mode != "write" or not record_ids:
                    raise ValidationFailed(f"{label}: lines can only be removed from an existing record")
                if not removing:
                    await self._check_line_removal(model, name, record_ids)
                    removing = True
                if existing is None:
                    existing = await self._current_line_ids(model, name, record_ids)
                if rid not in existing:
                    raise ValidationFailed(f"{label}: line {rid} does not belong to the record(s) being changed")
                if rid in touched:
                    raise ValidationFailed(f"{label}: line {rid} is listed twice; give each line one command")
                touched.add(rid)
                _spend(refs, label)
                commands.append([2, rid, 0])
            elif code in (2, 3, 5, 6) and depth == 0 and self.policy.line_removal_states(model, name) is not None:
                raise ValidationFailed(
                    f"{label}: command {code} would detach or replace lines, which is not allowed; to remove one line "
                    "use [2, line_id, 0] (only while the document is a draft)"
                )
            elif code in (2, 3, 5, 6):
                raise ValidationFailed(
                    f"{label}: command {code} would delete or detach existing lines; removing lines is not allowed "
                    "through this server (a person can do it in Odoo)"
                )
            elif code == 4:
                raise ValidationFailed(f"{label}: command 4 would move a line away from another record; not allowed")
            else:
                raise ValidationFailed(f"{label}: unknown command {code}")
        return commands

    async def _check_line_removal(self, model: str, name: str, record_ids: list[int]) -> None:
        """Lines may be removed only while every document being changed is in an allowed state, asked from Odoo."""
        allowed = self.policy.line_removal_states(model, name) or frozenset()
        rows = await self.client.call(
            model, "read", ids=record_ids, fields=["display_name", "state"], context={"active_test": False}
        )
        refused = [
            self.policy.line_removal_refusal(model, row.get("display_name") or f"{model} {row['id']}")
            for row in rows or [] if row.get("state") not in allowed
        ]
        if refused:
            raise PolicyViolation("; ".join(refused))

    async def _current_line_ids(self, model: str, name: str, record_ids: list[int]) -> set[int]:
        rows = await self.client.call(model, "read", ids=record_ids, fields=[name], context={"active_test": False})
        line_ids: set[int] = set()
        for row in rows or []:
            line_ids.update(row.get(name) or [])
        return line_ids

    async def _verify_refs(self, refs: dict[str, set[int]]) -> None:
        problems: list[str] = []
        for comodel, ids in refs.items():
            if not ids or comodel == "__nested_commands__":
                continue
            wanted = sorted(ids)
            try:
                found = await self.client.call(comodel, "search", domain=[["id", "in", wanted]], context={"active_test": False})
            except OdooError as exc:
                if exc.kind == "access":
                    problems.append(f"cannot check {comodel} ids {wanted[:20]}: you do not have read access to {comodel}")
                    continue
                raise
            missing = [i for i in wanted if i not in set(found or [])]
            if missing:
                problems.append(
                    f"{comodel} record id(s) {missing[:20]} do not exist (or are not visible to you). "
                    "Look ids up with odoo_find / odoo_search instead of guessing."
                )
        if problems:
            raise ValidationFailed(problems)

    # ------------------------------------------------------------------ analytic distribution

    async def describe_analytic_distribution(self, value: Any) -> str:
        """Readable text for previews, e.g. 'Project Alpha 60%, Project Beta 40%'. Accounts it cannot name show as #id."""
        if not isinstance(value, dict) or not value:
            return "none"
        keys = {str(key): [p.strip() for p in str(key).split(",")] for key in value}
        ids = sorted({int(p) for parts in keys.values() for p in parts if p.isascii() and p.isdigit()})
        names: dict[int, str] = {}
        if ids:
            try:
                # the plain name: Odoo's display name adds the code and the partner ("Alpha - Acme Corp")
                rows = await self.client.call(
                    ANALYTIC_ACCOUNT_MODEL, "read", ids=ids, fields=["name"], context={"active_test": False}
                )
                names = {row["id"]: row.get("name") or f"#{row['id']}" for row in rows or []}
            except OdooError:
                pass  # a preview still shows the ids
        shown = []
        for key, share in value.items():
            parts = keys[str(key)]
            label = " / ".join(names.get(int(p), f"#{p}") if p.isascii() and p.isdigit() else p for p in parts)
            shown.append(f"{label} {_percent(share)}%")
        return ", ".join(shown)

    # ------------------------------------------------------------------ automation rules

    async def _check_automation(self, values: dict, *, mode: str, record_ids: list[int] | None, refs) -> None:
        """An automation rule as it will be after the change: an allowed trigger, literal filters, and only allowed
        actions, whose updates pass the same field rules as a normal change. Filters are stored normalised, and
        new actions get the rule's model."""
        if mode != "create" and values == {"active": False}:
            return  # switching rules off is always safe
        if mode == "create":
            if not values.get("model_id"):
                raise ValidationFailed(
                    f"{AUTOMATION_MODEL}.model_id is required: the id of the model (ir.model) whose records the rule watches"
                )
            model_id = values["model_id"]
            rule_model = await self._model_name(model_id)
            trigger = values.get("trigger")
            existing_ids: list[int] = []
        else:
            if len(record_ids or []) != 1:
                raise ValidationFailed("change automation rules one at a time (only archiving can cover several at once)")
            rows = await self.client.call(
                AUTOMATION_MODEL, "read", ids=record_ids, fields=["model_id", "model_name", "trigger", "action_server_ids"],
                context={"active_test": False},
            )
            if not rows:
                raise ValidationFailed(f"automation rule {record_ids[0]} does not exist or is not visible to you")
            model_id = _id_of(rows[0].get("model_id"))
            rule_model = rows[0].get("model_name") or None
            trigger = values.get("trigger", rows[0].get("trigger"))
            existing_ids = list(rows[0].get("action_server_ids") or [])
        if not rule_model:
            raise ValidationFailed(f"ir.model record id {model_id!r} does not exist (or is not visible to you)")
        if rule_model in LIMITED_MODELS:
            raise PolicyViolation(
                f"automation rules cannot watch setup records ({rule_model}); a person sets that up in Odoo"
            )
        reason = self.policy.model_write_block_reason(rule_model)
        if reason:
            raise PolicyViolation(f"automation rules can watch only records Claude may change itself: {reason}")
        problems: list[str] = []
        if not trigger:
            problems.append(f"{AUTOMATION_MODEL}.trigger is required: when the rule runs, e.g. 'on_create_or_write'")
        else:
            reason = self.policy.automation_trigger_block_reason(trigger)
            if reason:
                problems.append(reason)
        for key in ("filter_pre_domain", "filter_domain"):
            if values.get(key):
                try:
                    values[key] = await self._literal_domain(rule_model, f"{AUTOMATION_MODEL}.{key}", values[key])
                except ValidationFailed as exc:
                    problems.extend(exc.problems)
        commands = values.get("action_server_ids") or []
        for command in commands:
            if command[0] == 0:
                sent = command[2]
                if sent.setdefault("model_id", model_id) != model_id:
                    problems.append(
                        f"action '{sent.get('name')}' must use the rule's model ({rule_model}); leave model_id out"
                    )
        for action, sent in await self._actions_after(commands, existing_ids):
            reason = self.policy.automation_action_block_reason(action, trigger=trigger)
            if reason:
                problems.append(reason)
            elif action.get("state") == "object_write":
                problems.extend(await self._update_action_problems(rule_model, action, sent, refs))
        if problems:
            raise ValidationFailed(problems)

    async def _model_name(self, model_id: Any) -> str | None:
        rows = await self.client.call("ir.model", "read", ids=[model_id], fields=["model"])
        return rows[0].get("model") if rows else None

    async def _literal_domain(self, model: str, label: str, text: Any) -> str:
        """A filter stored as text: a plain list of conditions with fixed values, checked like a search."""
        try:
            domain = ast.literal_eval(text.strip())
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            domain = None
        if not isinstance(domain, list):
            raise ValidationFailed(
                f"{label} must be a plain list of conditions with fixed values, e.g. [(\"state\", \"=\", \"draft\")]; "
                "expressions such as uid or context_today() are not allowed"
            )
        try:
            normalized = await self.normalize_domain(model, domain)
        except ValidationFailed as exc:
            raise ValidationFailed([f"{label}: {problem}" for problem in exc.problems]) from exc
        return repr(normalized)

    async def _actions_after(self, commands: list, existing_ids: list[int]) -> list[tuple[dict, dict | None]]:
        """Each action of the rule as it will be after the change, with the values sent for it (None if untouched)."""
        edits = {command[1]: command[2] for command in commands if command[0] == 1}
        actions: list[tuple[dict, dict | None]] = []
        if existing_ids:
            known = await self.fields_of(SERVER_ACTION_MODEL)
            rows = await self.client.call(
                SERVER_ACTION_MODEL, "read", ids=existing_ids, fields=[f for f in _ACTION_CHECK_FIELDS if f in known],
                context={"active_test": False},
            )
            for row in rows or []:
                sent = edits.get(row["id"])
                actions.append(({**row, "model_id": _id_of(row.get("model_id")), **(sent or {})}, sent))
        actions.extend((command[2], command[2]) for command in commands if command[0] == 0)
        return actions

    async def _update_action_problems(self, model: str, action: dict, sent: dict | None, refs) -> list[str]:
        """An 'update the record' action must pass the same rules as the same change made directly."""
        name = action.get("name") or "the update action"
        path = action["update_path"].strip()
        fields = await self._fields_with(model, [path])
        meta = fields.get(path)
        if meta is None:
            return [f"action '{name}': '{path}' is not a field of {model}.{suggest(path, fields)}"]
        reason = self.policy.change_block_reason(model, "write")
        if reason:
            return [f"action '{name}' cannot update {model}: {reason}"]
        reason = self.policy.field_write_block_reason(path, meta, model=model)
        if reason:
            return [f"action '{name}' would set {model}.{path}, which {reason}"]
        ftype = meta.get("type")
        text = str(action.get("value") or "").strip()

        async def check(value: Any) -> Any:  # the same check as writing value to the field directly
            return await self._value(model, path, meta, value, mode="write", record_ids=None, depth=0, refs=refs)

        try:
            if ftype in ("many2one", "many2many"):
                operation = action.get("update_m2m_operation") or "add"
                clearing = ftype == "many2many" and operation == "clear"
                target = None if clearing else _action_record_id(action, meta["relation"])
                if ftype == "many2one":
                    await check(target or False)
                elif target is not None:
                    refs[meta["relation"]].add(target)
                elif not clearing:
                    raise ValidationFailed(
                        f"{model}.{path}: name the {meta['relation']} record to {operation} (value or resource_ref)"
                    )
            elif ftype == "boolean":
                pass  # update_boolean_value is a choice of 'true' / 'false', checked as a field
            elif ftype == "html":
                await check(action.get("html_value") or False)
            elif ftype in ("char", "text", "selection", "date"):
                await check(text or False)
            elif ftype == "datetime":
                utc = await check(text or False)
                if sent is not None and sent.get("value"):
                    sent["value"] = utc  # Odoo writes the text as it is, and stores date-times in UTC
            elif ftype in ("integer", "float", "monetary"):
                number = _number(text, whole=ftype == "integer")
                if number is None:
                    kind = "a whole number" if ftype == "integer" else "a number"
                    raise ValidationFailed(f"{model}.{path} must be {kind}, not {text!r}")
                await check(number)
            else:
                raise ValidationFailed(f"{model}.{path}: fields of type '{ftype}' cannot be set by an automation rule")
        except ValidationFailed as exc:
            return [f"action '{name}': {problem}" for problem in exc.problems]
        return []


def _analytic_distribution(label: str, value: Any, refs: dict) -> dict:
    """{"analytic account id": percentage}; a key may join several ids with commas (one account per plan)."""
    if not isinstance(value, dict) or not value:
        raise ValidationFailed(
            f"{label} must be an object of analytic account id: percentage, e.g. {{\"12\": 60, \"15\": 40}}"
        )
    if len(value) > MAX_ANALYTIC_KEYS:
        raise ValidationFailed(f"{label}: too many analytic accounts (max {MAX_ANALYTIC_KEYS})")
    out: dict[str, Any] = {}
    seen: set[frozenset[int]] = set()
    problems: list[str] = []
    for key, share in value.items():
        ids = _analytic_ids(key)
        if ids is None:
            problems.append(
                f"{label}: {key!r} is not an analytic account id; use the id, or ids joined by commas "
                "(one per analytic plan), e.g. \"12\" or \"12,31\""
            )
        elif frozenset(ids) in seen:
            problems.append(f"{label}: {key!r} is listed twice")
        elif not _is_percentage(share):
            problems.append(f"{label}: the percentage for {key!r} must be a number above 0 and at most 100, not {share!r}")
        else:
            seen.add(frozenset(ids))
            out[",".join(str(i) for i in ids)] = share
            refs[ANALYTIC_ACCOUNT_MODEL].update(ids)
    if problems:
        raise ValidationFailed(problems)
    return out


def _analytic_ids(key: Any) -> list[int] | None:
    if _is_int(key):
        parts = [str(key)]
    elif isinstance(key, str):
        parts = [part.strip() for part in key.split(",")]
    else:
        return None
    if not all(part.isascii() and part.isdigit() for part in parts):
        return None
    ids = [int(part) for part in parts]
    if any(i <= 0 for i in ids) or len(set(ids)) != len(ids):
        return None
    return ids


def _is_percentage(share: Any) -> bool:
    return isinstance(share, (int, float)) and not isinstance(share, bool) and math.isfinite(share) and 0 < share <= 100


def _percent(share: Any) -> str:
    try:
        return f"{round(float(share), 2):g}"
    except (TypeError, ValueError):
        return str(share)


def _id_of(value: Any) -> Any:
    """The id in a many2one value as Odoo reads it ([id, name]), or the value itself."""
    return value[0] if isinstance(value, (list, tuple)) and value else value


def _number(text: str, *, whole: bool) -> int | float | None:
    try:
        number = int(text) if whole else float(text)
    except ValueError:
        return None
    return number if whole or math.isfinite(number) else None


def _action_record_id(action: dict, relation: str) -> int | None:
    """The record an update action puts into a relational field: from resource_ref ('model,id') or value ('id')."""
    ref = action.get("resource_ref")
    if isinstance(ref, str) and "," in ref:
        ref_model, _, text = ref.partition(",")
        if ref_model.strip() != relation:
            raise ValidationFailed(f"resource_ref must point at a {relation} record, not {ref!r}")
    else:
        text = str(action.get("value") or "")
    text = text.strip()
    if not text or text == "0":
        return None
    if not (text.isascii() and text.isdigit()):
        raise ValidationFailed(f"the value must be the numeric id of a {relation} record, not {text!r}")
    return int(text)


def _search_alternatives(name: str, fields: dict[str, dict]) -> list[str]:
    """Stored, searchable fields that look like name: complete_name -> name."""
    stored = [n for n, m in fields.items() if n != name and m.get("searchable") is not False and m.get("store", True)]
    hits = [n for n in stored if name.endswith(f"_{n}")] + difflib.get_close_matches(name, stored, n=3, cutoff=0.6)
    return list(dict.fromkeys(hits))[:3]


def _check_domain_arity(domain: list) -> None:
    """'&' and '|' need two operands, '!' one (Polish notation); reject malformed domains outright."""
    available = 0
    for element in reversed(domain):
        if element in ("&", "|"):
            if available < 2:
                raise ValidationFailed(f"malformed domain: '{element}' needs two conditions after it")
            available -= 1
        elif element == "!":
            if available < 1:
                raise ValidationFailed("malformed domain: '!' needs a condition after it")
        else:
            available += 1


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _choice(meta: dict, value: Any, *, by_label: bool = False) -> Any:
    """The selection key that value names, or _NO_CHOICE. Without a list of options, any value passes."""
    options = [option for option in meta.get("selection") or [] if isinstance(option, (list, tuple)) and option]
    if not options:
        return value
    for option in options:
        if str(option[0]) == str(value):
            return option[0]
    if by_label and isinstance(value, str):
        hits = [o[0] for o in options if len(o) > 1 and isinstance(o[1], str) and o[1].casefold() == value.casefold()]
        if len(hits) == 1:
            return hits[0]
    return _NO_CHOICE


def _choices_shown(meta: dict) -> str:
    return ", ".join(repr(option[0]) for option in (meta.get("selection") or [])[:30] if option)


def _day(value: Any) -> date | None:
    """The date if value is a date without a time, such as '2026-10-31'."""
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _spend(refs: dict, label: str) -> None:
    """Count nested line creations/edits for one change (stored in the refs dict under a reserved key)."""
    count = len(refs.setdefault("__nested_commands__", set())) + 1
    if count > MAX_NESTED_COMMANDS:
        raise ValidationFailed(f"{label}: too many line changes in one go (max {MAX_NESTED_COMMANDS})")
    refs["__nested_commands__"].add(count)


def _check_ids(label: str, ids: list) -> None:
    if len(ids) > MAX_IDS_PER_COMMAND:
        raise ValidationFailed(f"{label}: too many ids (max {MAX_IDS_PER_COMMAND})")
    if any(i <= 0 for i in ids):
        raise ValidationFailed(f"{label}: ids must be positive integers")


def _command_code(label: str, command: Any) -> int:
    if not isinstance(command, (list, tuple)) or not command or not _is_int(command[0]):
        raise ValidationFailed(f"{label}: invalid relational command {command!r}")
    return command[0]


def _command_id(label: str, command: Any) -> int:
    if len(command) < 2 or not _is_int(command[1]) or command[1] <= 0:
        raise ValidationFailed(f"{label}: command {command[0]} needs a record id as its second element")
    return command[1]


def _command_vals(label: str, command: Any) -> dict:
    if len(command) < 3 or not isinstance(command[2], dict):
        raise ValidationFailed(f"{label}: command {command[0]} needs an object of values as its third element")
    return command[2]
