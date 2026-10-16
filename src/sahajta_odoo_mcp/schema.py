"""Cached model metadata (fields_get), per Odoo user, since field visibility depends on groups."""

from __future__ import annotations

import time
from collections import OrderedDict

from .errors import OdooError, ValidationFailed
from .odoo_client import OdooClient

FIELD_ATTRIBUTES = [
    "string",
    "type",
    "required",
    "readonly",
    "relation",
    "relation_field",
    "selection",
    "help",
    "store",
    "searchable",
    "sortable",
    "groupable",
    "aggregator",
    "group_operator",
    "currency_field",
]


class SchemaCache:
    def __init__(self, ttl_seconds: int = 600, max_entries: int = 2000, shared=None):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._data: OrderedDict[tuple, tuple[float, dict]] = OrderedDict()
        # Optional cache shared by all server instances (Redis): fields_get is the heaviest Odoo call.
        self._shared = shared

    async def fields(self, client: OdooClient, model: str) -> dict[str, dict]:
        identity = await client.identity()
        key = (client.creds.url, client.creds.db, identity.uid, model)
        hit = self._data.get(key)
        now = time.monotonic()
        if hit and hit[0] > now:
            self._data.move_to_end(key)
            return hit[1]
        shared_key = f"fields:{client.creds.url}|{client.creds.db}|{identity.uid}|{model}"
        cached = self._shared.get_json(shared_key) if self._shared is not None else None
        if isinstance(cached, dict) and cached:
            self._store(key, cached, now)
            return cached
        try:
            result = await client.call(model, "fields_get", attributes=FIELD_ATTRIBUTES)
        except OdooError as exc:
            if exc.kind == "missing":
                raise ValidationFailed(
                    f"model '{model}' does not exist in this Odoo (use odoo_list_models to find the right name)"
                ) from exc
            raise
        if not isinstance(result, dict):
            raise OdooError(f"unexpected fields_get answer for {model}", kind="server")
        result.setdefault("id", {"type": "integer", "string": "ID", "readonly": True, "store": True})
        self._store(key, result, now)
        if self._shared is not None:
            self._shared.set_json(shared_key, result, self._ttl)
        return result

    def _store(self, key: tuple, result: dict, now: float) -> None:
        self._data[key] = (now + self._ttl, result)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def clear(self) -> None:
        self._data.clear()
