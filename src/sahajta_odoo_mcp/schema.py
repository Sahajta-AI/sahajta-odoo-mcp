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
    def __init__(self, ttl_seconds: int = 600, max_entries: int = 2000):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._data: OrderedDict[tuple, tuple[float, dict]] = OrderedDict()

    async def fields(self, client: OdooClient, model: str) -> dict[str, dict]:
        identity = await client.identity()
        key = (client.creds.url, client.creds.db, identity.uid, model)
        hit = self._data.get(key)
        now = time.monotonic()
        if hit and hit[0] > now:
            self._data.move_to_end(key)
            return hit[1]
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
        self._data[key] = (now + self._ttl, result)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)
        return result

    def clear(self) -> None:
        self._data.clear()
