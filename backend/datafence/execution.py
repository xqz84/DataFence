"""Materialize local synthetic data lineage after the response policy gate.

QUERY creates a snapshot. API calls page without replacement into one cumulative
object. File operations copy existing snapshots; uploads can only consume an
existing parent. There is no network, external connector, filesystem export or LLM.
"""

from datetime import datetime, timezone

from .models import SecurityEvent


class SandboxExecutor:
    def __init__(self, customers: list[dict]):
        rows = []
        seen = set()
        for customer in customers:
            customer_id = customer.get("id")
            region = customer.get("region")
            if customer.get("synthetic") is not True or not isinstance(customer_id, str) or not customer_id.startswith("SYN-"):
                raise ValueError("executor accepts only explicitly synthetic customer identifiers")
            if customer_id in seen or not isinstance(region, str):
                raise ValueError("synthetic customers require distinct identifiers and a region")
            seen.add(customer_id)
            rows.append((customer_id, region))
        self._customers = tuple(sorted(rows))
        self._objects: dict[tuple[str, str, str], tuple[str, ...]] = {}

    @staticmethod
    def _key(event: SecurityEvent, object_id: str) -> tuple[str, str, str]:
        return event.employee_id, event.session_id, object_id

    def _parent(self, event: SecurityEvent) -> tuple[str, ...]:
        if not event.parent_object_id:
            raise ValueError(f"{event.event_type} requires an existing parent object")
        parent = self._objects.get(self._key(event, event.parent_object_id))
        if parent is None:
            raise ValueError(f"{event.event_type} parent object has not been materialized in this session")
        return parent

    def execute(self, event: SecurityEvent, blocked: bool) -> dict:
        if not isinstance(event, SecurityEvent):
            raise TypeError("execute requires a SecurityEvent")
        if blocked:
            return {"record_count": 0, "receipt": None}
        if event.event_type in {"LOGIN", "AI_PROMPT"}:
            # AI_PROMPT is only a request event in this PoC. No AI output exists.
            return {"record_count": 0, "receipt": None}
        if event.event_type in {"QUERY", "API"}:
            if not event.object_id:
                raise ValueError("a data read requires an output object identifier")
            regions = set(event.regions)
            key = self._key(event, event.object_id)
            previous = self._objects.get(key, ()) if event.event_type == "API" else ()
            already_read = set(previous)
            selected = tuple(customer_id for customer_id, region in self._customers
                             if region in regions and customer_id not in already_read)[:event.record_count]
            self._objects[key] = previous + selected
            return {"record_count": len(selected), "receipt": None}
        if event.event_type in {"EXPORT", "COMPRESS"}:
            parent = self._parent(event)
            if not event.object_id:
                raise ValueError("a file operation requires an output object identifier")
            self._objects[self._key(event, event.object_id)] = parent
            return {"record_count": len(parent), "receipt": None}
        if event.event_type == "UPLOAD":
            parent = self._parent(event)
            receipt = {"event_id": event.event_id, "channel": event.channel, "synthetic": True,
                       "customer_ids": list(parent), "source_object_id": event.parent_object_id,
                       "received_at": datetime.now(timezone.utc).isoformat()}
            return {"record_count": len(parent), "receipt": receipt}
        raise ValueError("unsupported synthetic event type")
