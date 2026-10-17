"""Event model shared by the generator, engine, triage and dashboard."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

from . import schema as S


def _iso(dt: datetime) -> str:
    """Splunk and ECS both accept ISO-8601 with an explicit UTC offset."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(slots=True)
class Event:
    """A single telemetry record.

    `fields` holds the flattened, ECS-style key/value pairs.  Keeping them in a
    flat dict (instead of nested objects) is deliberate: it is exactly how
    Splunk stores events internally, and it keeps rule authoring simple.
    """

    timestamp: datetime
    source: str
    fields: dict[str, Any] = field(default_factory=dict)
    #: Set on events that belong to a simulated attack; used by the evaluation
    #: harness to measure how many real attacks our rules actually catch.
    ground_truth: bool = False
    #: Scenario the event was generated for, e.g. "brute_force".
    scenario: str = ""
    #: Extra labels, e.g. {"stage": "credential_access"}.
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.fields.setdefault(S.TIMESTAMP, _iso(self.timestamp))
        self.fields.setdefault(S.SOURCE_NAME, self.source)
        self.fields.setdefault(S.EVENT_CATEGORY, "unknown")
        self.fields.setdefault(S.EVENT_TYPE, "unknown")
        self.fields.setdefault(S.EVENT_OUTCOME, "unknown")
        self.fields.setdefault(S.EVENT_ID, "")

    # -- convenience accessors ------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def __contains__(self, key: str) -> bool:
        return key in self.fields

    @property
    def event_id(self) -> str:
        return str(self.fields.get(S.EVENT_CODE) or self.fields.get(S.EVENT_ID) or "")

    @property
    def host(self) -> str:
        return str(self.fields.get(S.HOST_NAME, "unknown"))

    @property
    def user(self) -> str:
        return str(self.fields.get(S.USER_NAME, "unknown"))

    @property
    def src_ip(self) -> str:
        return str(self.fields.get(S.SRC_IP, ""))

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        out = {
            "timestamp": _iso(self.timestamp),
            "source": self.source,
            "ground_truth": self.ground_truth,
            "scenario": self.scenario,
            "fields": dict(self.fields),
        }
        if self.labels:
            out["labels"] = dict(self.labels)
        return out

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Event":
        ts = payload.get("timestamp") or payload.get("fields", {}).get(S.TIMESTAMP)
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return cls(
            timestamp=dt,
            source=payload.get("source", "unknown"),
            fields=dict(payload.get("fields", {})),
            ground_truth=bool(payload.get("ground_truth", False)),
            scenario=payload.get("scenario", ""),
            labels=dict(payload.get("labels", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)


def events_to_jsonl(events: Iterable[Event]) -> str:
    return "\n".join(e.to_json() for e in events)


def events_from_jsonl(blob: str) -> list[Event]:
    out: list[Event] = []
    for line in blob.splitlines():
        line = line.strip()
        if line:
            out.append(Event.from_dict(json.loads(line)))
    return out


def to_dataclass_dict(event: Event) -> dict[str, Any]:
    """Flat dict of a single event (used by the dashboard / CSV exports)."""
    d = asdict(event)
    d["fields"] = dict(event.fields)
    return d
