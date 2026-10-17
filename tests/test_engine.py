"""Unit tests for the detection engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from soclab.engine import DetectionEngine, match_value
from soclab.events import Event
from soclab.rules import Rule, load_rules

BASE_TS = datetime(2026, 10, 5, 9, 0, 0, tzinfo=timezone.utc)


def make_event(**fields) -> Event:
    payload = {"event.code": "4625", "source.ip": "10.0.0.1"}
    payload.update(fields)
    return Event(timestamp=BASE_TS, source="windows_security", fields=payload)


def make_rule(**kwargs) -> Rule:
    base = dict(
        id="TEST-001",
        title="Test rule",
        severity="high",
        confidence="high",
        mitre={"tactic": "Credential Access", "technique": "T1110"},
        detection={"selection": {"event.code": "4625"}, "condition": "selection"},
    )
    base.update(kwargs)
    return Rule(**base)


# --- value matching ---------------------------------------------------------

@pytest.mark.parametrize(
    "actual,expected,expected_result",
    [
        ("4625", "4625", True),
        ("4625", "4624", False),
        ("abc", "ABC", True),          # case-insensitive by default
        ("powershell.exe", "*.exe", True),
        ("powershell.exe", "*.dll", False),
        (10, "10", True),
        (10, "9", False),
        (5, ">3", True),
        (2, ">3", False),
        (5, ">=5", True),
        (5, "<=5", True),
        (5, "!=5", False),
        (None, None, True),
        ("", None, True),
    ],
)
def test_match_value(actual, expected, expected_result):
    assert match_value(actual, expected) is expected_result


def test_match_value_modifiers():
    assert match_value("hello world", {"contains": "lo wo"}) is True
    assert match_value("hello world", {"startswith": "hello"}) is True
    assert match_value("hello world", {"endswith": "world"}) is True
    assert match_value("Hello", {"re": "^h.*o$"}) is True
    assert match_value("x", {"contains": "zzz"}) is False


# --- conditions -------------------------------------------------------------

def test_simple_condition_matches():
    rule = make_rule()
    engine = DetectionEngine([rule])
    alerts = engine.run([make_event()])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "TEST-001"


def test_condition_exclusion():
    rule = make_rule(
        detection={
            "selection": {"event.code": "4625"},
            "filter": {"user.name": "svc_*"},
            "condition": "selection and not filter",
        }
    )
    engine = DetectionEngine([rule])
    assert len(engine.run([make_event(**{"user.name": "svc_backup"})])) == 0
    assert len(engine.run([make_event(**{"user.name": "a.ramesh"})])) == 1


def test_condition_or():
    rule = make_rule(
        detection={
            "a": {"event.code": "4625"},
            "b": {"event.code": "4624"},
            "condition": "a or b",
        }
    )
    engine = DetectionEngine([rule])
    assert len(engine.run([make_event()])) == 1
    assert len(engine.run([make_event(**{"event.code": "4624"})])) == 1


def test_condition_named_clause_is_not_dropped():
    """Regression: custom clause names used to be silently ignored."""
    rule = make_rule(
        detection={
            "selection": {"event.code": "7045"},
            "suspicious_path": {"service.image_path": "C:\\Windows\\*"},
            "condition": "selection and suspicious_path",
        }
    )
    engine = DetectionEngine([rule])
    assert len(engine.run([make_event(**{"event.code": "7045", "service.image_path": "C:\\Windows\\a.exe"})])) == 1
    assert len(engine.run([make_event(**{"event.code": "7045", "service.image_path": "C:\\Program Files\\a.exe"})])) == 0


def test_quantifier_condition():
    rule = make_rule(
        detection={
            "a": {"event.code": "1"},
            "b": {"process.name": "cmd.exe"},
            "condition": "all of them",
        }
    )
    engine = DetectionEngine([rule])
    assert len(engine.run([make_event(**{"event.code": "1", "process.name": "cmd.exe"})])) == 1
    assert len(engine.run([make_event(**{"event.code": "1", "process.name": "notepad.exe"})])) == 0


# --- aggregation ------------------------------------------------------------

def test_threshold_aggregation():
    rule = make_rule(
        detection={
            "selection": {"event.code": "4625"},
            "condition": "selection | count() > 3",
            "group_by": ["source.ip"],
            "window": "5m",
        }
    )
    engine = DetectionEngine([rule])
    events = [
        Event(timestamp=BASE_TS + timedelta(seconds=i * 10), source="windows_security",
              fields={"event.code": "4625", "source.ip": "1.2.3.4"})
        for i in range(5)
    ]
    alerts = engine.run(events)
    assert len(alerts) == 1
    assert alerts[0].event_count == 4  # threshold reached at the 4th event


def test_aggregation_respects_window():
    rule = make_rule(
        detection={
            "selection": {"event.code": "4625"},
            "condition": "selection | count() > 3",
            "group_by": ["source.ip"],
            "window": "1m",
        }
    )
    engine = DetectionEngine([rule])
    events = [
        Event(timestamp=BASE_TS + timedelta(seconds=i * 120), source="windows_security",
              fields={"event.code": "4625", "source.ip": "1.2.3.4"})
        for i in range(5)
    ]
    assert len(engine.run(events)) == 0


# --- sequences --------------------------------------------------------------

def test_sequence_requires_same_actor():
    """A success from a different host must not inherit someone else's failures."""
    rule = make_rule(
        detection={
            "failures": {"event.code": "4625"},
            "success": {"event.code": "4624"},
            "condition": "sequence",
            "sequence": ["failures", "success"],
            "sequence_threshold": 3,
            "group_by": ["source.ip"],
            "window": "15m",
        }
    )
    engine = DetectionEngine([rule])
    events = [
        make_event(**{"source.ip": "9.9.9.9"}),
        make_event(**{"source.ip": "9.9.9.9"}),
        make_event(**{"source.ip": "9.9.9.9"}),
        make_event(**{"event.code": "4624", "source.ip": "1.1.1.1"}),
    ]
    assert len(engine.run(events)) == 0

    events[-1] = make_event(**{"event.code": "4624", "source.ip": "9.9.9.9"})
    assert len(engine.run(events)) == 1


# --- rule loading -----------------------------------------------------------

def test_all_shipped_rules_load():
    rules = load_rules()
    assert len(rules) >= 20
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for rule in rules:
        assert rule.title
        assert rule.severity in {"critical", "high", "medium", "low", "informational"}
        assert rule.mitre.get("technique", "").startswith("T")
        assert rule.playbook, f"{rule.id} has no playbook"


def test_every_rule_has_a_spl_equivalent():
    for rule in load_rules():
        assert rule.splunk.get("spl"), f"{rule.id} has no SPL translation"
