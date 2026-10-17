"""The detection engine.

This is the heart of the lab: it evaluates every event against every enabled
rule and produces alerts.  It implements the subset of the Sigma condition
language that a working analyst actually needs:

    selection and not filter
    selection_a or selection_b
    1 of selection_*
    all of them
    selection | count() > 10
    selection | count(source.ip) > 3 by user.name

Field matching supports: exact match (case-insensitive), lists, wildcards,
``contains`` / ``startswith`` / ``endswith`` / ``re`` modifiers, numeric
comparisons (``gt``/``lt``/``gte``/``lte``) and ``exists``.

The engine is deliberately dependency-free and fast - the whole corpus is
evaluated in milliseconds, so you can iterate on rules fast.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

from .events import Event
from .rules import Rule

# --- value matching ---------------------------------------------------------

def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _match_modifiers(actual: Any, modifiers: dict[str, Any]) -> bool:
    for mod, expected in modifiers.items():
        if mod == "contains":
            if not isinstance(expected, (list, tuple)):
                expected = [expected]
            if not any(_as_text(e).lower() in _as_text(actual).lower() for e in expected):
                return False
        elif mod == "startswith":
            if not isinstance(expected, (list, tuple)):
                expected = [expected]
            if not any(_as_text(actual).lower().startswith(_as_text(e).lower()) for e in expected):
                return False
        elif mod == "endswith":
            if not isinstance(expected, (list, tuple)):
                expected = [expected]
            if not any(_as_text(actual).lower().endswith(_as_text(e).lower()) for e in expected):
                return False
        elif mod == "re":
            patterns = expected if isinstance(expected, (list, tuple)) else [expected]
            if not any(re.search(str(p), _as_text(actual), re.IGNORECASE) for p in patterns):
                return False
        elif mod == "in":
            if _as_text(actual).lower() not in {str(e).lower() for e in expected}:
                return False
        elif mod == "gt" and not float(actual) > float(expected):
            return False
        elif mod == "gte" and not float(actual) >= float(expected):
            return False
        elif mod == "lt" and not float(actual) < float(expected):
            return False
        elif mod == "lte" and not float(actual) <= float(expected):
            return False
        elif mod == "exists":
            if expected and actual in (None, ""):
                return False
            if not expected and actual not in (None, ""):
                return False
        elif mod == "case_sensitive":
            continue
    return True


def match_value(actual: Any, expected: Any, *, case_sensitive: bool = False) -> bool:
    """Compare one field value against one rule expectation."""
    if isinstance(expected, dict):
        mods = dict(expected)
        sensitive = bool(mods.pop("case_sensitive", False))
        return _match_modifiers(actual, mods)
    if isinstance(expected, (list, tuple)):
        return any(match_value(actual, e, case_sensitive=case_sensitive) for e in expected)
    if expected is None:
        return actual is None or actual == ""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return bool(actual) == bool(expected)

    # Sigma-style comparison shorthands: ">0", "<=100", "!=2".
    if isinstance(expected, str) and expected[:1] in "><!=":
        op = expected[:2] if expected[:2] in (">=", "<=", "==", "!=") else expected[0]
        raw = expected[len(op):].strip()
        try:
            left, right = float(actual), float(raw)
        except (TypeError, ValueError):
            return False
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == "!=":
            return left != right
        if op == "==":
            return left == right
        return False

    if isinstance(actual, (int, float)) and not isinstance(expected, (int, float)):
        return _as_text(actual) == _as_text(expected)
    a, b = _as_text(actual), _as_text(expected)
    if not case_sensitive:
        a, b = a.lower(), b.lower()
    if "*" in b or "?" in b:
        return fnmatch.fnmatchcase(a, b)
    return a == b


def match_clause(event: Event, clause: dict[str, Any]) -> bool:
    """All key/value pairs in the clause must match (logical AND)."""
    for field_name, expected in clause.items():
        actual = event.get(field_name)
        if not match_value(actual, expected):
            return False
    return True


# --- condition parsing ------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""\s*(?P<tok>
        \(                                  |
        \)                                  |
        \|                                  |
        \b(?:and|or|not)\b                  |
        \b(?:all|any|\d+)\s+of\s+[A-Za-z_][\w.]*  |
        [A-Za-z_][A-Za-z0-9_.]*
    )""",
    re.VERBOSE | re.IGNORECASE,
)


class _ConditionParser:
    """Recursive-descent parser for the Sigma condition grammar."""

    def __init__(self, text: str, clause_names: list[str]) -> None:
        self.text = text
        self.clause_names = clause_names
        self.tokens: list[str] = []
        pos = 0
        while pos < len(text):
            m = _TOKEN_RE.match(text, pos)
            if not m:
                pos += 1
                continue
            self.tokens.append(m.group("tok").strip())
            pos = m.end()

    def parse(self) -> tuple[Any, str | None]:
        """Return (ast, aggregation) where aggregation is e.g. 'count() > 10'."""
        body, _, agg = self.text.partition("|")
        self.tokens = self._tokenise(body)
        if not self.tokens:
            return ("empty", None)
        node, idx = self._parse_or()
        rest = " ".join(self.tokens[idx:])
        aggregation = agg.strip() or (rest.strip() if rest else None)
        return (node, aggregation)

    @staticmethod
    def _tokenise(text: str) -> list[str]:
        tokens: list[str] = []
        pos = 0
        while pos < len(text):
            m = _TOKEN_RE.match(text, pos)
            if not m:
                pos += 1
                continue
            tokens.append(m.group("tok").strip().lower())
            pos = m.end()
        return tokens

    # -- grammar ---------------------------------------------------------
    def _peek(self, i: int) -> str:
        return self.tokens[i] if i < len(self.tokens) else ""

    def _parse_or(self) -> tuple[Any, int]:
        node, i = self._parse_and()
        while self._peek(i) == "or":
            right, i = self._parse_and(i + 1)
            node = ("or", node, right)
        return node, i

    def _parse_and(self, i: int = 0) -> tuple[Any, int]:
        node, i = self._parse_not(i)
        while self._peek(i) == "and":
            right, i = self._parse_not(i + 1)
            node = ("and", node, right)
        return node, i

    def _parse_not(self, i: int) -> tuple[Any, int]:
        if self._peek(i) == "not":
            operand, i = self._parse_not(i + 1)
            return ("not", operand), i
        return self._parse_atom(i)

    def _parse_atom(self, i: int) -> tuple[Any, int]:
        tok = self._peek(i)
        if tok == "(":
            node, i = self._parse_or_after_paren(i + 1)
            return node, i
        m = re.match(r"^(\d+|all|any)\s+of\s+([\w.]+)$", tok)
        if m:
            quantifier = m.group(1)
            scope_name = m.group(2)
            if scope_name == "them":
                scope = list(self.clause_names)
            else:
                scope = [n for n in self.clause_names if n.startswith(scope_name)] or [scope_name]
            if quantifier == "all":
                return ("quantifier", "all", scope), i + 1
            if quantifier == "any":
                return ("quantifier", "any", scope), i + 1
            return ("quantifier", int(quantifier), scope), i + 1
        if tok:
            return ("clause", tok), i + 1
        return ("empty",), i

    def _parse_or_after_paren(self, i: int) -> tuple[Any, int]:
        node, i = self._parse_or()
        if self._peek(i) == ")":
            i += 1
        return node, i


def _eval_node(node: Any, event: Event, clauses: dict[str, dict[str, Any]]) -> bool:
    kind = node[0]
    if kind == "empty":
        return False
    if kind == "clause":
        name = node[1]
        clause = clauses.get(name)
        if clause is None:
            return False
        return match_clause(event, clause)
    if kind == "not":
        return not _eval_node(node[1], event, clauses)
    if kind == "and":
        return _eval_node(node[1], event, clauses) and _eval_node(node[2], event, clauses)
    if kind == "or":
        return _eval_node(node[1], event, clauses) or _eval_node(node[2], event, clauses)
    if kind == "quantifier":
        quantifier, scope = node[1], node[2]
        names = [n for n in scope if n in clauses]
        if quantifier == "all":
            return bool(names) and all(_eval_node(("clause", n), event, clauses) for n in names)
        if quantifier == "any":
            return any(_eval_node(("clause", n), event, clauses) for n in names)
        count = int(quantifier)
        hits = sum(1 for n in names if _eval_node(("clause", n), event, clauses))
        return hits >= count
    return False


# --- alerts -----------------------------------------------------------------

@dataclass(slots=True)
class Alert:
    id: str
    rule_id: str
    rule_title: str
    severity: str
    confidence: str
    technique_id: str
    tactic: str
    first_seen: datetime
    last_seen: datetime
    matched_events: list[Event] = field(default_factory=list)
    entities: dict[str, str] = field(default_factory=dict)
    playbook: str = ""
    source_spl: str = ""

    @property
    def event_count(self) -> int:
        return len(self.matched_events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "confidence": self.confidence,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "entities": self.entities,
            "playbook": self.playbook,
            "matched_events": [e.to_dict() for e in self.matched_events],
        }


# --- engine -----------------------------------------------------------------

class DetectionEngine:
    def __init__(self, rules: Sequence[Rule]) -> None:
        self.rules = list(rules)
        self._compiled: list[tuple[Rule, Any, str | None]] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            clauses = {
                name: value
                for name, value in rule.detection.items()
                if isinstance(value, dict) and name not in ("group_by",)
            }
            names = sorted(clauses)
            parser = _ConditionParser(rule.condition, names)
            ast, aggregation = parser.parse()
            self._compiled.append((rule, ast, aggregation))

    # -- helpers ----------------------------------------------------------
    def _clause_map(self, rule: Rule) -> dict[str, dict[str, Any]]:
        return {
            name: value
            for name, value in rule.detection.items()
            if isinstance(value, dict)
        }

    def _entity_values(self, rule: Rule, events: list[Event]) -> dict[str, str]:
        entities: dict[str, str] = {}
        wanted = rule.fields or [
            "host.name",
            "user.name",
            "source.ip",
            "destination.ip",
            "process.name",
            "url.original",
            "file.name",
            "mail.from",
            "cloud.resource.name",
        ]
        for f in wanted:
            values = {str(e.get(f)) for e in events if e.get(f) not in (None, "")}
            if values:
                entities[f] = ", ".join(sorted(values)[:4])
        return entities

    # -- main entry point -------------------------------------------------
    def run(self, events: Iterable[Event]) -> list[Alert]:
        events = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        counter = 0

        for rule, ast, aggregation in self._compiled:
            clauses = self._clause_map(rule)
            sequence = rule.detection.get("sequence")
            if sequence:
                groups = self._run_sequence(rule, list(sequence), events, clauses)
            else:
                candidates = [e for e in events if _eval_node(ast, e, clauses)]
                if not candidates:
                    continue
                if aggregation:
                    groups = self._aggregate(rule, candidates, aggregation)
                else:
                    groups = [(tuple(), candidates)]

            for key, group_events in groups:
                counter += 1
                first = group_events[0].timestamp
                last = group_events[-1].timestamp
                alerts.append(
                    Alert(
                        id=f"ALR-{counter:04d}",
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        technique_id=rule.technique_id,
                        tactic=rule.tactic,
                        first_seen=first,
                        last_seen=last,
                        matched_events=list(group_events),
                        entities=self._entity_values(rule, list(group_events)),
                        playbook=rule.playbook,
                        source_spl=rule.splunk.get("spl", ""),
                    )
                )
        alerts.sort(key=lambda a: (-_severity_rank(a.severity), a.first_seen))
        return alerts

    # -- sequence correlation ---------------------------------------------
    def _run_sequence(
        self,
        rule: Rule,
        sequence: list[str],
        events: list[Event],
        clauses: dict[str, dict[str, Any]],
    ) -> list[tuple[tuple, list[Event]]]:
        """Correlate a sequence of clauses inside a time window.

        ``sequence: [failures, success]`` means: an event matching the last
        clause, where an event matching the first clause happened within the
        rule's window.  This is how you detect "failed and then succeeded"
        without drowning the analyst in one alert per failed logon.
        """
        if len(sequence) < 2:
            return []
        window = rule.window_seconds
        group_by = rule.group_by or ["source.ip"]
        threshold = int(rule.detection.get("sequence_threshold", 1) or 1)

        first_clause = sequence[0]
        last_clause = sequence[-1]
        mid_clauses = sequence[1:-1]

        buckets: dict[tuple, list[Event]] = {}
        for idx, evt in enumerate(events):
            if last_clause not in clauses or not match_clause(evt, clauses[last_clause]):
                continue
            window_start = evt.timestamp - timedelta(seconds=window)
            prior = [e for e in events[:idx] if window_start <= e.timestamp <= evt.timestamp]
            # The correlated events must describe the SAME actor - otherwise a
            # random success from another host would inherit someone else's
            # failed logons (a classic false-positive trap).
            first_hits = [
                e
                for e in prior
                if match_clause(e, clauses.get(first_clause, {}))
                and all(str(e.get(g, "")) == str(evt.get(g, "")) for g in group_by)
            ]
            if len(first_hits) < threshold:
                continue
            if mid_clauses:
                ok = all(any(match_clause(e, clauses.get(m, {})) for e in prior) for m in mid_clauses)
                if not ok:
                    continue
            key = tuple(str(evt.get(g, "")) for g in group_by)
            bucket = buckets.setdefault(key, [])
            bucket.extend(first_hits)
            bucket.append(evt)

        return [(key, bucket) for key, bucket in buckets.items() if bucket]

    # -- aggregation -------------------------------------------------------
    def _aggregate(
        self, rule: Rule, candidates: list[Event], aggregation: str
    ) -> list[tuple[tuple, list[Event]]]:
        """Apply a `| count(...) > N [by fields]` style aggregation."""
        expr = aggregation.strip().lower()
        count_field = ""
        group_by = rule.group_by

        m = re.search(r"count\s*\(\s*([\w.\-]+)?\s*\)", expr)
        if m and m.group(1):
            count_field = m.group(1)

        # "> 10" means eleven or more, ">= 10" means ten or more.  Getting this
        # wrong is the classic off-by-one that makes a threshold rule useless.
        comparator = re.search(r"(>=|>)\s*(\d+)", expr)
        if comparator:
            operator, number = comparator.group(1), int(comparator.group(2))
            min_count = number + 1 if operator == ">" else number
        else:
            min_count = rule.threshold
        by = re.search(r"\bby\s+([\w.,\s]+)$", expr)
        if by:
            group_by = [g.strip() for g in by.group(1).split(",") if g.strip()]

        window = rule.window_seconds
        buckets: dict[tuple, list[Event]] = {}
        for evt in candidates:
            key = tuple(str(evt.get(g, "")) for g in group_by)
            bucket = buckets.setdefault(key, [])
            # Sliding window: drop events that fell out of the time window.
            cutoff = evt.timestamp - timedelta(seconds=window)
            bucket[:] = [b for b in bucket if b.timestamp >= cutoff]
            bucket.append(evt)
            if len(bucket) >= min_count:
                # Emit the bucket, then start a fresh one to avoid duplicates.
                buckets[key] = []
                yield key, list(bucket)


def _severity_rank(severity: str) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
    return order.get(severity.lower(), 0)
