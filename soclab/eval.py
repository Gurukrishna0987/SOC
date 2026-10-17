"""Detection evaluation harness.

Every attack event in the generated corpus is labelled, which means we can
answer a question that most student portfolios never answer: *do my detection
rules actually work?*

Metrics produced:

  * **Stage recall** - for every (scenario, stage) pair in the attack tree, was
    it detected at all?  This is the number that matters: it tells you which
    parts of the kill chain you are blind to.
  * **Alert precision** - of the alerts raised, how many touched a real
    attack event versus benign background traffic?
  * **Per-rule breakdown** - which rules fire, how often, and are they right?
  * **MITRE coverage** - which ATT&CK techniques are covered and which are not.

Being able to say "my rules cover 7 of 8 attack stages in the ransomware
chain and the two remaining blind spots are X and Y" is a far stronger
conversation in an interview than "I wrote some detection rules".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .engine import Alert
from .events import Event
from .rules import Rule


@dataclass(slots=True)
class StageResult:
    scenario: str
    stage: str
    detected: bool
    rule_ids: list[str] = field(default_factory=list)
    event_count: int = 0


@dataclass(slots=True)
class EvalReport:
    stage_results: list[StageResult] = field(default_factory=list)
    true_positive_alerts: int = 0
    false_positive_alerts: int = 0
    benign_events: int = 0
    attack_events: int = 0
    rule_stats: dict[str, dict[str, int]] = field(default_factory=dict)
    technique_coverage: dict[str, bool] = field(default_factory=dict)
    missed_stages: list[str] = field(default_factory=list)

    @property
    def stage_recall(self) -> float:
        if not self.stage_results:
            return 0.0
        return sum(1 for s in self.stage_results if s.detected) / len(self.stage_results)

    @property
    def alert_precision(self) -> float:
        total = self.true_positive_alerts + self.false_positive_alerts
        if total == 0:
            return 0.0
        return self.true_positive_alerts / total

    def to_dict(self) -> dict:
        return {
            "stage_recall": round(self.stage_recall, 4),
            "stage_detected": sum(1 for s in self.stage_results if s.detected),
            "stage_total": len(self.stage_results),
            "alert_precision": round(self.alert_precision, 4),
            "true_positive_alerts": self.true_positive_alerts,
            "false_positive_alerts": self.false_positive_alerts,
            "attack_events": self.attack_events,
            "benign_events": self.benign_events,
            "missed_stages": self.missed_stages,
            "stage_results": [
                {
                    "scenario": s.scenario,
                    "stage": s.stage,
                    "detected": s.detected,
                    "rules": s.rule_ids,
                    "events": s.event_count,
                }
                for s in self.stage_results
            ],
            "rule_stats": self.rule_stats,
            "technique_coverage": self.technique_coverage,
        }


def evaluate(
    events: Iterable[Event],
    alerts: Iterable[Alert],
    rules: Iterable[Rule] | None = None,
) -> EvalReport:
    events = list(events)
    alerts = list(alerts)
    rules = list(rules or [])

    report = EvalReport()
    report.attack_events = sum(1 for e in events if e.ground_truth)
    report.benign_events = sum(1 for e in events if not e.ground_truth)

    # Index alert -> matched ground-truth events
    for alert in alerts:
        hit = any(e.ground_truth for e in alert.matched_events)
        if hit:
            report.true_positive_alerts += 1
        else:
            report.false_positive_alerts += 1

        stats = report.rule_stats.setdefault(
            alert.rule_id, {"alerts": 0, "true_positive": 0, "false_positive": 0}
        )
        stats["alerts"] += 1
        stats["true_positive" if hit else "false_positive"] += 1

    # Which (scenario, stage) groups were detected?
    groups: dict[tuple[str, str], list[Event]] = {}
    for evt in events:
        if not evt.ground_truth:
            continue
        stage = evt.labels.get("stage", "unknown")
        groups.setdefault((evt.scenario, stage), []).append(evt)

    for (scenario, stage), group in sorted(groups.items()):
        matched_rules: list[str] = []
        group_ids = {id(e) for e in group}
        for alert in alerts:
            if any(id(e) in group_ids for e in alert.matched_events):
                matched_rules.append(alert.rule_id)
        detected = bool(matched_rules)
        report.stage_results.append(
            StageResult(
                scenario=scenario,
                stage=stage,
                detected=detected,
                rule_ids=sorted(set(matched_rules)),
                event_count=len(group),
            )
        )
        if not detected:
            report.missed_stages.append(f"{scenario}/{stage}")

    # MITRE technique coverage: did at least one alert fire for each technique
    # that a rule claims to cover?
    fired = {a.technique_id for a in alerts if a.technique_id}
    for rule in rules:
        tid = rule.technique_id
        if tid:
            report.technique_coverage[tid] = report.technique_coverage.get(tid, False) or tid in fired

    return report
