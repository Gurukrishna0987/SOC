"""Pipeline orchestration: generator -> engine -> triage -> evaluation.

Keeping the whole flow in one function means the dashboard, the CLI and the
tests all see exactly the same data, and the demo you show in an interview is
reproducible with one command.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import Alert, DetectionEngine
from .eval import EvalReport, evaluate
from .events import Event, events_from_jsonl, events_to_jsonl
from .generator import generate_corpus
from .rules import Rule, load_rules
from .triage import Incident, TriageEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"


@dataclass(slots=True)
class PipelineResult:
    events: list[Event]
    alerts: list[Alert]
    incidents: list[Incident]
    report: EvalReport
    rules: list[Rule]

    def summary(self) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        for inc in self.incidents:
            by_severity[inc.priority] = by_severity.get(inc.priority, 0) + 1
        return {
            "events": len(self.events),
            "attack_events": sum(1 for e in self.events if e.ground_truth),
            "alerts": len(self.alerts),
            "incidents": len(self.incidents),
            "by_priority": by_severity,
            "stage_recall": round(self.report.stage_recall, 4),
            "alert_precision": round(self.report.alert_precision, 4),
            "missed_stages": self.report.missed_stages,
        }


def run_pipeline(
    seed: int = 1337,
    benign_count: int = 220,
    rule_dir: Path | str | None = None,
) -> PipelineResult:
    rules = load_rules(rule_dir or (REPO_ROOT / "rules"))
    events = generate_corpus(seed=seed, benign_count=benign_count)
    engine = DetectionEngine(rules)
    alerts = engine.run(events)
    triage = TriageEngine()
    incidents = triage.triage(alerts, events)
    report = evaluate(events, alerts, rules)
    return PipelineResult(events=events, alerts=alerts, incidents=incidents, report=report, rules=rules)


# --- persistence ------------------------------------------------------------

def save_corpus(events: list[Event], path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(events_to_jsonl(events), encoding="utf-8")
    return path


def load_corpus(path: Path | str) -> list[Event]:
    return events_from_jsonl(Path(path).read_text(encoding="utf-8"))


def save_json(payload: Any, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def load_json(path: Path | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))
