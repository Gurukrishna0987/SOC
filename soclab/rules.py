"""Detection rule loading.

The rules in ``rules/*.yaml`` follow a Sigma-inspired format.  Sigma is the
de-facto standard for portable detection content: you can take a rule from this
lab and load it into Splunk Enterprise Security, Elastic Security, Microsoft
Sentinel or Chronicle with a converter.  Using a standard format (rather than an
invented one) is deliberate - it means the detection work you show in this repo
is directly usable at a real employer.

Sigma uses the "selection / filter / condition" model:

    selection:   conditions that must hold for an event to be interesting
    filter:      conditions that EXCLUDE events (known-benign exceptions)
    condition:   how to combine them, e.g. "selection and not filter"

This module also keeps the parts of Sigma that matter for a SOC analyst:
severity, confidence, MITRE ATT&CK mapping, false-positive notes, and a link to
the response playbook to execute when the rule fires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULE_DIR = REPO_ROOT / "rules"


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    description: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    mitre: dict[str, str] = field(default_factory=dict)
    data_sources: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    fields: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    playbook: str = ""
    splunk: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    path: str = ""

    @property
    def condition(self) -> str:
        return str(self.detection.get("condition", "selection"))

    @property
    def group_by(self) -> list[str]:
        return list(self.detection.get("group_by", []) or [])

    @property
    def threshold(self) -> int:
        return int(self.detection.get("threshold", 1) or 1)

    @property
    def window_seconds(self) -> int:
        window = str(self.detection.get("window", "5m"))
        return _parse_window(window)

    @property
    def technique(self) -> str:
        return self.mitre.get("technique", "")

    @property
    def tactic(self) -> str:
        return self.mitre.get("tactic", "")

    @property
    def technique_id(self) -> str:
        """e.g. T1110.001 - the label used on the dashboard heat map."""
        sub = self.mitre.get("subtechnique", "")
        if sub:
            return f"{self.technique}.{sub}" if not sub.startswith(self.technique) else sub
        return self.technique


def _parse_window(window: str) -> int:
    window = window.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if window and window[-1] in units:
        try:
            return int(float(window[:-1]) * units[window[-1]])
        except ValueError:
            return 300
    try:
        return int(float(window))
    except ValueError:
        return 300


def load_rule_file(path: Path) -> list[Rule]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules: list[Rule] = []
    # Support both a single-document file and a list of documents.
    documents = raw if isinstance(raw, list) else [raw]
    for doc in documents:
        if not doc:
            continue
        rules.append(
            Rule(
                id=str(doc.get("id", "UNKNOWN")),
                title=str(doc.get("title", "Untitled rule")),
                description=str(doc.get("description", "")).strip(),
                severity=str(doc.get("severity", "medium")).lower(),
                confidence=str(doc.get("confidence", "medium")).lower(),
                mitre=dict(doc.get("mitre", {}) or {}),
                data_sources=list(doc.get("data_sources", []) or []),
                logsource=dict(doc.get("logsource", {}) or {}),
                detection=dict(doc.get("detection", {}) or {}),
                fields=list(doc.get("fields", []) or []),
                falsepositives=list(doc.get("falsepositives", []) or []),
                references=list(doc.get("references", []) or []),
                playbook=str(doc.get("playbook", "")),
                splunk=dict(doc.get("splunk", {}) or {}),
                enabled=bool(doc.get("enabled", True)),
                path=str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path),
            )
        )
    return rules


def load_rules(rule_dir: Path | str = DEFAULT_RULE_DIR) -> list[Rule]:
    rule_dir = Path(rule_dir)
    rules: list[Rule] = []
    for path in sorted(rule_dir.glob("*.y*ml")):
        rules.extend(load_rule_file(path))
    return rules


def rules_by_id(rules: list[Rule]) -> dict[str, Rule]:
    return {r.id: r for r in rules}
