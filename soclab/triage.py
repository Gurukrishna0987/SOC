"""Triage engine: turn raw alerts into prioritised, explainable incidents.

This module is where the analyst value sits.  A SIEM will happily hand you 400
alerts; a SOC analyst has to say which 5 matter, why, and what to do next.
The pipeline implemented here is the one most SOCs run:

  1. **Enrich**  - attach asset criticality, data classification, owner.
  2. **Score**   - severity x criticality x confidence -> a 0-100 risk score.
  3. **Prioritise** - rank into P1/P2/P3 with an SLA for each tier.
  4. **Correlate** - stitch related alerts into a single attack narrative.
  5. **Explain** - attach a "why" string and the playbook to execute.

Every step is deterministic and logged, so an interview demo can explain
exactly how a number was produced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import yaml

from .engine import Alert
from .events import Event
from .rules import Rule

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"

# How long a Tier-1 analyst is expected to act on each priority.
SLA_MINUTES = {"P1": 15, "P2": 60, "P3": 240, "P4": 1440}

# MITRE tactics ranked by how urgently they need attention.  Exfiltration and
# impact are late-stage and mean the attacker is already winning.
TACTIC_WEIGHT = {
    "Initial Access": 1.2,
    "Execution": 1.3,
    "Persistence": 1.2,
    "Privilege Escalation": 1.4,
    "Defense Evasion": 1.3,
    "Credential Access": 1.4,
    "Discovery": 0.9,
    "Lateral Movement": 1.4,
    "Collection": 1.2,
    "Command and Control": 1.4,
    "Exfiltration": 1.6,
    "Impact": 1.6,
}


@dataclass(slots=True)
class Incident:
    """A triaged alert, ready to be worked by an analyst."""

    id: str
    alert_id: str
    rule_id: str
    title: str
    priority: str
    risk_score: float
    severity: str
    confidence: str
    status: str = "new"
    technique_id: str = ""
    tactic: str = ""
    asset: str = ""
    asset_criticality: str = "unknown"
    asset_role: str = ""
    owner: str = ""
    data_classification: str = ""
    user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sla_minutes: int = 0
    due_by: str = ""
    rationale: list[str] = field(default_factory=list)
    playbook: str = ""
    entities: dict[str, str] = field(default_factory=dict)
    scenario: str = ""
    ground_truth: bool = False
    matched_events: list[dict[str, Any]] = field(default_factory=list)
    linked_alerts: list[str] = field(default_factory=list)
    analyst_notes: str = ""
    suppression_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


class TriageEngine:
    def __init__(
        self,
        assets: dict[str, Any] | None = None,
        org: dict[str, Any] | None = None,
    ) -> None:
        self.asset_config = assets if assets is not None else _load_yaml(CONFIG_DIR / "assets.yaml")
        self.org = org if org is not None else _load_yaml(CONFIG_DIR / "org.yaml")
        self.assets: dict[str, dict[str, Any]] = self.asset_config.get("assets", {}) or {}
        self.criticality_weights: dict[str, float] = (
            self.asset_config.get("criticality_weights") or {}
        )
        self.severity_scores: dict[str, int] = self.asset_config.get("severity_scores") or {}

    # -- enrichment -------------------------------------------------------
    def asset_info(self, host: str) -> dict[str, Any]:
        return self.assets.get(host, {})

    def _primary_host(self, alert: Alert) -> str:
        hosts = [h for h in alert.entities.get("host.name", "").split(", ") if h]
        if hosts:
            return hosts[0]
        for evt in alert.matched_events:
            name = evt.get("host.name")
            if name:
                return str(name)
        return "unknown"

    def _primary(self, alert: Alert, field_name: str) -> str:
        value = alert.entities.get(field_name, "")
        if value:
            return value.split(", ")[0]
        for evt in alert.matched_events:
            val = evt.get(field_name)
            if val:
                return str(val)
        return ""

    # -- scoring ----------------------------------------------------------
    def score(self, alert: Alert, asset: dict[str, Any]) -> tuple[float, list[str]]:
        """Additive risk model: easy to explain, easy to tune, easy to defend.

        Every component is listed in the rationale so an analyst - or an
        interviewer - can see exactly why an incident got the score it got.
        """
        reasons: list[str] = []
        score = 0.0

        base = float(self.severity_scores.get(alert.severity.lower(), 20))
        score += base
        reasons.append(f"rule severity '{alert.severity}' (+{base:.0f})")

        criticality = str(asset.get("criticality", "unknown")).lower()
        asset_bonus = float(self.criticality_weights.get(criticality, 8.0))
        score += asset_bonus
        reasons.append(
            f"asset criticality '{criticality}' on {asset.get('role', 'unknown host')} "
            f"(+{asset_bonus:.0f})"
        )

        tactic_weight = TACTIC_WEIGHT.get(alert.tactic, 1.0)
        tactic_bonus = min(15.0, max(0.0, (tactic_weight - 1.0) * 30))
        score += tactic_bonus
        if tactic_bonus:
            reasons.append(f"ATT&CK tactic '{alert.tactic}' (+{tactic_bonus:.0f})")

        confidence = alert.confidence.lower()
        confidence_bonus = {"high": 10.0, "medium": 5.0, "low": 0.0}.get(confidence, 5.0)
        score += confidence_bonus
        reasons.append(f"rule confidence '{confidence}' (+{confidence_bonus:.0f})")

        if alert.event_count > 1:
            volume_bonus = min(5.0, (alert.event_count - 1) * 0.4)
            score += volume_bonus
            reasons.append(f"{alert.event_count} correlated events (+{volume_bonus:.1f})")

        if alert.technique_id:
            reasons.append(f"mapped to MITRE ATT&CK {alert.technique_id} ({alert.tactic})")

        return round(min(score, 100.0), 1), reasons

    def priority_for(self, score: float) -> str:
        if score >= 80:
            return "P1"
        if score >= 55:
            return "P2"
        if score >= 30:
            return "P3"
        return "P4"

    # -- main -------------------------------------------------------------
    def triage(self, alerts: Iterable[Alert], events: list[Event] | None = None) -> list[Incident]:
        alerts = list(alerts)
        event_index = {e.fields.get("@timestamp", ""): e for e in (events or [])}
        incidents: list[Incident] = []

        for alert in alerts:
            host = self._primary_host(alert)
            asset = self.asset_info(host)
            score, reasons = self.score(alert, asset)
            priority = self.priority_for(score)
            sla = SLA_MINUTES.get(priority, 240)
            due = alert.last_seen.timestamp() + sla * 60

            scenario = ""
            ground_truth = False
            for evt in alert.matched_events:
                if evt.scenario:
                    scenario = evt.scenario
                    ground_truth = evt.ground_truth
                    break

            inc = Incident(
                id=alert.id.replace("ALR-", "INC-"),
                alert_id=alert.id,
                rule_id=alert.rule_id,
                title=alert.rule_title,
                priority=priority,
                risk_score=score,
                severity=alert.severity,
                confidence=alert.confidence,
                technique_id=alert.technique_id,
                tactic=alert.tactic,
                asset=host,
                asset_criticality=str(asset.get("criticality", "unknown")),
                asset_role=str(asset.get("role", "")),
                owner=str(asset.get("owner", "")),
                data_classification=str(asset.get("data_classification", "")),
                user=self._primary(alert, "user.name"),
                source_ip=self._primary(alert, "source.ip"),
                destination_ip=self._primary(alert, "destination.ip"),
                event_count=alert.event_count,
                first_seen=alert.first_seen.isoformat(),
                last_seen=alert.last_seen.isoformat(),
                sla_minutes=sla,
                due_by=datetime.utcfromtimestamp(due).isoformat() + "Z",
                rationale=reasons,
                playbook=alert.playbook,
                entities=alert.entities,
                scenario=scenario,
                ground_truth=ground_truth,
                matched_events=[e.to_dict() for e in alert.matched_events[:25]],
            )
            incidents.append(inc)

        incidents.sort(key=lambda i: (-i.risk_score, i.first_seen))
        self._apply_exceptions(incidents)
        self._correlate(incidents)
        return incidents

    # -- exceptions & allow-lists -----------------------------------------
    def _apply_exceptions(self, incidents: list[Incident]) -> None:
        """Suppress known-benign activity using the org context file.

        A SOC without suppression is a SOC that drowns in false positives.
        Three suppression sources are honoured here:

          * ``known_exceptions`` - rule + host pairs with a documented reason
          * ``allow_list.source_ips`` - shared egress (VPN/NAT) addresses
          * ``allow_list.users`` - service accounts that behave noisily
        """
        allow = self.org.get("allow_list", {}) or {}
        allow_ips = set(allow.get("source_ips", []) or [])
        allow_users = set(allow.get("users", []) or [])
        exceptions = self.org.get("known_exceptions", []) or []

        for inc in incidents:
            reason = ""
            for exc in exceptions:
                if exc.get("rule_id") != inc.rule_id:
                    continue
                if exc.get("host") and exc["host"] != inc.asset:
                    continue
                reason = f"Known exception: {exc.get('reason', 'documented exception')}"
                break
            if not reason and inc.source_ip and inc.source_ip in allow_ips:
                reason = f"Source IP {inc.source_ip} is an allow-listed shared egress address"
            if not reason and inc.user and inc.user in allow_users:
                reason = f"User {inc.user} is an allow-listed service account"
            if reason:
                inc.status = "suppressed"
                inc.suppression_reason = reason
                inc.rationale.append(f"SUPPRESSED - {reason}")

    # -- correlation ------------------------------------------------------
    def _correlate(self, incidents: list[Incident]) -> None:
        """Link incidents that share an entity so the analyst sees a story.

        Two alerts that share (source IP, user) or (user, host) are usually
        two steps of the same intrusion.  This is the cheapest form of
        correlation and it is what Tier-1 analysts are expected to do manually.
        """
        by_key: dict[str, list[Incident]] = {}
        for inc in incidents:
            if inc.scenario:
                key = f"scenario:{inc.scenario}"
            elif inc.source_ip:
                key = f"ip:{inc.source_ip}"
            elif inc.user and inc.asset:
                key = f"user-asset:{inc.user}|{inc.asset}"
            else:
                continue
            by_key.setdefault(key, []).append(inc)

        for key, group in by_key.items():
            if len(group) < 2:
                continue
            for inc in group:
                others = [o.id for o in group if o.id != inc.id]
                inc.linked_alerts = sorted(set(inc.linked_alerts) | set(others))


def incidents_to_json(incidents: list[Incident]) -> str:
    return json.dumps([i.to_dict() for i in incidents], indent=2)
