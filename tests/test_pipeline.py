"""End-to-end tests for the pipeline, triage and evaluation."""

from __future__ import annotations

import pytest

from soclab.engine import DetectionEngine
from soclab.eval import evaluate
from soclab.generator import generate_corpus
from soclab.pipeline import run_pipeline
from soclab.playbooks import load_playbooks
from soclab.rules import load_rules
from soclab.triage import TriageEngine


@pytest.fixture(scope="module")
def result():
    return run_pipeline(seed=1337, benign_count=120)


def test_corpus_is_deterministic():
    a = generate_corpus(seed=42, benign_count=50)
    b = generate_corpus(seed=42, benign_count=50)
    assert [e.fields for e in a] == [e.fields for e in b]


def test_corpus_contains_both_classes(result):
    assert result.report.attack_events > 0
    assert result.report.benign_events > 0


def test_every_attack_stage_is_detected(result):
    """The rule set must cover every modelled stage of every intrusion."""
    missed = [f"{s.scenario}/{s.stage}" for s in result.report.stage_results if not s.detected]
    assert not missed, f"undetected attack stages: {missed}"
    assert result.report.stage_recall == 1.0


def test_alert_precision_is_high(result):
    assert result.report.alert_precision >= 0.85


def test_triage_produces_prioritised_incidents(result):
    assert result.incidents
    scores = [i.risk_score for i in result.incidents]
    assert scores == sorted(scores, reverse=True)
    for inc in result.incidents:
        assert inc.priority in {"P1", "P2", "P3", "P4"}
        assert inc.rationale, "every incident must explain its score"
        assert inc.sla_minutes > 0


def test_risk_score_bounds(result):
    for inc in result.incidents:
        assert 0 <= inc.risk_score <= 100


def test_suppression_uses_org_allowlist(result):
    suppressed = [i for i in result.incidents if i.status == "suppressed"]
    for inc in suppressed:
        assert inc.suppression_reason


def test_every_rule_links_to_an_existing_playbook():
    playbooks = load_playbooks()
    for rule in load_rules():
        assert rule.playbook in playbooks, f"{rule.id} -> missing playbook {rule.playbook}"


def test_incidents_link_related_alerts(result):
    linked = [i for i in result.incidents if i.linked_alerts]
    assert linked, "correlation should group at least some incidents"


def test_evaluation_reports_technique_coverage(result):
    coverage = result.report.technique_coverage
    assert coverage
    assert any(coverage.values())


def test_attack_chain_is_correlatable(result):
    """The ransomware scenario must produce alerts at several stages."""
    ids = {i.rule_id for i in result.incidents if i.scenario == "ransomware"}
    assert len(ids) >= 3
