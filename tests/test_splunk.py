"""Tests for the Splunk export layer."""

from __future__ import annotations

import re

from soclab.rules import load_rules
from soclab.splunk import build_savedsearches_conf, rule_to_spl, spl_field


def test_field_mapping_covers_common_fields():
    assert spl_field("event.code") == "EventCode"
    assert spl_field("host.name") == "host"
    assert spl_field("source.ip") == "src_ip"
    assert spl_field("process.command_line") == "CommandLine"


def test_every_rule_generates_spl():
    for rule in load_rules():
        spl = rule_to_spl(rule)
        assert spl.strip()
        assert "\n" not in spl
        assert "|" in spl or "index=" in spl


def test_savedsearches_conf_is_valid():
    conf = build_savedsearches_conf(load_rules())
    assert "[soc_lab_" in conf
    # Every stanza must have a displayName, search and a schedule
    stanzas = re.split(r"^\[", conf, flags=re.MULTILINE)[1:]
    assert len(stanzas) >= 20
    for stanza in stanzas:
        assert "displayName" in stanza
        assert "search = " in stanza
        assert "cron_schedule" in stanza
        assert "alert_threshold" in stanza


def test_conf_values_are_escaped():
    conf = build_savedsearches_conf(load_rules())
    for line in conf.splitlines():
        if line.startswith("search = "):
            value = line[len("search = "):]
            assert not re.search(r'(?<!\\)"', value) or value.count('"') % 2 == 0
