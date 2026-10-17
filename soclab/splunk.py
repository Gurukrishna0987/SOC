"""Splunk integration.

Two jobs:

1. **Translate** the Sigma-style rules in ``rules/`` into Splunk Processing
   Language (SPL) so the same detection content runs in a real Splunk
   Enterprise / Splunk Security instance.  The field mapping table below is
   the interesting part: it maps the ECS field names used in this lab onto
   Splunk CIM field names, which is the translation you have to get right in
   a real job.

2. **Export** ready-to-load artefacts: ``savedsearches.conf`` (scheduled
   searches that create notable events), a classic dashboard XML, and a
   hunting-query library.

The exported content works against any Splunk index that contains the events
this lab generates, and the SPL also works against a real Windows event log
index because it is written against CIM field names.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .rules import Rule, load_rules

REPO_ROOT = Path(__file__).resolve().parent.parent

# ECS field name -> Splunk CIM / common field name.
FIELD_MAP = {
    "event.code": "EventCode",
    "event.id": "EventCode",
    "event.action": "action",
    "event.category": "source",
    "event.outcome": "status",
    "host.name": "host",
    "host.ip": "dest",
    "user.name": "user",
    "user.domain": "user_domain",
    "source.ip": "src_ip",
    "source.port": "src_port",
    "destination.ip": "dest_ip",
    "destination.port": "dest_port",
    "process.name": "Image",
    "process.executable": "Image",
    "process.command_line": "CommandLine",
    "process.parent.name": "ParentImage",
    "file.name": "file_name",
    "file.path": "file_path",
    "registry.path": "registry_path",
    "url.original": "url",
    "dns.question.name": "QueryName",
    "mail.from": "from",
    "mail.to": "to",
    "mail.subject": "subject",
    "mail.file.name": "attachments",
    "mail.attachment.count": "attachment_count",
    "mail.spf_result": "spf",
    "mail.dkim_result": "dkim",
    "mail.dmarc_result": "dmarc",
    "cloud.action": "eventName",
    "cloud.resource.name": "resourceName",
    "cloud.source.ip": "sourceIPAddress",
    "cloud.account.id": "accountId",
    "cloud.region": "region",
    "api.operation": "eventName",
    "proxy.url": "uri",
    "proxy.bytes": "bytes",
    "http.response.status_code": "status",
    "http.request.method": "http_method",
    "winlog.logon_type": "Logon_Type",
    "av.setting": "AuditPolicyChanges",
    "service.name": "ServiceName",
    "service.image_path": "ImagePath",
    "group.name": "TargetUserName",
    "firewall.rule": "RuleName",
    "message": "Message",
    "powershell.script_block": "ScriptBlockText",
}

# Which Splunk index / sourcetype each telemetry source maps to.
SOURCE_MAP = {
    "windows_security": ('index=wineventlog sourcetype="XmlWinEventLog:Security"',
                         'index=wineventlog sourcetype="XmlWinEventLog:System"'),
    "sysmon": 'index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
    "linux_syslog": 'index=linux sourcetype="syslog"',
    "email_gateway": 'index=email sourcetype="email:send"',
    "proxy": 'index=proxy sourcetype="proxy"',
    "cloud_audit": 'index=cloud sourcetype="aws:cloudtrail"',
    "firewall": 'index=firewall',
    "edr": 'index=edr sourcetype="edr"',
}


def spl_field(field_name: str) -> str:
    return FIELD_MAP.get(field_name, field_name.replace(".", "_"))


def _spl_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text.startswith((">", "<", "!=")) or text.endswith("*") or "*" in text:
        return f'"{text}"'
    return f'"{text}"'


def _clause_to_spl(clause: dict[str, Any]) -> str:
    parts: list[str] = []
    for field_name, expected in clause.items():
        spl_name = spl_field(field_name)
        if isinstance(expected, list):
            values = ", ".join(_spl_value(v) for v in expected)
            parts.append(f"{spl_name} IN ({values})")
        elif isinstance(expected, dict):
            for mod, val in expected.items():
                if mod in ("contains", "startswith", "endswith", "re"):
                    continue
                parts.append(f"{spl_name}={_spl_value(val)}")
        else:
            parts.append(f"{spl_name}={_spl_value(expected)}")
    return " ".join(parts)


def rule_to_spl(rule: Rule) -> str:
    """Return the SPL search for a rule."""
    if rule.splunk.get("spl"):
        return " ".join(rule.splunk["spl"].split())

    data_sources = rule.data_sources or ["windows_security"]
    base = SOURCE_MAP.get(data_sources[0], "index=*")[0]

    selections = {
        name: value
        for name, value in rule.detection.items()
        if isinstance(value, dict) and name not in ("group_by",)
    }
    if not selections:
        return f"{base} | stats count by host"

    # Combine the clauses with the rule's own condition semantics.
    condition = rule.condition
    pieces: list[str] = []
    if "filter" in selections and "not filter" in condition:
        neg = _clause_to_spl(selections["filter"])
        main = [v for k, v in selections.items() if k != "filter"]
        main_spl = " ".join(_clause_to_spl(c) for c in main)
        pieces.append(f"({main_spl}) NOT ({neg})")
    else:
        pieces.append(" ".join(_clause_to_spl(c) for c in selections.values()))

    search = f"{base} " + " ".join(pieces)
    if rule.group_by:
        group = ", ".join(spl_field(g) for g in rule.group_by)
        search += f" | stats count as events by {group}"
        if rule.threshold > 1:
            search += f" | where events > {rule.threshold - 1}"
    else:
        search += " | stats count as events by host, user, src_ip"
    return search


def _conf_escape(text: str) -> str:
    """Escape a value for a Splunk .conf file."""
    text = " ".join(text.split())
    return text.replace("\\", "\\\\").replace('"', '\\"')


def build_savedsearches_conf(rules: list[Rule]) -> str:
    lines: list[str] = [
        "# Saved searches exported from the SOC Lab rule set.",
        "# Load into $SPLUNK_HOME/etc/apps/soc_lab/local/",
        "# (Splunk Enterprise Security license required for alerting).",
        "",
    ]
    for rule in rules:
        spl = rule_to_spl(rule)
        name = f"soc_lab_{rule.id.lower().replace('-', '_')}"
        lines.extend(
            [
                f"[{name}]",
                f"displayName = {rule.id} - {rule.title}",
                f"description = {rule.description.strip()[:200]}",
                f"search = {spl}",
                "enableScheduled = True",
                "cron_schedule = */5 * * * *",
                "dispatch.earliest_time = -24h",
                "dispatch.latest_time = now",
                "alert_type = number_of_events",
                "alert_comparator = greater than",
                f"alert_threshold = {rule.threshold}",
                "counttype = number of events",
                "quantity = 0",
                "relation = greater than",
                "severity = " + {"critical": "5", "high": "4", "medium": "3"}.get(rule.severity, "2"),
                f"mitre_technique = {rule.technique_id}",
                f"playbook = {rule.playbook}",
                "",
            ]
        )
    return "\n".join(lines)


def build_dashboard_xml(rules: list[Rule]) -> str:
    """A classic Splunk dashboard that plots the SOC lab detections."""
    panels: list[str] = []
    panel_no = 1
    for rule in rules[:6]:
        spl = _conf_escape(rule_to_spl(rule))
        panels.append(
            f"""    <panel id="panel_{panel_no}">
      <title>{rule.id} - {rule.title[:60]}</title>
      <table>
        <search>
          <query>{spl}</query>
          <earliest>-7d</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>"""
        )
        panel_no += 1

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<form version="1.1">
  <label>SOC Lab Overview</label>
  <description>Detection coverage exported from the SOC Lab rule set.</description>
  <fieldset submitButton="true" autoRun="true">
{chr(10).join(panels)}
  </fieldset>
</form>
"""


def build_hunting_queries() -> str:
    """A library of SPL hunting queries (the 'proactive' side of a SOC)."""
    return """# Splunk hunting queries

These are the queries a SOC analyst runs when there is no alert - the
proactive side of the job.  Replace `index=*` with your real index.

## 1. Where are users authenticating from? (baseline / impossible travel)
```spl
index=* EventCode=4624
| stats count as logons dc(user) as user by src_ip
| sort - logons
```

## 2. Accounts that never normally log on interactively
```spl
index=* EventCode=4624 Logon_Type=2
| stats earliest(_time) as first_seen latest(_time) as last_seen count as logons by user src_ip
| sort - logons
```

## 3. Which processes are signed, and which are not?
```spl
index=* (EventCode=1 OR EventCode=4688)
| stats count dc(Image) as images by Image ParentImage User
| where images > 0
```

## 4. Encoded or obfuscated command lines
```spl
index=* CommandLine=("*-enc*" OR "*FromBase64String*" OR "*DownloadString*")
| table _time host user Image ParentImage CommandLine
```

## 5. Users accessing admin shares
```spl
index=* EventCode=5140 (ShareName="*C$*" OR ShareName="*ADMIN$*" OR ShareName="*$")
| stats count as accesses by user src_ip dest ShareName
```

## 6. Service accounts that are being used interactively
```spl
index=* EventCode=4624 (user="svc_*" OR user="*_backup")
| search Logon_Type=2
| table _time host user src_ip Logon_Type
```

## 7. Rare destinations talking to your hosts
```spl
index=* EventCode=3
| stats count as conns dc(dest) as dest by src_ip dest
| where conns < 5
```

## 8. Large data transfers out
```spl
index=proxy bytes>10000000
| stats sum(bytes) as total_bytes count as requests by src user dest
| sort - total_bytes
```

## 9. DNS queries with very long labels (tunnelling heuristic)
```spl
index=* EventCode=22
| rex field=QueryName "^(?<sub>[^.]+)\\."
| eval len=len(sub)
| where len > 40
| stats count by QueryName Computer
```

## 10. Scheduled tasks created outside business hours
```spl
index=* EventCode=4698
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 20
| table _time host SubjectUserName TaskName
```

## 11. Password spray - one failure, many accounts, one source
```spl
index=* EventCode=4625
| stats count as fails dc(user) as accounts by src_ip
| where accounts > 5 AND fails > 5
```

## 12. Audit log cleared
```spl
index=* EventCode=1102
| table _time host SubjectUserName
```
"""


def export_splunk_assets(out_dir: Path | str, rule_dir: Path | str | None = None) -> list[Path]:
    """Write every Splunk artefact and return the list of files written."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rules = load_rules(rule_dir or (REPO_ROOT / "rules"))

    written: list[Path] = []

    conf_path = out_dir / "savedsearches.conf"
    conf_path.write_text(build_savedsearches_conf(rules), encoding="utf-8")
    written.append(conf_path)

    dash_path = out_dir / "dashboard_soc_lab.xml"
    dash_path.write_text(build_dashboard_xml(rules), encoding="utf-8")
    written.append(dash_path)

    hunts_path = out_dir / "hunting_queries.md"
    hunts_path.write_text(build_hunting_queries(), encoding="utf-8")
    written.append(hunts_path)

    readme_path = out_dir / "README.md"
    readme_path.write_text(_build_readme(rules), encoding="utf-8")
    written.append(readme_path)

    return written


def _build_readme(rules: list[Rule]) -> str:
    return f"""# Splunk assets exported from the SOC Lab

`python -m soclab splunk` regenerates every file in this folder from the
rules in `../rules/`.  There are {len(rules)} rules.

## 1. Load the saved searches (Splunk Enterprise, 30-day trial is enough)

```bash
# copy the conf file into the app directory
sudo cp savedsearches.conf \\
  $SPLUNK_HOME/etc/apps/soc_lab/local/savedsearches.conf
$SPLUNK_HOME/bin/splunk reload savedsearch
```

Or, in the browser: **Settings -> Search & Reporting -> Searches, Reports &
Dashboards -> add a new saved search** and paste the `search =` line.

## 2. Load the dashboard

Settings -> Search & Reporting -> Dashboards -> Create -> Import Dashboard,
then upload `dashboard_soc_lab.xml`.

## 3. Use the hunting queries

`hunting_queries.md` contains 12 ready-to-run hunts.  Copy a query into the
Search bar and change `index=*` to the index that holds your events.

## 4. Bring in the lab data

The easiest way to see the rules fire against real-looking data:

```bash
python -m soclab generate          # writes data/events.jsonl
```

Then load it into Splunk as a JSON index (Splunk 9) or convert it with
`splunk-unwrap`/`kv` into key=value events.

## Field mapping

The lab uses ECS-style field names; the SPL uses Splunk CIM names:

| Lab field (ECS)     | Splunk field     |
|---------------------|------------------|
| `event.code`        | `EventCode`      |
| `host.name`         | `host`           |
| `user.name`         | `user`           |
| `source.ip`         | `src_ip`         |
| `destination.ip`    | `dest_ip`        |
| `process.name`      | `Image`          |
| `process.command_line` | `CommandLine` |
| `file.name`         | `file_name`      |
| `url.original`      | `url`            |
| `winlog.logon_type` | `Logon_Type`     |

## A note on licensing

Saved-search *scheduling* and alerting require a Splunk Enterprise
Security licence. The 30-day Splunk Enterprise trial is enough to load the
saved searches and run every hunt, which is all you need to demo this.
"""
