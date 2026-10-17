"""Flask dashboard for the SOC lab.

Design notes
------------
* **No external assets.**  Every chart is server-rendered SVG and every style
  is in ``static/style.css``.  The dashboard works on a plane, in an interview
  with no wifi, and cannot break because a CDN changed.
* **Analyst-first layout.**  The overview answers the four questions a
  Tier-1 analyst is asked on handover: what is burning, what is critical,
  what is spreading, and what did we miss.
* **The incident detail page is the product.**  It shows the risk breakdown,
  the raw events, the ATT&CK mapping and the response playbook in one place -
  which is what you screenshot for a portfolio.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, request

from . import schema as S
from .engine import Alert, DetectionEngine
from .eval import evaluate
from .generator import generate_corpus
from .playbooks import load_playbooks
from .pipeline import REPO_ROOT, run_pipeline
from .rules import load_rules
from .triage import TriageEngine

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


# --- small chart helpers ----------------------------------------------------

def svg_bar_chart(data: list[tuple[str, float]], *, width: int = 520, bar: int = 22, color: str = "#38bdf8") -> str:
    """Horizontal bar chart as inline SVG."""
    if not data:
        return '<p class="muted">No data</p>'
    label_w = 150
    value_w = 60
    plot_w = width - label_w - value_w
    height = len(data) * (bar + 8) + 8
    top = max(v for _, v in data) or 1
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" class="chart">'
    ]
    for i, (label, value) in enumerate(data):
        y = i * (bar + 8) + 4
        w = max(2, int(plot_w * (value / top)))
        parts.append(
            f'<text x="0" y="{y + bar - 6}" class="lbl">{_esc(label)}</text>'
            f'<rect x="{label_w}" y="{y}" width="{w}" height="{bar}" rx="3" fill="{color}"/>'
            f'<text x="{label_w + w + 8}" y="{y + bar - 6}" class="val">{value:g}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def svg_timeline(points: list[tuple[str, float]], *, width: int = 760, height: int = 190) -> str:
    """Simple area/line chart of alert volume over time."""
    if not points:
        return '<p class="muted">No data</p>'
    pad_l, pad_b, pad_t = 44, 26, 10
    plot_w = width - pad_l - 12
    plot_h = height - pad_b - pad_t
    top = max(v for _, v in points) or 1
    n = len(points)
    step = plot_w / max(1, n - 1)
    coords = [
        (pad_l + i * step, pad_t + plot_h - (v / top) * plot_h) for i, (_, v) in enumerate(points)
    ]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area = (
        f"{pad_l},{pad_t + plot_h} " + line + f" {coords[-1][0]:.1f},{pad_t + plot_h}"
    )
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" class="chart">',
        f'<polygon points="{area}" fill="rgba(56,189,248,0.14)" />',
        f'<polyline points="{line}" fill="none" stroke="#38bdf8" stroke-width="2" />',
    ]
    for frac in (0, 0.5, 1):
        y = pad_t + plot_h - frac * plot_h
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - 12}" y2="{y:.1f}" '
            f'stroke="#1e293b" stroke-width="1" />'
        )
        parts.append(f'<text x="4" y="{y + 4:.1f}" class="val">{int(top * frac)}</text>')
    for i, (label, _) in enumerate(points):
        if i % max(1, len(points) // 8) == 0:
            x = pad_l + i * step
            parts.append(f'<text x="{x - 16:.1f}" y="{height - 6}" class="lbl">{_esc(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# --- application ------------------------------------------------------------

def create_app(seed: int = 1337, benign_count: int = 220) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
        static_url_path="/static",
    )
    app.config["JSON_SORT_KEYS"] = False

    result = run_pipeline(seed=seed, benign_count=benign_count)
    rules = {r.id: r for r in result.rules}
    playbooks = load_playbooks()

    app.config["LAB"] = result
    app.config["RULES"] = rules
    app.config["PLAYBOOKS"] = playbooks

    # -- overview --------------------------------------------------------
    @app.route("/")
    def index() -> str:
        incidents = result.incidents
        active = [i for i in incidents if i.status != "suppressed"]

        by_priority = Counter(i.priority for i in active)
        by_severity = Counter(i.severity for i in active)
        by_rule = Counter(i.rule_id for i in active).most_common(8)
        by_asset = Counter(i.asset for i in active).most_common(8)
        by_tactic = Counter(i.tactic for i in active if i.tactic).most_common(8)
        by_technique = Counter(i.technique_id for i in active if i.technique_id).most_common(10)

        # Alert volume per day
        per_day: Counter = Counter()
        for inc in active:
            per_day[inc.first_seen[:10]] += 1
        days = sorted(per_day)
        if not days:
            days = ["-"]
        span = (datetime.fromisoformat(days[-1]) - datetime.fromisoformat(days[0])).days or 1
        full_days = [days[0]]
        cur = datetime.fromisoformat(days[0])
        for _ in range(span):
            cur += timedelta(days=1)
            full_days.append(cur.strftime("%Y-%m-%d"))
        timeline = [(d[5:], per_day.get(d, 0)) for d in full_days]

        critical_assets = sorted(
            {i.asset for i in active if i.asset_criticality in ("critical", "high")}
        )
        report = result.report.to_dict()

        return render_template(
            "index.html",
            summary=result.summary(),
            incidents=active,
            by_priority=by_priority,
            by_severity=by_severity,
            rule_chart=svg_bar_chart([(f"{rid} {rules[rid].title[:26] if rid in rules else ''}", c) for rid, c in by_rule], color="#f97316"),
            asset_chart=svg_bar_chart(by_asset, color="#34d399"),
            tactic_chart=svg_bar_chart(by_tactic, color="#a78bfa"),
            technique_chart=svg_bar_chart(by_technique, color="#f472b6"),
            timeline_chart=svg_timeline(timeline),
            critical_assets=critical_assets,
            report=report,
            rules=rules,
        )

    # -- incidents -------------------------------------------------------
    @app.route("/incidents")
    def incidents() -> str:
        items = list(result.incidents)
        q = request.args.get("q", "").strip().lower()
        priority = request.args.get("priority", "").strip().upper()
        status = request.args.get("status", "").strip().lower()
        rule = request.args.get("rule", "").strip()

        if q:
            items = [
                i
                for i in items
                if q in i.title.lower()
                or q in i.asset.lower()
                or q in i.user.lower()
                or q in i.rule_id.lower()
                or q in (i.source_ip or "").lower()
                or q in (i.technique_id or "").lower()
            ]
        if priority:
            items = [i for i in items if i.priority == priority]
        if status:
            items = [i for i in items if i.status == status]
        if rule:
            items = [i for i in items if i.rule_id == rule]

        return render_template(
            "incidents.html",
            incidents=items,
            q=q,
            priority=priority,
            status=status,
            rule=rule,
            all_rules=sorted(rules),
            total=len(result.incidents),
        )

    @app.route("/incidents/<incident_id>")
    def incident_detail(incident_id: str) -> str:
        inc = next((i for i in result.incidents if i.id == incident_id), None)
        if inc is None:
            abort(404)
        rule = rules.get(inc.rule_id)
        pb = playbooks.get(inc.playbook)
        linked = [i for i in result.incidents if inc.id in i.linked_alerts]
        return render_template(
            "incident.html",
            inc=inc,
            rule=rule,
            playbook=pb,
            linked=linked,
            all_playbooks=playbooks,
        )

    # -- hunt ------------------------------------------------------------
    @app.route("/hunt")
    def hunt() -> str:
        query = request.args.get("q", "").strip()
        results: list[dict[str, Any]] = []
        if query:
            needle = query.lower()
            for evt in result.events:
                blob = json.dumps(evt.fields, default=str).lower()
                if needle in blob:
                    results.append(
                        {
                            "timestamp": evt.fields.get(S.TIMESTAMP, ""),
                            "source": evt.source,
                            "code": evt.fields.get(S.EVENT_CODE, ""),
                            "host": evt.fields.get(S.HOST_NAME, ""),
                            "user": evt.fields.get(S.USER_NAME, ""),
                            "message": evt.fields.get(S.MESSAGE, ""),
                            "scenario": evt.scenario,
                        }
                    )
                if len(results) >= 200:
                    break
        return render_template("hunt.html", query=query, results=results)

    # -- coverage --------------------------------------------------------
    @app.route("/coverage")
    def coverage() -> str:
        report = result.report.to_dict()
        rule_rows = []
        for r in result.rules:
            stats = report["rule_stats"].get(r.id, {"alerts": 0, "true_positive": 0, "false_positive": 0})
            rule_rows.append((r, stats))
        technique_map: dict[str, list] = defaultdict(list)
        for r in result.rules:
            technique_map[r.technique_id].append(r)
        incidents_first: dict[str, str] = {}
        for inc in result.incidents:
            incidents_first.setdefault(inc.rule_id, inc.id)
        return render_template(
            "coverage.html",
            report=report,
            rule_rows=rule_rows,
            technique_map=dict(technique_map),
            rules=rules,
            incidents_first=incidents_first,
        )

    # -- playbooks -------------------------------------------------------
    @app.route("/playbooks")
    def playbooks_index() -> str:
        return render_template("playbooks.html", playbooks=playbooks, rules=rules)

    @app.route("/playbooks/<playbook_id>")
    def playbook_detail(playbook_id: str) -> str:
        pb = playbooks.get(playbook_id)
        if pb is None:
            abort(404)
        linked_rules = [r for r in result.rules if r.playbook == playbook_id]
        return render_template("playbook.html", pb=pb, linked_rules=linked_rules)

    # -- API -------------------------------------------------------------
    @app.route("/api/summary")
    def api_summary():
        return jsonify(result.summary())

    @app.route("/api/incidents")
    def api_incidents():
        return jsonify([i.to_dict() for i in result.incidents])

    @app.route("/api/incidents/<incident_id>")
    def api_incident(incident_id: str):
        inc = next((i for i in result.incidents if i.id == incident_id), None)
        if inc is None:
            abort(404)
        return jsonify(inc.to_dict())

    @app.route("/api/evaluation")
    def api_evaluation():
        return jsonify(result.report.to_dict())

    @app.route("/api/events")
    def api_events():
        limit = min(int(request.args.get("limit", 200)), 1000)
        return jsonify([e.to_dict() for e in result.events[:limit]])

    @app.route("/api/rules")
    def api_rules():
        from dataclasses import asdict
        return jsonify([asdict(r) for r in result.rules])

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "events": len(result.events)})

    return app


def main() -> None:  # pragma: no cover - convenience entry point
    app = create_app()
    app.run(host="0.0.0.0", port=8080, debug=False)


if __name__ == "__main__":  # pragma: no cover
    main()
