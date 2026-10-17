"""Command line interface for the SOC lab.

    python -m soclab demo                 # run the whole pipeline end to end
    python -m soclab generate             # write the labelled corpus
    python -m soclab detect               # run detection rules
    python -m soclab triage               # score and prioritise incidents
    python -m soclab evaluate             # detection coverage + precision
    python -m soclab report               # human readable summary
    python -m soclab serve                # launch the SOC dashboard
    python -m soclab splunk               # export Splunk SPL / saved searches
    python -m soclab hunt --host DC01     # quick ad-hoc hunt
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import DetectionEngine
from .eval import evaluate
from .events import Event
from .generator import generate_corpus
from .pipeline import DATA_DIR, REPO_ROOT, load_corpus, run_pipeline, save_corpus, save_json
from .rules import load_rules
from .triage import TriageEngine

CORPUS_PATH = DATA_DIR / "events.jsonl"
ALERTS_PATH = DATA_DIR / "alerts.json"
INCIDENTS_PATH = DATA_DIR / "incidents.json"
REPORT_PATH = DATA_DIR / "evaluation.json"


def _load_events(args: argparse.Namespace) -> list[Event]:
    if args.corpus and Path(args.corpus).exists():
        return load_corpus(args.corpus)
    return generate_corpus(seed=args.seed, benign_count=args.benign)


def _rules():
    return load_rules(REPO_ROOT / "rules")


# --- commands ---------------------------------------------------------------

def cmd_generate(args: argparse.Namespace) -> int:
    events = generate_corpus(seed=args.seed, benign_count=args.benign)
    path = save_corpus(events, args.out or CORPUS_PATH)
    attacks = sum(1 for e in events if e.ground_truth)
    print(f"Generated {len(events)} events ({attacks} attack / {len(events) - attacks} benign)")
    print(f"Written to {path}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    events = _load_events(args)
    rules = _rules()
    alerts = DetectionEngine(rules).run(events)
    save_json([a.to_dict() for a in alerts], args.out or ALERTS_PATH)
    print(f"Detection complete: {len(alerts)} alerts from {len(rules)} rules over {len(events)} events")
    for alert in alerts[:10]:
        print(f"  [{alert.severity.upper():<7}] {alert.rule_id}  {alert.rule_title} ({alert.event_count} events)")
    print(f"Written to {args.out or ALERTS_PATH}")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    events = _load_events(args)
    rules = _rules()
    alerts = DetectionEngine(rules).run(events)
    incidents = TriageEngine().triage(alerts, events)
    save_json([i.to_dict() for i in incidents], args.out or INCIDENTS_PATH)
    print(f"Triaged {len(alerts)} alerts into {len(incidents)} incidents")
    for inc in incidents[:10]:
        print(
            f"  {inc.priority}  score={inc.risk_score:<6} {inc.rule_id:<8} "
            f"{inc.asset:<13} {inc.title[:60]}"
        )
    print(f"Written to {args.out or INCIDENTS_PATH}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    events = _load_events(args)
    rules = _rules()
    alerts = DetectionEngine(rules).run(events)
    report = evaluate(events, alerts, rules)
    data = report.to_dict()
    save_json(data, args.out or REPORT_PATH)

    print("=" * 68)
    print("DETECTION EVALUATION")
    print("=" * 68)
    print(f"Attack events          : {data['attack_events']}")
    print(f"Benign events          : {data['benign_events']}")
    print(f"Alerts raised          : {data['true_positive_alerts'] + data['false_positive_alerts']}")
    print(f"True-positive alerts   : {data['true_positive_alerts']}")
    print(f"False-positive alerts  : {data['false_positive_alerts']}")
    print(f"Alert precision        : {data['alert_precision'] * 100:.1f}%")
    print(f"Attack-stage recall    : {data['stage_recall'] * 100:.1f}%  "
          f"({data['stage_detected']}/{data['stage_total']} stages)")
    print("-" * 68)
    for stage in data["stage_results"]:
        mark = "DETECTED" if stage["detected"] else "MISSED  "
        rules_fired = ",".join(stage["rules"]) or "-"
        print(f"  {mark}  {stage['scenario']:<18} {stage['stage']:<22} [{rules_fired}]")
    if data["missed_stages"]:
        print("-" * 68)
        print("Blind spots: " + ", ".join(data["missed_stages"]))
    print("=" * 68)
    print(f"Written to {args.out or REPORT_PATH}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    result = run_pipeline(seed=args.seed, benign_count=args.benign)
    print(json.dumps(result.summary(), indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .dashboard import create_app

    app = create_app(seed=args.seed, benign_count=args.benign)
    print(f"SOC dashboard running on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_splunk(args: argparse.Namespace) -> int:
    from .splunk import export_splunk_assets

    out_dir = Path(args.out or (REPO_ROOT / "splunk"))
    written = export_splunk_assets(out_dir)
    for path in written:
        print(f"  wrote {path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    events = _load_events(args)
    needle = args.query.lower()
    hits = []
    for evt in events:
        blob = json.dumps(evt.fields, default=str).lower()
        if needle in blob:
            hits.append(evt)
    print(f"{len(hits)} event(s) matched '{args.query}'")
    for evt in hits[: args.limit]:
        print(
            f"  {evt.timestamp.isoformat()}  {evt.source:<16} "
            f"{evt.get('event.code', ''):<12} {evt.get('host.name', ''):<14} "
            f"{evt.get('user.name', ''):<16} {str(evt.get('message', ''))[:70]}"
        )
    return 0


def cmd_vapt(args: argparse.Namespace) -> int:
    from .vapt import SafetyError, save_report, scan

    try:
        result = scan(args.target, allow_remote=args.allow_remote)
    except SafetyError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2

    print("=" * 68)
    print(f"WEB ASSESSMENT - {result.target}")
    print("=" * 68)
    print(f"HTTP status: {result.status}")
    for severity, count in sorted(result.counts().items(), key=lambda kv: -kv[0].count("C")):
        print(f"  {severity:<9} {count}")
    print("-" * 68)
    for i, f in enumerate(result.findings, 1):
        print(f"  {i}. [{f.severity:<8}] {f.title}")
        print(f"       OWASP {f.owasp}")
        print(f"       {f.evidence}")
    print("=" * 68)

    out = args.out or "data/vapt-report.md"
    save_report(result, out)
    print(f"Report written to {out}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    result = run_pipeline(seed=args.seed, benign_count=args.benign)
    summary = result.summary()
    print("=" * 68)
    print("SOC LAB - END TO END DEMO")
    print("=" * 68)
    print(f"Telemetry generated : {summary['events']} events "
          f"({summary['attack_events']} attack / {summary['events'] - summary['attack_events']} benign)")
    print(f"Rules evaluated     : {len(result.rules)}")
    print(f"Alerts raised       : {summary['alerts']}")
    print(f"Incidents triaged   : {summary['incidents']}  {summary['by_priority']}")
    print(f"Attack-stage recall : {summary['stage_recall'] * 100:.1f}%")
    print(f"Alert precision     : {summary['alert_precision'] * 100:.1f}%")
    print("-" * 68)
    print("TOP PRIORITY INCIDENTS")
    for inc in result.incidents[:8]:
        print(f"  {inc.priority}  {inc.risk_score:>5}  {inc.rule_id:<8} {inc.asset:<13} {inc.title[:52]}")
    print("=" * 68)
    save_corpus(result.events, CORPUS_PATH)
    save_json([i.to_dict() for i in result.incidents], INCIDENTS_PATH)
    save_json(result.report.to_dict(), REPORT_PATH)
    print(f"Corpus    -> {CORPUS_PATH.relative_to(REPO_ROOT)}")
    print(f"Incidents -> {INCIDENTS_PATH.relative_to(REPO_ROOT)}")
    print(f"Report    -> {REPORT_PATH.relative_to(REPO_ROOT)}")
    return 0


# --- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soclab",
        description="SOC Lab - a hands-on Security Operations Centre pipeline",
    )
    parser.add_argument("--seed", type=int, default=1337, help="random seed for reproducibility")
    parser.add_argument("--benign", type=int, default=220, help="number of benign background events")
    parser.add_argument("--corpus", help="path to an existing corpus jsonl file")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate", help="generate the labelled telemetry corpus")
    p.add_argument("--out")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("detect", help="run detection rules over the corpus")
    p.add_argument("--out")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("triage", help="triage alerts into prioritised incidents")
    p.add_argument("--out")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("evaluate", help="measure detection coverage and precision")
    p.add_argument("--out")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("report", help="print a pipeline summary")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("serve", help="launch the SOC dashboard")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("splunk", help="export Splunk SPL, saved searches and dashboards")
    p.add_argument("--out")
    p.set_defaults(func=cmd_splunk)

    p = sub.add_parser("hunt", help="free-text hunt across the corpus")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("vapt", help="run a local-only web security assessment")
    p.add_argument("target", help="target URL (loopback only unless --allow-remote)")
    p.add_argument("--out", help="output file (.md or .json)")
    p.add_argument("--allow-remote", action="store_true", help="permit scanning a non-local target")
    p.set_defaults(func=cmd_vapt)

    p = sub.add_parser("demo", help="run the full pipeline and write the artefacts")
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
