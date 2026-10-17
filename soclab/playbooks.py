"""Response playbook loader.

A playbook is the "what do I actually do now" half of a SOC job.  Detection
without response is a dashboard; a Tier-1 analyst is judged on closing the loop.

Each playbook is a YAML document with:

  * ``id`` / ``title``
  * ``triage``      - what to check first, in order
  * ``contain``     - commands to stop the bleeding (PowerShell / bash / SPL)
  * ``eradicate``   - remove the persistence
  * ``recover``     - restore the asset
  * ``escalate``    - when and to whom to escalate
  * ``comms``       - a short template an analyst can paste into a ticket
  * ``mitre``       - techniques covered
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAYBOOK_DIR = REPO_ROOT / "playbooks"


@dataclass(slots=True)
class Playbook:
    id: str
    title: str
    triage: list[str] = field(default_factory=list)
    contain: list[dict[str, str]] = field(default_factory=list)
    eradicate: list[dict[str, str]] = field(default_factory=list)
    recover: list[str] = field(default_factory=list)
    escalate: list[str] = field(default_factory=list)
    comms: str = ""
    mitre: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "triage": self.triage,
            "contain": self.contain,
            "eradicate": self.eradicate,
            "recover": self.recover,
            "escalate": self.escalate,
            "comms": self.coms,
            "mitre": self.mitre,
            "evidence": self.evidence,
        }


def load_playbooks(playbook_dir: Path | str = DEFAULT_PLAYBOOK_DIR) -> dict[str, Playbook]:
    playbook_dir = Path(playbook_dir)
    out: dict[str, Playbook] = {}
    for path in sorted(playbook_dir.glob("*.y*ml")):
        docs = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if isinstance(docs, list):
            for doc in docs:
                pb = _to_playbook(doc)
                out[pb.id] = pb
        else:
            pb = _to_playbook(docs)
            out[pb.id] = pb
    return out


def _to_playbook(doc: dict[str, Any]) -> Playbook:
    def _steps(value: Any) -> list[dict[str, str]]:
        if not value:
            return []
        if isinstance(value, list):
            return [s if isinstance(s, dict) else {"step": str(s)} for s in value]
        return [{"step": str(value)}]

    return Playbook(
        id=str(doc.get("id", "UNKNOWN")),
        title=str(doc.get("title", "Untitled playbook")),
        triage=[str(t) for t in (doc.get("triage") or [])],
        contain=_steps(doc.get("contain")),
        eradicate=_steps(doc.get("eradicate")),
        recover=[str(r) for r in (doc.get("recover") or [])],
        escalate=[str(e) for e in (doc.get("escalate") or [])],
        comms=str(doc.get("comms", "")),
        mitre=[str(m) for m in (doc.get("mitre") or [])],
        evidence=[str(e) for e in (doc.get("evidence") or [])],
    )
