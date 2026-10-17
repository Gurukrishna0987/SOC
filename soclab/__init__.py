"""SOC Lab - a hands-on Security Operations Centre home lab.

The package is organised the way a SOC pipeline actually flows:

    generator -> events -> engine (rules) -> alerts -> triage -> incidents
                                     \\-> eval (coverage & precision)

Each stage is a separate module so that you can test, profile and explain
every step - which is exactly what an interviewer will ask you to do.
"""

__version__ = "1.0.0"

from .events import Event  # noqa: F401
from .engine import Alert, DetectionEngine  # noqa: F401
from .rules import Rule, load_rules  # noqa: F401
from .triage import Incident, TriageEngine  # noqa: F401

__all__ = [
    "Event",
    "Alert",
    "DetectionEngine",
    "Rule",
    "load_rules",
    "Incident",
    "TriageEngine",
]
