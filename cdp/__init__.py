"""Claude Detection Platform — Sigma-based detection-as-code with Claude triage."""

__version__ = "0.1.0"

from cdp.models import Alert, Event, SigmaRule, TriageResult

__all__ = ["Alert", "Event", "SigmaRule", "TriageResult", "__version__"]
