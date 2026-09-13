"""Per-class verdict evaluators for the dynamic-validation stage (ADR-017).

Replaces the hardcoded ``if/else`` over HTTP status codes with a registry of
pure, per-class evaluator functions.  Each evaluator maps a
:class:`LiveProbeEvidence` (resolved status + body TEXT + optional differential
probes) to the live-verdict vocabulary:

- ``corroborated``      the live target confirmed the hypothesis,
- ``not_corroborated``  the target actively defended / refuted it,
- ``inconclusive``      the probe could not decide.

This module is the CANONICAL home of that vocabulary and of
:func:`live_verdict_from_status`; ``quarry_workflows.run_scan`` re-exports both
for backward compatibility (its import direction already flows
quarry_workflows → quarry_activities, so no import cycle is introduced).

Purity: evaluators and registry helpers perform no I/O, so they are safe to call
from workflow code running under Temporal's sandbox.  Body artifacts are
resolved to text by ACTIVITIES (``read-artifact-text``) before evidence is
constructed here — evaluators never see raw artifact refs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from quarry.schemas import VulnerabilityClass

__all__ = [
    "CORROBORATED",
    "INCONCLUSIVE",
    "NOT_CORROBORATED",
    "LIVE_CORROBORATED",
    "LIVE_INCONCLUSIVE",
    "LIVE_NOT_CORROBORATED",
    "Evaluator",
    "LiveProbeEvidence",
    "Verdict",
    "VERDICT_SOURCE_DEFAULT",
    "VERDICT_SOURCE_PER_CLASS",
    "clear_evaluators",
    "default_evaluator",
    "evaluate_live_verdict",
    "evaluate_live_verdict_with_source",
    "live_verdict_from_status",
    "register_evaluator",
    "registered_classes",
    "resolve_evaluator",
]

# Live-verdict vocabulary for the agentic dynamic-validation stage (ADR-017).
LIVE_CORROBORATED = "corroborated"
LIVE_NOT_CORROBORATED = "not_corroborated"
LIVE_INCONCLUSIVE = "inconclusive"

# Verdict-provenance tags recorded on the finding.dynamic_validated event.
VERDICT_SOURCE_PER_CLASS = "per_class"
VERDICT_SOURCE_DEFAULT = "default"

# Back-compat aliases (dynamic_validate_stage's re-export names).
CORROBORATED = LIVE_CORROBORATED
NOT_CORROBORATED = LIVE_NOT_CORROBORATED
INCONCLUSIVE = LIVE_INCONCLUSIVE

# Status codes that indicate the live target actively defends the path — the
# candidate hypothesis is NOT corroborated (guard present / resource absent).
_LIVE_DEFENDED_STATUS = frozenset({401, 403, 404})


def live_verdict_from_status(status_code: int) -> str:
    """Map an HTTP status code to a live-corroboration verdict.

    Pure function (no I/O) — safe inside sandboxed workflow code.

    - 2xx → ``corroborated`` (the hypothesised path is served live).
    - 401/403/404 → ``not_corroborated`` (the target enforces the guard).
    - anything else (5xx, other ambiguous codes) → ``inconclusive``.
    """
    if 200 <= status_code < 300:
        return LIVE_CORROBORATED
    if status_code in _LIVE_DEFENDED_STATUS:
        return LIVE_NOT_CORROBORATED
    return LIVE_INCONCLUSIVE


Verdict = str
Evaluator = Callable[["LiveProbeEvidence"], Verdict]


@dataclass(frozen=True)
class LiveProbeEvidence:
    """Resolved live-probe inputs for a single candidate.

    Bodies are resolved TEXT (activities read artifacts); never raw refs.
    The primary probe comes first; optional baseline/differential probes follow
    in ``additional``.  ``body_text`` may be None when the artifact could not
    be resolved — evaluators treat a missing body as non-corroboration, never
    an error.
    """

    status_code: int
    body_text: str | None = None
    additional: tuple[LiveProbeEvidence, ...] = field(default=())


_REGISTRY: dict[VulnerabilityClass, Evaluator] = {}


def register_evaluator(cls: VulnerabilityClass, fn: Evaluator) -> None:
    """Register *fn* as the evaluator for *cls* (last registration wins)."""
    _REGISTRY[cls] = fn


def registered_classes() -> list[VulnerabilityClass]:
    """Return the classes that currently have a per-class evaluator."""
    return list(_REGISTRY)


def clear_evaluators() -> None:
    """Remove all per-class registrations (every class falls back to default).

    Test-support / reset hook: the module-level registry is global state, and
    tests that register sentinel evaluators need a public way to reset it
    without touching module internals.
    """
    _REGISTRY.clear()


def resolve_evaluator(cls: VulnerabilityClass) -> Evaluator:
    """Return the evaluator for *cls*, defaulting to the status-only evaluator."""
    return _REGISTRY.get(cls, default_evaluator)


def default_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """Status-only fallback: identical to ``live_verdict_from_status``.

    Ignores body text and differential probes — evidence beyond the status
    code only matters to classes with a registered per-class evaluator.
    """
    return live_verdict_from_status(ev.status_code)


def evaluate_live_verdict(cls: VulnerabilityClass, ev: LiveProbeEvidence) -> Verdict:
    """Evaluate *ev* with the evaluator registered for *cls* (default fallback)."""
    return resolve_evaluator(cls)(ev)


def evaluate_live_verdict_with_source(
    cls: VulnerabilityClass,
    ev: LiveProbeEvidence,
) -> tuple[Verdict, str]:
    """Like :func:`evaluate_live_verdict` but also returns the provenance tag.

    Returns ``(verdict, "per_class" | "default")`` so the caller can record
    which evaluator decided — surfaced on the ``finding.dynamic_validated``
    event as ``verdict_source``.
    """
    fn = _REGISTRY.get(cls)
    if fn is None:
        return default_evaluator(ev), VERDICT_SOURCE_DEFAULT
    return fn(ev), VERDICT_SOURCE_PER_CLASS
