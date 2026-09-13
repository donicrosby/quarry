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
    "EvaluatorSpec",
    "LiveProbeEvidence",
    "SSTI_MARKER",
    "Verdict",
    "VERDICT_SOURCE_DEFAULT",
    "VERDICT_SOURCE_PER_CLASS",
    "clear_evaluators",
    "default_evaluator",
    "evaluate_live_verdict",
    "evaluate_live_verdict_with_source",
    "live_verdict_from_status",
    "register_builtin_evaluators",
    "register_evaluator",
    "registered_classes",
    "resolve_evaluator",
    "resolve_evaluator_spec",
    "sql_injection_evaluator",
    "ssti_evaluator",
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


_REGISTRY: dict[VulnerabilityClass, EvaluatorSpec] = {}


@dataclass(frozen=True)
class EvaluatorSpec:
    """A registered evaluator plus the metadata the workflow consults.

    ``min_probes`` is how many live probes a class NEEDS before its evaluator
    can decide: 1 for status/marker evaluators, 2 for differential evaluators
    (SQLi boolean TRUE/FALSE pair — the baseline rides in ``additional``).
    The dynamic-validate dispatch loop consults this to decide whether to send
    a second probe (budget permitting); single-probe classes keep exactly the
    one-dispatch behavior.
    """

    fn: Evaluator
    min_probes: int = 1


def register_evaluator(
    cls: VulnerabilityClass,
    fn: Evaluator,
    *,
    min_probes: int = 1,
) -> None:
    """Register *fn* as the evaluator for *cls* (last registration wins).

    ``min_probes`` declares how many probes the evaluator needs (1 = single
    probe, 2 = a differential primary/baseline pair).
    """
    _REGISTRY[cls] = EvaluatorSpec(fn=fn, min_probes=min_probes)


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
    return _REGISTRY.get(cls, _DEFAULT_SPEC).fn


def resolve_evaluator_spec(cls: VulnerabilityClass) -> EvaluatorSpec:
    """Return the evaluator spec (fn + min_probes) for *cls*.

    Unregistered classes resolve to the default status-only evaluator with
    ``min_probes=1`` — the pre-registry single-dispatch behavior.
    """
    return _REGISTRY.get(cls, _DEFAULT_SPEC)


def default_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """Status-only fallback: identical to ``live_verdict_from_status``.

    Ignores body text and differential probes — evidence beyond the status
    code only matters to classes with a registered per-class evaluator.
    """
    return live_verdict_from_status(ev.status_code)


_DEFAULT_SPEC = EvaluatorSpec(fn=default_evaluator, min_probes=1)


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
    spec = _REGISTRY.get(cls)
    if spec is None:
        return default_evaluator(ev), VERDICT_SOURCE_DEFAULT
    return spec.fn(ev), VERDICT_SOURCE_PER_CLASS


# ---------------------------------------------------------------------------
# Built-in per-class evaluators (per-class-dynamic-validation tasks 1.3/1.4)
# ---------------------------------------------------------------------------

# SSTI arithmetic-marker probe: the agent sends ``{{7*7}}``; a template engine
# that evaluates it renders the result into the response body.
SSTI_MARKER = "49"


def _is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def ssti_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """SSTI arithmetic-marker evaluator (single probe).

    The probe carries ``{{7*7}}`` to the injectable parameter; corroboration
    means the EVALUATED result ``49`` appears in the 2xx response body — the
    engine executed the expression — and not the literal ``{{7*7}}`` string.

    - non-2xx → ``inconclusive`` (probe error / guard; cannot decide).
    - 2xx + body contains ``49`` → ``corroborated``.
    - 2xx without the marker, or an unresolvable body → ``not_corroborated``
      (missing body is non-corroboration, never an error).
    - ``additional`` (differential) probes are ignored: SSTI is single-probe.
    """
    if not _is_2xx(ev.status_code):
        return LIVE_INCONCLUSIVE
    if ev.body_text and SSTI_MARKER in ev.body_text:
        return LIVE_CORROBORATED
    return LIVE_NOT_CORROBORATED


def sql_injection_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """SQLi boolean-differential evaluator (primary + baseline pair).

    The workflow dispatches a TRUE-payload probe (primary) and its FALSE-payload
    counterpart (baseline, in ``ev.additional[0]``).  Corroboration means the
    two 2xx bodies diverge — the injected predicate changed the query's boolean
    semantics — not that a syntax error appeared.

    - no baseline probe → ``inconclusive`` (the differential needs the pair).
    - primary non-2xx → ``inconclusive`` (probe error; cannot decide).
    - either body unresolvable (None) → ``inconclusive`` (no text to compare).
    - bodies diverge → ``corroborated``; identical (incl. both empty, or both
      echoing the payload) → ``not_corroborated`` (parameterisation swallows it).

    Honest limitation: the diff is symmetric — it cannot tell WHICH probe the
    divergence favors; ``probe_count`` on the event payload lets a post-run
    audit distinguish primary-heavy from baseline-heavy divergence.  Extra
    probes beyond the baseline are ignored (only the first baseline compares).
    """
    if not ev.additional:
        return LIVE_INCONCLUSIVE
    baseline = ev.additional[0]
    if not _is_2xx(ev.status_code):
        return LIVE_INCONCLUSIVE
    if ev.body_text is None or baseline.body_text is None:
        return LIVE_INCONCLUSIVE
    if ev.body_text != baseline.body_text:
        return LIVE_CORROBORATED
    return LIVE_NOT_CORROBORATED


def register_builtin_evaluators() -> None:
    """Register the shipped per-class evaluators (idempotent, import-safe).

    Called at module import so SSTI/SQL_INJECTION candidates route per-class as
    soon as the registry is loaded; also safe to re-call (e.g. from tests that
    cleared the registry) — last registration wins, so this is idempotent.
    """
    register_evaluator(VulnerabilityClass.SSTI, ssti_evaluator, min_probes=1)
    register_evaluator(VulnerabilityClass.SQL_INJECTION, sql_injection_evaluator, min_probes=2)


register_builtin_evaluators()
