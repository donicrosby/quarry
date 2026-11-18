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
    "ssrf_evaluator",
    "ssti_evaluator",
    "timing_differential_evaluator",
    "TIMING_INJECTED_DELAY_FRACTION",
    "TIMING_MIN_SIGMA_MULTIPLIER",
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

    ``duration_seconds`` / ``injected_delay_seconds`` carry the timing signal for
    the timing-differential evaluator (blind SQLi / command injection): the
    primary probe's observed round-trip duration, and the delay the probe
    intended to inject. Both default to None so status/marker evaluators ignore
    them and pre-existing callers are unaffected.
    """

    status_code: int
    body_text: str | None = None
    additional: tuple[LiveProbeEvidence, ...] = field(default=())
    duration_seconds: float | None = None
    injected_delay_seconds: float | None = None


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


def _sql_boolean_differential_evaluator(ev: LiveProbeEvidence) -> Verdict:
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


def ssrf_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """SSRF boolean-differential evaluator (primary + baseline pair).

    The workflow dispatches a userinfo-bypass probe (primary) — e.g.
    ``/fetch-local?url=http://localhost@<target-origin>/users/1`` — whose
    nested URL defeats a naive ``startswith`` prefix check while still
    fetching the scan target itself, and a baseline probe (``additional[0]``)
    fetching the same nested endpoint WITHOUT the bypass (or a disallowed/
    never-resolving URL the guard must reject).  Corroboration means the two
    bodies diverge: the bypassed probe reached nested-endpoint content the
    baseline could not — the server really fetched an attacker-shaped URL.

    - no baseline probe → ``inconclusive`` (the differential needs the pair).
    - primary non-2xx → ``inconclusive`` (guard rejected the bypass, or the
      nested fetch itself errored — e.g. the app's own 500 — cannot decide).
    - either body unresolvable (None) → ``inconclusive`` (no text to compare).
    - bodies diverge → ``corroborated``; identical → ``not_corroborated``
      (the parameter drives no observable difference — validated or inert).

    Honest limitation: the diff is symmetric — it cannot tell WHICH probe the
    divergence favors, nor distinguish "nested fetch succeeded" from any other
    response asymmetry (e.g. a cache or rate limiter keyed on the URL).  The
    pair is CONSTRUCTED to make the primary the only one that can return
    nested-endpoint content, so in practice divergence implies the bypass
    worked; ``probe_count`` on the event payload lets a post-run audit
    re-examine.  Extra probes beyond the baseline are ignored.
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


# ---------------------------------------------------------------------------
# Timing-differential evaluator (credibility-economics step 4)
# ---------------------------------------------------------------------------

# K: how many robust baseline sigmas the induced delay must clear. Pinned (not a
# magic number inside the predicate) so the rule is auditable and the fixtures
# can assert the exact bound.
TIMING_MIN_SIGMA_MULTIPLIER = 3.0
# The induced delay must also clear this fraction of the delay the probe
# intended to inject — a timing signal smaller than that is noise, not evidence.
TIMING_INJECTED_DELAY_FRACTION = 0.6
# 1.4826 * MAD is the consistency constant that makes the median absolute
# deviation an unbiased estimator of sigma for normally distributed samples.
_MAD_TO_SIGMA = 1.4826


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _mad_robust_sigma(values: list[float]) -> float:
    """MAD-based robust standard deviation of *values*."""
    centre = _median(values)
    return _MAD_TO_SIGMA * _median([abs(v - centre) for v in values])


def timing_differential_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """Timing-differential evaluator for blind SQLi / command injection.

    Blind classes produce no marker in the body, so the signal is *time*: the
    attack probe induces a delay the baseline probes do not. The primary probe
    (``ev``) is the attack sample; ``ev.additional`` carries the baseline
    samples. Corroboration requires ALL of:

    - at least 2 baseline samples and a baseline spread (an all-identical
      baseline has no measurable noise, so the threshold would collapse to zero),
    - a majority of the baseline samples strictly below the attack duration
      (majority-sample consistency: a single fast baseline must not decide it),
    - the observed delay (attack − median baseline) clearing
      ``max(K * robust_sigma(baseline), 0.6 * injected_delay)``.

    Returns ``inconclusive`` when the timing samples are absent — the caller
    (the cascade's step 4) then falls through to the debater. ``not_corroborated``
    means the delay did not clear the bound (no induced timing signal).
    """
    attack = ev.duration_seconds
    if attack is None:
        return LIVE_INCONCLUSIVE
    baselines = [b.duration_seconds for b in ev.additional if b.duration_seconds is not None]
    if len(baselines) < 2:
        return LIVE_INCONCLUSIVE
    baseline_median = _median(baselines)
    sigma = _mad_robust_sigma(baselines)
    if sigma <= 0.0:
        # A degenerate (zero-spread) baseline cannot produce a calibrated bound.
        return LIVE_INCONCLUSIVE
    observed = attack - baseline_median
    if observed <= 0.0:
        return LIVE_NOT_CORROBORATED
    faster = sum(1 for value in baselines if value < attack)
    if faster * 2 <= len(baselines):
        return LIVE_NOT_CORROBORATED
    injected = ev.injected_delay_seconds
    required = TIMING_MIN_SIGMA_MULTIPLIER * sigma
    if injected is not None:
        required = max(required, TIMING_INJECTED_DELAY_FRACTION * injected)
    if observed >= required:
        return LIVE_CORROBORATED
    return LIVE_NOT_CORROBORATED


def sql_injection_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """SQLi evaluator: timing-differential when durations are present, else boolean.

    Blind SQLi carries no boolean/error differential — only an induced delay — so
    when the evidence carries timing samples the timing evaluator decides; the
    pre-existing boolean-differential path is unchanged for the (common) case
    where the evidence carries bodies but no durations.
    """
    if ev.duration_seconds is not None:
        return timing_differential_evaluator(ev)
    return _sql_boolean_differential_evaluator(ev)


def register_builtin_evaluators() -> None:
    """Register the shipped per-class evaluators (idempotent, import-safe).

    Called at module import so SSTI/SQL_INJECTION/SSRF candidates route
    per-class as soon as the registry is loaded; also safe to re-call (e.g.
    from tests that cleared the registry) — last registration wins, so this
    is idempotent.
    """
    register_evaluator(VulnerabilityClass.SSTI, ssti_evaluator, min_probes=1)
    register_evaluator(VulnerabilityClass.SQL_INJECTION, sql_injection_evaluator, min_probes=2)
    register_evaluator(VulnerabilityClass.SSRF, ssrf_evaluator, min_probes=2)
    register_evaluator(VulnerabilityClass.COMMAND_INJECTION, timing_differential_evaluator)


register_builtin_evaluators()
