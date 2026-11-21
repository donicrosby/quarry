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

import statistics
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
    "TIMING_ATTACK_SAMPLES",
    "TIMING_BASELINE_SAMPLES",
    "TIMING_STATISTICAL_PASS",
    "Evaluator",
    "EvaluatorSpec",
    "LiveProbeEvidence",
    "SSTI_MARKER",
    "Verdict",
    "VerdictReceipt",
    "VERDICT_SOURCE_DEFAULT",
    "VERDICT_SOURCE_PER_CLASS",
    "clear_evaluators",
    "default_evaluator",
    "evaluate_live_verdict",
    "evaluate_live_verdict_with_receipt",
    "evaluate_live_verdict_with_source",
    "file_upload_evaluator",
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

# --------------------------------------------------------------------------
# Oracle mechanisms derived from Pentest-Swarm AI (AGPL-3.0,
# swarm/verify/oracle/{timing,differential}.go) — re-derived as pure
# statistics and set operations; see THIRD_PARTY_NOTICES.md.
# --------------------------------------------------------------------------

# Statistical timing oracle sampling and thresholds. N clean (baseline)
# latency samples and M attack samples; a sample count that clears the budget
# is dispatched as one batch by the workflow.
TIMING_BASELINE_SAMPLES = 5  # N
TIMING_ATTACK_SAMPLES = 3  # M

# Noise floor (sigma multiplier) and the injected-delay fraction the induced
# delay must also clear; delay-ladder linearity band and additive floor.
_TIMING_SIGMA_MULTIPLIER = 3.0
_TIMING_DELAY_FRACTION = 0.6
_MAD_ROBUST_SCALE = 1.4826
_TIMING_LADDER_LOW = 1.4
_TIMING_LADDER_HIGH = 2.6

# Marker returned by the timing path when the initial statistical pass cleared
# but the delay ladder has not run yet.  It is a control signal for the
# workflow (dispatch the ladder), never a live verdict: the corroborated
# verdict requires ladder confirmation.
TIMING_STATISTICAL_PASS = "statistical_pass"

# Differential hardening: payload-echo normalization placeholder and the
# token-Jaccard similarity at/above which the two bodies are "equivalent".
_INJECTED_PLACEHOLDER = "§INJECTED§"
_TOKEN_JACCARD_THRESHOLD = 0.95


@dataclass(frozen=True)
class VerdictReceipt:
    """Audit receipt for one statistical timing-path evaluation.

    Carried onto the ``finding.dynamic_validated`` event payload (serialized)
    whenever the timing path ran, so a proven (or refused) blind-injection
    verdict is reproducible from the recorded statistics alone.

    ``n``/``m`` are the source design's N (baseline samples) and M (attack
    samples).  ``induced_delay_ms`` is the MEASURED median attack latency minus
    median baseline latency; ``threshold`` is the noise floor the induced delay
    had to clear; ``ladder_scale_factor`` is ladder_induced / first_induced and
    stays None until the delay ladder runs.  ``reason`` names why the verdict
    landed where it did.
    """

    n: int
    m: int
    baseline_median: float
    attack_median: float
    mad: float
    robust_sigma: float
    classical_sigma: float
    threshold: float
    induced_delay_ms: float
    majority_count: int
    majority_required: int
    ladder_scale_factor: float | None
    reason: str


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
    Timing/differential annotations are transported from the dispatched
    :class:`~quarry.schemas.HttpRequestSpec` at workflow dispatch time (the
    same way ``body_text``/``status_code`` flow): ``elapsed_ms`` is the probe
    latency, ``injected_values`` the agent-declared injected payload
    substrings, ``indicator`` the optional hunter-supplied success marker, and
    ``injected_delay_ms`` the agent-declared delay that opts the probe into the
    statistical timing path (absent → the hardened differential path)."""

    status_code: int
    body_text: str | None = None
    additional: tuple[LiveProbeEvidence, ...] = field(default=())
    duration_seconds: float | None = None
    injected_delay_seconds: float | None = None
    elapsed_ms: int | None = None
    injected_values: tuple[str, ...] | None = None
    indicator: str | None = None
    injected_delay_ms: int | None = None


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

    ``timing_profile`` marks classes whose evaluator can run the statistical
    timing path: the workflow dispatches N baseline + M attack latency probes
    when a probe carries an ``injected_delay_ms`` annotation, instead of the
    two-probe differential pair.  It is an explicit flag — never inferred from
    ``min_probes``.
    """

    fn: Evaluator
    min_probes: int = 1
    timing_profile: bool = False


def register_evaluator(
    cls: VulnerabilityClass,
    fn: Evaluator,
    *,
    min_probes: int = 1,
    timing_profile: bool = False,
) -> None:
    """Register *fn* as the evaluator for *cls* (last registration wins).

    ``min_probes`` declares how many probes the evaluator needs (1 = single
    probe, 2 = a differential primary/baseline pair).  ``timing_profile``
    declares a timing-oracle class (see :class:`EvaluatorSpec`).
    """
    _REGISTRY[cls] = EvaluatorSpec(fn=fn, min_probes=min_probes, timing_profile=timing_profile)


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


def evaluate_live_verdict_with_receipt(
    cls: VulnerabilityClass,
    ev: LiveProbeEvidence,
) -> tuple[Verdict, VerdictReceipt | None]:
    """Like :func:`evaluate_live_verdict` but also returns the timing receipt.

    The receipt is ``None`` unless the class runs the statistical timing path
    (a ``timing_profile`` class whose primary evidence carries
    ``injected_delay_ms``); the caller — the workflow — serializes a non-None
    receipt onto the ``finding.dynamic_validated`` event payload.  Evaluators
    stay pure ``LiveProbeEvidence -> Verdict`` callables with no event access,
    mirroring :func:`evaluate_live_verdict_with_source`.

    When the statistical pass clears but the ladder batch is absent from the
    evidence, the returned verdict is the internal ladder-trigger marker: the
    workflow dispatches the ladder batch, then re-evaluates the combined
    evidence to obtain the final three-way verdict.
    """
    spec = _REGISTRY.get(cls)
    if spec is None:
        return default_evaluator(ev), None
    if spec.timing_profile and ev.injected_delay_ms is not None:
        return _timing_evaluate(ev, ev.injected_delay_ms)
    return spec.fn(ev), None


# ---------------------------------------------------------------------------
# Built-in per-class evaluators (per-class-dynamic-validation tasks 1.3/1.4)
# ---------------------------------------------------------------------------

# SSTI arithmetic-marker probe: the agent sends ``{{7*7}}``; a template engine
# that evaluates it renders the result into the response body.
SSTI_MARKER = "49"


def _is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


# ---------------------------------------------------------------------------
# Differential hardening helpers (payload-echo normalization + indicator +
# token-Jaccard).  Mechanism re-derived from Pentest-Swarm AI (AGPL-3.0,
# swarm/verify/oracle/differential.go) — pure set operations; see
# THIRD_PARTY_NOTICES.md.
# ---------------------------------------------------------------------------


def _normalize_body(body: str, injected_values: tuple[str, ...]) -> str:
    """Replace every injected payload substring in *body* with a placeholder.

    Pure function.  A target that reflects the injected payload back into the
    response would otherwise make the attack and baseline bodies diverge by
    construction, masquerading as a semantic difference.  Replacing each
    agent-declared injected value with ``§INJECTED§`` on BOTH bodies collapses
    an echo-only difference to structural equivalence.  Empty values are
    skipped (``str.replace("")`` would insert the placeholder everywhere).
    """
    normalized = body
    for value in injected_values:
        if value:
            normalized = normalized.replace(value, _INJECTED_PLACEHOLDER)
    return normalized


def _token_jaccard(a: str, b: str) -> float:
    """Whitespace-token set Jaccard similarity ``|A ∩ B| / |A ∪ B|``.

    Pure function over two resolved bodies.  Two empty bodies (both token sets
    empty) are identical → 1.0.  Callers resolve ``None`` bodies to
    inconclusive BEFORE calling this; it receives only ``str``.
    """
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    union = tokens_a | tokens_b
    if not union:
        return 1.0
    return len(tokens_a & tokens_b) / len(union)


def _indicator_verdict(
    attack_body: str | None,
    baseline_body: str | None,
    indicator: str | None,
) -> Verdict | None:
    """Decide from a hunter-supplied success marker, or fall through.

    Checked on the RAW (pre-normalization) bodies, before the generic
    heuristics:

    - marker in the attack body only → ``corroborated``;
    - marker absent from both → ``not_corroborated``;
    - marker in both (or in the baseline only) → ``None`` (cannot decide from
      the marker alone — fall through to normalization/Jaccard).

    No marker supplied (``None``/empty) → ``None`` immediately (no-op).
    """
    if not indicator:
        return None
    in_attack = attack_body is not None and indicator in attack_body
    in_baseline = baseline_body is not None and indicator in baseline_body
    if in_attack and not in_baseline:
        return LIVE_CORROBORATED
    if not in_attack and not in_baseline:
        return LIVE_NOT_CORROBORATED
    return None


def _differential_verdict(ev: LiveProbeEvidence) -> Verdict:
    """Hardened boolean-differential verdict over a primary/baseline pair.

    Ordering: base early returns → indicator (raw bodies) → payload-echo
    normalization → token-Jaccard similarity → exact-body comparison.

    - no baseline probe → ``inconclusive`` (the differential needs the pair).
    - primary non-2xx → ``inconclusive`` (probe error / guard; cannot decide).
    - either body unresolvable (None) → ``inconclusive`` (nothing to compare;
      never an error, and None bodies never reach normalization or Jaccard).
    - indicator present in the attack body only → ``corroborated``; absent from
      both → ``not_corroborated``; present in both → fall through.
    - normalized bodies ≥ 0.95 token-Jaccard with matching status →
      ``not_corroborated`` (structurally equivalent); with differing status →
      ``inconclusive`` (equivalent bodies, different treatment).
    - below 0.95 → exact comparison of the NORMALIZED bodies: divergent →
      ``corroborated``, identical → ``not_corroborated``.
    """
    if not ev.additional:
        return LIVE_INCONCLUSIVE
    baseline = ev.additional[0]
    if not _is_2xx(ev.status_code):
        return LIVE_INCONCLUSIVE
    if ev.body_text is None or baseline.body_text is None:
        return LIVE_INCONCLUSIVE
    indicator_verdict = _indicator_verdict(ev.body_text, baseline.body_text, ev.indicator)
    if indicator_verdict is not None:
        return indicator_verdict
    injected = ev.injected_values or ()
    normalized_primary = _normalize_body(ev.body_text, injected)
    normalized_baseline = _normalize_body(baseline.body_text, injected)
    if _token_jaccard(normalized_primary, normalized_baseline) >= _TOKEN_JACCARD_THRESHOLD:
        if ev.status_code == baseline.status_code:
            return LIVE_NOT_CORROBORATED
        return LIVE_INCONCLUSIVE
    if normalized_primary != normalized_baseline:
        return LIVE_CORROBORATED
    return LIVE_NOT_CORROBORATED


# ---------------------------------------------------------------------------
# Statistical timing oracle (delay-annotated probes).  Mechanism re-derived
# from Pentest-Swarm AI (AGPL-3.0, swarm/verify/oracle/timing.go) as pure
# statistics; see THIRD_PARTY_NOTICES.md.
# ---------------------------------------------------------------------------


def _median(values: list[int] | list[float]) -> float:
    return float(statistics.median(values))


def _mad(values: list[int], center: float) -> float:
    """Median absolute deviation of *values* about *center*."""
    return float(statistics.median([abs(v - center) for v in values]))


def _timing_samples(
    ev: LiveProbeEvidence,
) -> tuple[list[int], list[int], list[int]]:
    """Split timing evidence into (baseline, attack, ladder) latency samples.

    Evidence shape (workflow-assembled): the primary probe is the FIRST attack
    probe; ``additional`` carries the N baseline probes, then the remaining
    ``M-1`` attack probes, then (only after the ladder ran) the M ladder attack
    probes.  A probe whose latency could not be observed contributes nothing —
    the caller treats an undersized batch as inconclusive, never an error.
    """
    additional = ev.additional
    n = TIMING_BASELINE_SAMPLES
    m = TIMING_ATTACK_SAMPLES
    baseline_group = additional[:n]
    attack_group = (ev,) + additional[n : n + m - 1]
    ladder_group = additional[n + m - 1 : n + m - 1 + m]
    baseline = [s.elapsed_ms for s in baseline_group if s.elapsed_ms is not None]
    attacks = [s.elapsed_ms for s in attack_group if s.elapsed_ms is not None]
    ladder = [s.elapsed_ms for s in ladder_group if s.elapsed_ms is not None]
    return baseline, attacks, ladder


def _timing_evaluate(
    ev: LiveProbeEvidence,
    injected_delay_ms: int,
) -> tuple[Verdict, VerdictReceipt]:
    """Run the statistical timing oracle over a timing-evidence batch.

    Samples N baseline and M attack latencies, computes the robust noise-floor
    sigma as ``max(classical stdev, MAD × 1.4826)``, and requires BOTH the
    initial statistical pass AND delay-ladder confirmation before corroborating.

    Returns ``(verdict, receipt)``.  The verdict is the internal
    ``TIMING_STATISTICAL_PASS`` marker when the statistical pass cleared and
    the ladder batch is absent (the workflow dispatches the ladder and
    re-evaluates); otherwise it is a final live verdict.
    """
    n = TIMING_BASELINE_SAMPLES
    m = TIMING_ATTACK_SAMPLES
    majority_required = (m + 1) // 2
    baseline, attacks, ladder = _timing_samples(ev)
    if len(baseline) < n or len(attacks) < m:
        return LIVE_INCONCLUSIVE, VerdictReceipt(
            n=len(baseline),
            m=len(attacks),
            baseline_median=0.0,
            attack_median=0.0,
            mad=0.0,
            robust_sigma=0.0,
            classical_sigma=0.0,
            threshold=0.0,
            induced_delay_ms=0.0,
            majority_count=0,
            majority_required=majority_required,
            ladder_scale_factor=None,
            reason="insufficient_timing_samples",
        )
    baseline_median = _median(baseline)
    attack_median = _median(attacks)
    induced = attack_median - baseline_median
    mad = _mad(baseline, baseline_median)
    robust_sigma = mad * _MAD_ROBUST_SCALE
    classical_sigma = float(statistics.stdev(baseline))
    sigma = max(classical_sigma, robust_sigma)
    threshold = max(_TIMING_SIGMA_MULTIPLIER * sigma, _TIMING_DELAY_FRACTION * injected_delay_ms)
    majority_cut = baseline_median + injected_delay_ms / 2
    majority_count = sum(1 for sample in attacks if sample >= majority_cut)

    def _receipt(*, ladder_scale_factor: float | None, reason: str) -> VerdictReceipt:
        return VerdictReceipt(
            n=len(baseline),
            m=len(attacks),
            baseline_median=baseline_median,
            attack_median=attack_median,
            mad=mad,
            robust_sigma=robust_sigma,
            classical_sigma=classical_sigma,
            threshold=threshold,
            induced_delay_ms=induced,
            majority_count=majority_count,
            majority_required=majority_required,
            ladder_scale_factor=ladder_scale_factor,
            reason=reason,
        )

    # Source switch (timing.go:136-158), inclusive comparators (>=).
    if induced < _TIMING_SIGMA_MULTIPLIER * sigma:
        return LIVE_NOT_CORROBORATED, _receipt(ladder_scale_factor=None, reason="below_noise_floor")
    if induced < threshold or majority_count < majority_required:
        return LIVE_INCONCLUSIVE, _receipt(ladder_scale_factor=None, reason="inconclusive")
    if len(ladder) < m:
        # Statistical pass, ladder not yet run (or budget-starved): the
        # workflow owns the ladder dispatch.  The marker is never corroborated.
        return TIMING_STATISTICAL_PASS, _receipt(
            ladder_scale_factor=None, reason="statistical_pass"
        )
    # Delay-ladder confirmation (timing.go:164-179): the induced delay must
    # SCALE with the injected delay, killing coincidental-slow-endpoint FPs.
    ladder_median = _median(ladder)
    ladder_induced = ladder_median - baseline_median
    scale = ladder_induced / induced if induced != 0 else 0.0
    scales = _TIMING_LADDER_LOW <= scale <= _TIMING_LADDER_HIGH
    clears_floor = ladder_induced >= induced + _TIMING_DELAY_FRACTION * injected_delay_ms
    if scales and clears_floor:
        return LIVE_CORROBORATED, _receipt(ladder_scale_factor=scale, reason="ladder_confirmed")
    return LIVE_INCONCLUSIVE, _receipt(ladder_scale_factor=scale, reason="ladder_failed_to_scale")


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
    """SQLi evaluator — composition dispatch over timing and differential paths.
    A single registered evaluator handles BOTH blind-SQLi and boolean SQLi so
    the registry stays one-evaluator-per-class:

    - ``injected_delay_ms`` present (delay-annotated probe) → the statistical
      timing path (:func:`_timing_evaluate`).  A statistical pass with no
      ladder batch in the evidence is NOT corroboration — the workflow owns the
      ladder dispatch, so this callable reports ``inconclusive`` for it and the
      timing-aware entry point (:func:`evaluate_live_verdict_with_receipt`)
      surfaces the marker + receipt.
    - absent → the hardened differential path (indicator → payload-echo
      normalization → token-Jaccard → exact comparison), preserving the
      boolean SQLi TRUE/FALSE pair behaviour.

    The differential path's early returns: no baseline probe → ``inconclusive``
    (the differential needs the pair); primary non-2xx → ``inconclusive``;
    either body unresolvable (None) → ``inconclusive`` (never an error).
    Divergence corroborates; identical bodies do not.
    """
    if ev.injected_delay_ms is not None:
        verdict, _receipt = _timing_evaluate(ev, ev.injected_delay_ms)
        if verdict == TIMING_STATISTICAL_PASS:
            return LIVE_INCONCLUSIVE
        return verdict
    return _differential_verdict(ev)


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

    Shares the hardened differential path with SQLi: an optional
    ``indicator`` outranks the generic heuristics, payload-echo normalization
    removes reflected injected values, and token-Jaccard similarity ≥ 0.95
    with matching status reads as equivalence.  Early returns: no baseline →
    ``inconclusive``; primary non-2xx → ``inconclusive`` (guard rejected the
    bypass, or the nested fetch errored — cannot decide); either body
    unresolvable → ``inconclusive``.

    Honest limitation: the diff is symmetric — it cannot tell WHICH probe the
    divergence favors, nor distinguish "nested fetch succeeded" from any other
    response asymmetry (e.g. a cache or rate limiter keyed on the URL).  The
    pair is CONSTRUCTED to make the primary the only one that can return
    nested-endpoint content, so in practice divergence implies the bypass
    worked; ``probe_count`` on the event payload lets a post-run audit
    re-examine.  Extra probes beyond the baseline are ignored.
    """
    return _differential_verdict(ev)


def file_upload_evaluator(ev: LiveProbeEvidence) -> Verdict:
    """File-upload upload→fetch-back CHAIN evaluator (primary + fetch-back pair).

    The dynamic-validate prompt orders the agent's proposals as the multipart
    upload first, then the fetch-back that reads the stored artifact, so the
    upload rides as the primary probe and the fetch-back as ``additional[0]``.
    Corroboration is a TWO-step observation: the handler ACCEPTED the file the
    validation should have refused (step 1) AND the stored artifact was served
    back (step 2).  One step alone is not corroboration — the point of the chain
    is that a 2xx upload that is never read back proves nothing.

    - no fetch-back probe → ``inconclusive`` (the chain needs both steps; the
      upload's 2xx alone cannot corroborate).
    - upload 4xx → ``not_corroborated`` (the handler enforced the rule the
      candidate claims is missing); any other non-2xx upload → ``inconclusive``
      (probe error / server fault — cannot decide).
    - fetch-back 4xx → ``not_corroborated`` (the stored file was not served
      back — renamed, unsanitised-but-absent, or guarded); any other non-2xx
      fetch-back → ``inconclusive``.
    - either body unresolvable (None) → ``inconclusive`` (no text to read back).
    - both steps 2xx and the fetch-back returns a non-empty body → ``corroborated``;
      a resolved-but-empty body → ``not_corroborated`` (nothing read back).

    Honest limitation: the evaluator does not know the marker the agent uploaded,
    so it corroborates on the two-step OBSERVATION (both steps 2xx + a non-empty
    read-back), not a marker equality — the same class of limitation SQLi/SSRF
    document.  Extra probes beyond the fetch-back are ignored.
    """
    if not ev.additional:
        return LIVE_INCONCLUSIVE
    fetch_back = ev.additional[0]
    if not _is_2xx(ev.status_code):
        return LIVE_NOT_CORROBORATED if 400 <= ev.status_code < 500 else LIVE_INCONCLUSIVE
    if not _is_2xx(fetch_back.status_code):
        return LIVE_NOT_CORROBORATED if 400 <= fetch_back.status_code < 500 else LIVE_INCONCLUSIVE
    if fetch_back.body_text is None:
        return LIVE_INCONCLUSIVE
    if fetch_back.body_text.strip():
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


def register_builtin_evaluators() -> None:
    """Register the shipped per-class evaluators (idempotent, import-safe).

    Called at module import so SSTI/SQL_INJECTION/SSRF candidates route
    per-class as soon as the registry is loaded; also safe to re-call (e.g.
    from tests that cleared the registry) — last registration wins, so this
    is idempotent.

    ``sql_injection_evaluator`` handles BOTH the boolean differential pair and
    the blind-SQLi timing batch internally (composition dispatch), so it stays
    registered as a single evaluator with ``min_probes=2`` and gains the
    ``timing_profile`` flag the workflow consults to dispatch N+M latency
    probes when a probe carries ``injected_delay_ms``.
    """
    register_evaluator(VulnerabilityClass.SSTI, ssti_evaluator, min_probes=1)
    register_evaluator(
        VulnerabilityClass.SQL_INJECTION,
        sql_injection_evaluator,
        min_probes=2,
        timing_profile=True,
    )
    register_evaluator(VulnerabilityClass.SSRF, ssrf_evaluator, min_probes=2)
    register_evaluator(VulnerabilityClass.COMMAND_INJECTION, timing_differential_evaluator)
    # FILE_UPLOAD corroborates through a CHAIN (upload + fetch-back), so it
    # needs the pair: ``min_probes=2`` makes dynamic dispatch keep both the
    # agent's upload and fetch-back proposals instead of silently dropping the
    # fetch-back (see ``select_dynamic_probe_specs``).
    register_evaluator(VulnerabilityClass.FILE_UPLOAD, file_upload_evaluator, min_probes=2)


register_builtin_evaluators()
