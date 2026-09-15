# Per-Class Dynamic Validation Implementation Plan (2/4 → 4/4 promotion fix)

> **For Hermes:** Use subagent-driven-development to implement this plan task-by-task.
> Slice map at the bottom. Real-model baseline re-run at the end is USER-GATED (cost).

**Goal:** Every huntable VulnerabilityClass gets class-rigorous dynamic validation
(per-class verdict evaluators + per-class dynamic_validate templates), so a
local benchmark run with the promotion path enabled reaches 4/4 finals.

**Architecture:** A pure-function `VerdictEvaluator` registry in
`quarry_activities` replaces hardcoded `live_verdict_from_status` calls.
Workflow code stays I/O-free: activities resolve body artifacts to text,
evaluators consume resolved text. Prompt templates close the per-class gap in
`prompts/dynamic_validate/` and `prompts/hunt/`.

**Tech Stack:** Python 3.12, pydantic v2, Temporal activities, Jinja2 templates,
pytest strict TDD, ruff + pyright clean, conventional commits.

---

## Ground truth from recon (2026-09-13, supersedes stale tasks.md assumptions)

- **Verdict vocabulary:** `corroborated / not_corroborated / inconclusive`
  (constants `LIVE_*` in `src/quarry_workflows/run_scan.py:2913-2915`).
- **Current evaluator:** `live_verdict_from_status(status_code)` at
  `run_scan.py:2916` — 2xx→corroborated, 401/403/404→not_corroborated, else
  inconclusive. Called at TWO sites: `run_scan.py:1654` (workflow dispatch loop)
  and `src/quarry_workflows/dynamic_validate_stage.py:63`
  (`resolve_live_verdict`, pure helper, also re-exports the LIVE_* constants).
- **`HttpResponseCapture`** (`src/quarry/schemas.py:1506`): `status_code`,
  `headers`, `body_artifact_ref` (artifact id — body NOT inline),
  `elapsed_ms`, `request_artifact_ref`. Evaluators that need body content
  (SSTI marker, SQLi diff) must receive body TEXT resolved by the caller.
- **Dispatch:** `select_dynamic_probe_spec()` (run_scan.py:2877) picks the FIRST
  well-formed agent-proposed spec from `proposed_http_specs: list`, falls back
  to `build_dynamic_probe_spec` (`_CLASS_PROBE_PATHS` covers only
  idor/command_injection/ssrf/xss). Workflow then dispatches ONE
  `http-request` activity (RetryPolicy maximum_attempts=1). A `corroborated`
  verdict → `promote_with_dynamic_evidence()` → FinalFinding persisted +
  `finding.dynamic_validated` event; otherwise candidate stays NEEDS_PROOF
  annotated with the verdict.
- **Template selection:** `src/quarry_activities/dynamic_validate.py:117-131`
  already prefers `prompts/dynamic_validate/<vuln_class>.1.0.0.j2`, falls back
  to generic `dynamic_validate.1.0.0.j2`.
- **Existing dynamic_validate templates:** command_injection, dynamic_validate
  (generic), idor, ssrf. Missing (8): sql_injection, xss, ssti, xxe,
  file_upload, auth, open_redirect, csrf.
- **Existing hunt templates:** 18 files. tasks.md 3.1 says "xxe, file_upload,
  csrf" — **xxe.1.0.0.j2 ALREADY EXISTS**. Actually missing: **csrf,
  file_upload** only.
- **VulnerabilityClass enum** (`src/quarry/schemas.py:92-111`): 19 members
  (secrets … weak_crypto).
- **Golden tests:** `tests/unit/test_prompting.py` (4 tests, one golden fixture
  `expected_sanitized_prompt.txt`) — template ADDITIONS don't touch it, but run
  it anyway. Also sweep for any file-manifest golden enumerating `prompts/`
  (e.g. test_prompt_registry / manifest snapshot) — if one exists, its golden
  fixture must be regenerated deliberately, not blundered into.
- **Repo rules:** `from __future__ import annotations` everywhere; NO
  `# pyright: ignore` / `# type: ignore`; ruff E501 line length 100; strict
  TDD (red first); conventional commits; `uv sync --group dev` (NOT `--extra`).
- **Temporal sandbox rule:** workflow code must stay pure — artifact reads and
  HTTP happen in activities only.

---

## Slice A — VerdictEvaluator registry + default evaluator + wiring (tasks 1.1, 1.2, 1.5)

### Task A1: Registry protocol + registration/lookup tests (RED)

**Files:** Create `tests/unit/test_verdict_evaluators.py`

```python
from quarry.schemas import VulnerabilityClass
from quarry_activities.verdict_evaluators import (
    LiveProbeEvidence, evaluate_live_verdict, register_evaluator, resolve_evaluator,
)

def test_register_and_resolve_per_class():
    def fake(ev: LiveProbeEvidence) -> str:
        return "not_corroborated"
    register_evaluator(VulnerabilityClass.SSTI, fake)
    assert resolve_evaluator(VulnerabilityClass.SSTI) is fake

def test_unregistered_class_falls_back_to_default_status_evaluator():
    default = resolve_evaluator(VulnerabilityClass.LDAP_INJECTION)
    ev = LiveProbeEvidence(status_code=403)
    assert default(ev) == "not_corroborated"  # 403 in defended set
```

Run: `uv run pytest tests/unit/test_verdict_evaluators.py -q` → FAIL (module missing).

### Task A2: Implement registry + `LiveProbeEvidence` (GREEN)

**Files:** Create `src/quarry_activities/verdict_evaluators.py`

```python
"""Per-class pure verdict evaluators (ADR-017 code-evaluated rule)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from quarry.schemas import VulnerabilityClass
from quarry_workflows.run_scan import (
    LIVE_CORROBORATED, LIVE_INCONCLUSIVE, LIVE_NOT_CORROBORATED,
    live_verdict_from_status,
)

Verdict = str
Evaluator = Callable[["LiveProbeEvidence"], Verdict]

@dataclass(frozen=True)
class LiveProbeEvidence:
    """Resolved live-probe inputs for a single candidate.

    Bodies are resolved TEXT (activities read artifacts); never raw refs.
    Primary probe first; optional baseline/differential probes follow.
    """
    status_code: int
    body_text: str | None = None
    additional: tuple["LiveProbeEvidence", ...] = field(default=())

_REGISTRY: dict[VulnerabilityClass, Evaluator] = {}

def register_evaluator(cls: VulnerabilityClass, fn: Evaluator) -> None: ...
def resolve_evaluator(cls: VulnerabilityClass) -> Evaluator:
    return _REGISTRY.get(cls, _default_evaluator)

def _default_evaluator(ev: LiveProbeEvidence) -> Verdict:
    return live_verdict_from_status(ev.status_code)

def evaluate_live_verdict(cls: VulnerabilityClass, ev: LiveProbeEvidence) -> Verdict:
    return resolve_evaluator(cls)(ev)
```

Import-cycle note: `dynamic_validate_stage.py` already imports from
`run_scan`, so `quarry_activities.verdict_evaluators` importing
`quarry_workflows.run_scan` matches the existing dependency direction.
Re-export LIVE_* from here too if convenient.

### Task A3: Wiring — replace both hardcoded call sites (RED→GREEN)

**Files:** Modify `src/quarry_workflows/run_scan.py:1654` block and
`src/quarry_workflows/dynamic_validate_stage.py:63`.

- Write failing test first: dynamic_validate stage test asserting an
  SSTI-registered evaluator is consulted for an SSTI candidate (monkeypatch a
  sentinel evaluator into the registry, assert its verdict is returned).
- Workflow-side wiring (`run_scan.py`): after `capture` is validated, resolve
  body text via a NEW tiny activity `read-artifact-text` (artifact_root +
  `body_artifact_ref` → `str | None`, size-capped, missing artifact → None),
  build `LiveProbeEvidence`, call `evaluate_live_verdict(retained.vuln_class, ev)`.
  Keep the existing promote-on-corroborated flow unchanged otherwise.
- `dynamic_validate_stage.resolve_live_verdict` gains an optional
  `evidence: LiveProbeEvidence | None = None` param: when provided, route
  through the registry; when absent, keep current status-only behavior
  (existing tests must stay green untouched).
- Event enrichment: include `verdict_source: "per_class"|"default"` in the
  `finding.dynamic_validated` / annotation event payload.

### Task A4: Slice A gate

`uv run ruff check . && uv run ruff format --check . && uv run pyright &&
uv run pytest -q` → green. Commit `feat: verdict evaluator registry + wiring`.

---

## Slice B — SSTI + SQLi evaluators + multi-probe dispatch (tasks 1.3, 1.4)

### Task B1: SSTI marker evaluator (RED→GREEN)

`{{7*7}}` probe → body contains `49` ⇒ corroborated. Pure fn:

```python
def ssti_evaluator(ev: LiveProbeEvidence) -> Verdict:
    if ev.status_code < 200 or ev.status_code >= 300:
        return LIVE_INCONCLUSIVE
    return LIVE_CORROBORATED if ev.body_text and "49" in ev.body_text else LIVE_NOT_CORROBORATED
```

Tests: 200+"49"→corroborated; 200 w/o marker→not_corroborated; 500→inconclusive;
`body_text=None`→not_corroborated (never corroborate on missing evidence).
Register under `VulnerabilityClass.SSTI`.

### Task B2: SQLi boolean-diff evaluator (RED→GREEN)

True/false probe pair via `ev.additional[0]` (baseline):

```python
def sql_injection_evaluator(ev: LiveProbeEvidence) -> Verdict:
    if not ev.additional:
        return LIVE_INCONCLUSIVE  # differential needs the pair
    base = ev.additional[0]
    if ev.status_code < 200 or ev.status_code >= 300:
        return LIVE_INCONCLUSIVE
    if ev.body_text is None or base.body_text is None:
        return LIVE_INCONCLUSIVE
    diverge = ev.body_text != base.body_text
    return LIVE_CORROBORATED if diverge else LIVE_NOT_CORROBORATED
```

Tests: diverging 200-pair→corroborated; identical bodies→not_corroborated;
single probe→inconclusive; non-2xx primary→inconclusive.
Register under `VulnerabilityClass.SQL_INJECTION`.

### Task B3: Two-probe dispatch support (RED→GREEN)

**Files:** Modify `run_scan.py` select/dispatch block.

- `select_dynamic_probe_spec` gains a sibling `select_dynamic_probe_specs`
  returning up to TWO well-formed proposals (SQLi true/false pair); keep the
  single-spec function delegating to it (old callers untouched).
- Workflow: when class == SQL_INJECTION (evaluator declares `needs_pair =
  True` via registry metadata — a `EvaluatorSpec` dataclass carrying `fn` +
  `min_probes: int = 1`), dispatch primary + baseline probes (each single
  attempt), resolve both bodies, build nested `LiveProbeEvidence`.
- Cost guard: second probe only when `val_budget_remaining` still positive.

Commit `feat: ssti + sqli verdict evaluators, differential probe dispatch`.

---

## Slice C — dynamic_validate templates ×8 (tasks 2.1–2.3)

### Task C1: Render tests (RED)

**Files:** Create `tests/unit/test_dynamic_validate_templates.py`.

For each of sql_injection, xss, ssti, xxe, file_upload, auth, open_redirect,
csrf: template `prompts/dynamic_validate/<slug>.1.0.0.j2` exists, renders with
the standard context (reuse the harness pattern from existing idor/ssrf
template tests — find them via
`grep -rn "dynamic_validate" tests/unit/`), and the rendered text contains a
class-specific verdict instruction (e.g. "SQLi" differential guidance for
sql_injection; "49" marker mention for ssti).

### Task C2: Author templates (GREEN)

Copy the structure of `prompts/dynamic_validate/idor.1.0.0.j2` (same context
vars, same output contract — proposed_http_specs JSON schema). Class-specific
sections only; do not invent new context variables. Version `1.0.0`.

### Task C3: Registry completeness test (task 2.3)

Every `VulnerabilityClass` member resolves to either
`prompts/dynamic_validate/<slug>.1.0.0.j2` or the generic
`dynamic_validate.1.0.0.j2` — parametrized over all 19 enum members.

Commit `feat: per-class dynamic_validate prompt templates`.

---

## Slice D — missing hunt templates (task 3.1/3.2, corrected: csrf + file_upload)

**Files:** Create `prompts/hunt/csrf.1.0.0.j2`,
`prompts/hunt/file_upload.1.0.0.j2`, extend the hunt template test module
(find via `grep -rln "prompts/hunt" tests/unit/`).

RED: render test per template (renders with standard hunt context, mentions
class-specific sinks/sources — CSRF: token-validation bypass, state-changing
endpoints; file_upload: multipart handling, extension/content-type checks).
GREEN: author, modeled on `prompts/hunt/xss.1.0.0.j2`.

Commit `feat: csrf + file_upload hunt templates`.

---

## Landing gate (task 4.1, 4.2) — orchestrator, not subagent

1. Full suite + lint + types green on the integration branch
   (`uv run pytest -q -n 4`; golden `test_benchmark.py` + `test_prompting.py`
   explicitly called out in the PR body).
2. AGENTS.md: update test counts, add/adjust rows if package layout changed
   (no new package here — only new module in quarry_activities).
3. `openspec validate per-class-dynamic-validation --strict`; tick tasks.md in
   the landing commit (correcting 3.1/3.2 wording to the real gap:
   csrf + file_upload, noting xxe pre-existed).
4. Push, PR, CI, merge (user's word), `openspec archive` if last slice.
5. **Baseline re-run (USER-GATED — real model spend):** full promotion-path
   local benchmark:
   - `quarry target start examples/vulnerable-fastapi --port 8001`
     (NOT 8000 — collides with quarry API server)
   - `quarry benchmark local --target http://127.0.0.1:8001
     --dynamic-validation --live-prove` with cost cap
   - Verify from `.quarry/quarry.db`: `final_findings` by class == 4/4,
     `workflow_events` show per-class verdicts. Report detection vs promotion
     separately. This closes the 2/4 → 4/4 loop.

---

## Slice → subagent map (sequential where stacked, parallel where independent)

| Slice | Depends on | Worktree branch |
|---|---|---|
| A registry+wiring | — | `pcdv/registry` from origin/main |
| B evaluators+dispatch | A (registry API) | `pcdv/evaluators` from A's merged HEAD |
| C dyn_validate templates | — (independent of A) | `pcdv/dyn-templates` from origin/main |
| D hunt templates | — (independent) | `pcdv/hunt-templates` from origin/main |
| Landing+baseline | A+B+C+D merged | orchestrator |

Dispatch A, C, D in parallel once PR #45 is merged (branch from fresh
origin/main; avoids AGENTS.md/tasks.md churn while #45 sits open). B follows
A's merge. Each subagent gets: this plan's slice section, repo rules block,
`git -c credential.helper='!gh auth git-credential'` push incantation,
own worktree, "done = tests green + pushed + PR open + summary with PR URL".

## Risks / open questions

- **`read-artifact-text` activity** is new workflow surface: keep it trivial
  (read, cap at N KB, return None on any failure), single retry, and unit-test
  the None-on-missing path — the evaluator contract treats missing body as
  non-corroboration, never error.
- **Body-size cap:** SQLi diff on huge bodies — cap resolved text (e.g. 64 KB)
  in the activity, note in evaluator docstring.
- **Second probe spend:** gated on remaining budget; event payload should
  record `probe_count` so post-run audit can see differential dispatches.
- **Secrets class:** stays evaluator-less (default status evaluator; HTTP
  probe returns None from `build_dynamic_probe_spec`) — secrets promotion
  remains the deterministic gate. If 4/4 still shows secrets stuck after this
  slate, the gap is the `key_name` metadata path — separate ticket, do not
  bolt it on here.
- **Merge ordering with #45:** if #45 merges first, rebase slices; conflict
  surface is AGENTS.md only.
