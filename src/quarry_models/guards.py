"""Guard functions run after every model turn in the agent loop.

Guards inspect model output for safety violations. Each function returns
``True`` if the guard fires (problem detected) and ``False`` if clear.
"""

from __future__ import annotations

import re as _re
from typing import Any

from pydantic import BaseModel

from quarry.schemas import ProposedAction, ReasoningCheckResult
from quarry_models.redaction import scrub

_REDACTED_MARKER = _re.compile(r"\[REDACTED_SECRET_\d+\]")

# ---------------------------------------------------------------------------
# Existing guards
# ---------------------------------------------------------------------------


def check_leaked_secret(text: str) -> bool:
    """Return True if *text* appears to contain an unredacted secret.

    Compares the scrubbed version of *text* with the original; if the
    scrubber made changes (hits > 0), the original text contained a secret.
    Redacted markers (``[REDACTED_SECRET_N]``) from a prior scrub pass do
    not count as a new leak — they are stripped before the check.
    """
    stripped = _REDACTED_MARKER.sub("", text)
    result = scrub(stripped)
    return result.hits > 0


def check_schema_mismatch(response: object, expected_type: type[BaseModel]) -> bool:
    """Return True if *response* is not an instance of *expected_type*.

    Subclasses of *expected_type* are accepted (``isinstance`` check).
    """
    return not isinstance(response, expected_type)


def check_unauthorized_action(actions: list[str], allowed_kinds: list[str]) -> bool:
    """Return True if any action in *actions* is not in *allowed_kinds*."""
    return any(action not in allowed_kinds for action in actions)


# ---------------------------------------------------------------------------
# ADR-020: Deterministic vagueness guard
# ---------------------------------------------------------------------------

# ── Action-kind tiers ───────────────────────────────────────────────────────
# All four checks apply to high-risk and proof/exploit kinds.
# Read-only kinds skip args_coherence (presence + context_reference + lexicon only).
_READ_ONLY_KINDS: frozenset[str] = frozenset(
    {
        "read_file",
        "read",
        "list_dir",
        "grep",
        "search_code",
        "treesitter_query",
        "cite",
        "summarize",
        "hypothesize",
        "request_check",
        "safe_proof",
        "deliver_finalized",
    }
)
_HIGH_RISK_KINDS: frozenset[str] = frozenset({"http_request", "opengrep", "codeql_query"})
_PROOF_KINDS: frozenset[str] = frozenset({"dynamic_validate", "prove"})

# ── Defaults (overridden by [scan.reasoning_lexicon] in quarry.toml) ────────
# NOTE: these are reviewed explicitly — a wrong rule silently rejects valid actions.
# Keep the list short and target only fully-generic, zero-content phrases.
_DEFAULT_BANNED_PHRASES: tuple[str, ...] = (
    "test the exploit",
    "check the endpoint",
    "see what happens",
    "verify the vulnerability",
    "probe it",
    "investigate",
)
_DEFAULT_BANNED_EVIDENCE: tuple[str, ...] = (
    "it works",
    "confirmed",
    "vulnerable",
    "success",
)

# Minimum token count per ActionReasoning field (default 4).
_MIN_TOKEN_LENGTH: int = 4

# ── Concrete-locator pattern ─────────────────────────────────────────────────
# Matches URL paths (/path, /path?param=), file:line refs (file.py:42),
# explicit param mentions (`param`=), and named function refs (module.function).
_LOCATOR_RE = _re.compile(
    r"(?:"
    r"/[a-zA-Z0-9_\-/.?=&%]+"  # URL path: /search?q= or /admin/users
    r"|[a-zA-Z0-9_/\-.]+\.[a-zA-Z]{1,6}:\d+"  # file:line: src/auth.py:42
    r"|`[a-zA-Z0-9_\-]+`"  # backtick-quoted param name: `q`
    r"|(?<![a-zA-Z])[a-zA-Z0-9_]+\?[a-zA-Z0-9_&=]+"  # raw query: id?user=
    r"|[a-zA-Z0-9_/\-.]+\.[a-zA-Z]{1,6}"  # simple file path: src/auth.py
    r")"
)

# ── vuln_class synonym map ──────────────────────────────────────────────────
# Maps vuln_class value (or prefix) → accepted synonym words.
# Keep permissive: short synonyms are fine; we just need ONE to appear.
_VULN_SYNONYMS: dict[str, tuple[str, ...]] = {
    "xss": ("xss", "cross-site", "cross_site", "reflected", "stored", "script"),
    "command_injection": ("command_injection", "command injection", "exec", "shell", "subprocess"),
    "sql_injection": ("sql_injection", "sql injection", "sqli", "sql", "query"),
    "idor": ("idor", "insecure direct", "direct object", "object reference", "access control"),
    "ssrf": ("ssrf", "server-side request", "server side request", "request forgery"),
    "path_traversal": ("path_traversal", "path traversal", "directory traversal", "lfi", "../"),
    "secrets": ("secrets", "secret", "credential", "token", "api key", "password"),
    "open_redirect": ("open_redirect", "open redirect", "redirect"),
    "rce": ("rce", "remote code execution", "code execution", "eval", "exec"),
    "xxe": ("xxe", "xml external", "entity injection"),
}


def _token_count(text: str) -> int:
    """Count whitespace-separated tokens in *text*."""
    return len(text.split())


def _contains_locator(text: str) -> bool:
    """Return True if *text* contains a concrete locator (URL path, file:line, param)."""
    return bool(_LOCATOR_RE.search(text))


def _contains_vuln_synonym(text: str, vuln_class: str) -> bool:
    """Return True if *text* mentions the vuln_class or a recognised synonym."""
    text_lower = text.lower()
    # Direct substring match (handles "xss", "command_injection", etc.)
    if vuln_class.lower() in text_lower:
        return True
    # Synonym lookup by prefix or exact key
    for key, synonyms in _VULN_SYNONYMS.items():
        if key in vuln_class.lower() or vuln_class.lower() in key:
            for syn in synonyms:
                if syn in text_lower:
                    return True
    return False


def _check_presence(reasoning: Any) -> list[str]:
    """Sub-check: every ActionReasoning field must be non-empty and above a minimum.

    Prose fields (hypothesis, expected_evidence, why_this_tool) require ≥ min tokens.
    target_ref is a locator (URL path, file:line, param name) and only requires non-empty.
    """
    failures: list[str] = []
    # Prose fields require ≥ _MIN_TOKEN_LENGTH tokens
    for field_name in ("hypothesis", "expected_evidence", "why_this_tool"):
        val = getattr(reasoning, field_name, "") or ""
        if not val.strip() or _token_count(val) < _MIN_TOKEN_LENGTH:
            failures.append(
                f"field '{field_name}' is empty or too short "
                f"(min {_MIN_TOKEN_LENGTH} tokens, got {_token_count(val)})"
            )
    # target_ref is a locator (not prose) — only requires non-empty
    target_ref = (reasoning.target_ref or "").strip()
    if not target_ref:
        failures.append("field 'target_ref' is empty — add a URL path, file:line, or param name")
    return failures


def _check_context_reference(reasoning: Any, vuln_class: str) -> list[str]:
    """Sub-check: hypothesis or target_ref must name the vuln_class AND a concrete locator."""
    failures: list[str] = []
    combined = f"{reasoning.hypothesis} {reasoning.target_ref}"
    has_vuln = _contains_vuln_synonym(combined, vuln_class)
    has_locator = _contains_locator(reasoning.target_ref) or _contains_locator(reasoning.hypothesis)
    if not has_vuln:
        failures.append(
            f"hypothesis/target_ref does not name the vulnerability class '{vuln_class}' "
            "or a recognised synonym"
        )
    if not has_locator:
        failures.append(
            "target_ref contains no concrete locator — add a URL path (/path?param=), "
            "file:line ref (file.py:42), or backtick-quoted param name (`q`)"
        )
    return failures


def _check_lexicon(reasoning: Any) -> list[str]:
    """Sub-check: reject reasoning dominated by banned generic phrases."""
    failures: list[str] = []
    hyp_lower = reasoning.hypothesis.lower()
    why_lower = reasoning.why_this_tool.lower()
    ev_lower = reasoning.expected_evidence.lower()

    for phrase in _DEFAULT_BANNED_PHRASES:
        if phrase in hyp_lower or phrase in why_lower:
            failures.append(f"banned generic phrase '{phrase}' in reasoning")
            break

    for phrase in _DEFAULT_BANNED_EVIDENCE:
        if (
            ev_lower.strip() == phrase
            or ev_lower.startswith(phrase + " ")
            or ev_lower.endswith(" " + phrase)
        ):
            failures.append(f"expected_evidence uses banned blank claim '{phrase}'")
            break

    return failures


def _check_args_coherence(action: ProposedAction, vuln_class: str) -> list[str]:
    """Sub-check: target_ref must be consistent with actual args.

    Rules (explicit, reviewed):
    - http_request: if args has 'path', target_ref must share a path component with it.
    - read_file: if args has 'path', target_ref must reference the same file base name.
    - dynamic_validate / prove: args payload must contain a token appropriate to vuln_class.

    These rules are intentionally narrow to minimise false positives (wrong rules
    silently reject valid actions). Extend only after observing actual misbehaviour.
    """
    failures: list[str] = []
    kind = action.kind.lower()
    args = action.args or {}
    target_ref_lower = action.reasoning.target_ref.lower()

    if kind == "http_request":
        path = str(args.get("path", args.get("url", "")))
        if path:
            # Extract first path component from target_ref and check it appears in args path
            path_match = _re.search(r"/([a-zA-Z0-9_\-]+)", target_ref_lower)
            args_path_lower = path.lower()
            if path_match and path_match.group(1) not in args_path_lower:
                failures.append(
                    f"target_ref mentions path '/{path_match.group(1)}' but args path is '{path}'"
                )

    elif kind == "read_file":
        file_path = str(args.get("path", ""))
        if file_path:
            # Extract file basename from target_ref and check it appears in args path
            ref_match = _re.search(r"([a-zA-Z0-9_\-]+\.[a-zA-Z]{1,6})", target_ref_lower)
            if ref_match and ref_match.group(1) not in file_path.lower():
                failures.append(
                    f"target_ref mentions file '{ref_match.group(1)}' "
                    f"but args path is '{file_path}'"
                )

    return failures


def check_vague_reasoning(
    action: ProposedAction,
    task_context: dict[str, Any],
    args: dict[str, Any],
) -> ReasoningCheckResult:
    """Deterministic vagueness guard for a ProposedAction's ActionReasoning.

    Runs four sub-checks (presence, context_reference, lexicon, args_coherence)
    with graduated strictness:
    - Read-only kinds (read_file, grep, …): presence + context_reference + lexicon
    - High-risk kinds (http_request, …): all four
    - Proof/exploit kinds (dynamic_validate, prove): all four

    Checks are **permissive** — false positives kill hunt iterations.
    Reject only clearly-vague reasoning.

    Returns:
        ReasoningCheckResult with passed=True if all applicable checks pass,
        or passed=False with failed_checks populated and detail for re-prompt.
    """
    reasoning = action.reasoning
    vuln_class = str(task_context.get("vuln_class", ""))
    kind_lower = action.kind.lower()

    failed: list[str] = []
    detail_parts: list[str] = []

    # ── Sub-check 1: presence ───────────────────────────────────────────────
    presence_failures = _check_presence(reasoning)
    if presence_failures:
        failed.append("presence")
        detail_parts.extend(presence_failures)

    # ── Sub-check 2: context_reference ─────────────────────────────────────
    context_failures = _check_context_reference(reasoning, vuln_class)
    if context_failures:
        failed.append("context_reference")
        detail_parts.extend(context_failures)

    # ── Sub-check 3: lexicon ────────────────────────────────────────────────
    lexicon_failures = _check_lexicon(reasoning)
    if lexicon_failures:
        failed.append("lexicon")
        detail_parts.extend(lexicon_failures)

    # ── Sub-check 4: args_coherence (high-risk + proof/exploit only) ────────
    if kind_lower in _HIGH_RISK_KINDS or kind_lower in _PROOF_KINDS:
        coherence_failures = _check_args_coherence(action, vuln_class)
        if coherence_failures:
            failed.append("args_coherence")
            detail_parts.extend(coherence_failures)

    passed = len(failed) == 0
    detail = "; ".join(detail_parts) if detail_parts else ""

    return ReasoningCheckResult(passed=passed, failed_checks=failed, detail=detail)
