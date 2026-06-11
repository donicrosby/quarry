"""Tests for check_vague_reasoning() custom lexicon injection.

Verifies that:
1. Custom banned phrases/evidence can be injected via keyword params.
2. The module-level defaults still fire when no overrides are provided.
3. The QuarryConfig schema accepts [scan.reasoning_lexicon] settings.

Written RED-first: the config tests fail until ReasoningLexiconConfig and
ScanConfig are added to panel_config.py; the guard tests fail until
check_vague_reasoning accepts banned_phrases/banned_evidence kwargs.
"""

from __future__ import annotations

from quarry.schemas import ActionReasoning, ProposedAction


def _make_action(
    hypothesis: str = "Locate eval call at src/admin.py:31 for RCE via exec",
    target_ref: str = "src/admin.py:31",
    expected_evidence: str = "eval call with unsanitized user input found at src/admin.py:31",
    why: str = "grep locates the exact call site efficiently",
    kind: str = "read",
) -> ProposedAction:
    return ProposedAction(
        kind=kind,
        tool_name="grep",
        args={"pattern": "eval"},
        reasoning=ActionReasoning(
            hypothesis=hypothesis,
            target_ref=target_ref,
            expected_evidence=expected_evidence,
            why_this_tool=why,
        ),
    )


# ---------------------------------------------------------------------------
# Custom lexicon injection — the params must be wired into _check_lexicon
# ---------------------------------------------------------------------------


def test_custom_banned_phrase_is_caught() -> None:
    """A custom phrase injected via banned_phrases kwarg must trigger lexicon failure."""
    from quarry_models.guards import check_vague_reasoning

    action = _make_action(
        hypothesis="custom_marker_phrase at src/admin.py:31 for RCE via exec",
    )
    result = check_vague_reasoning(
        action,
        {"vuln_class": "rce"},
        action.args,
        banned_phrases=("custom_marker_phrase",),
    )
    assert not result.passed, "Expected custom_marker_phrase to trigger lexicon check"
    assert "lexicon" in result.failed_checks


def test_custom_banned_phrase_not_triggered_without_hit() -> None:
    """Custom banned phrase must only fire when the phrase is present."""
    from quarry_models.guards import check_vague_reasoning

    action = _make_action()  # default hypothesis — no custom phrase
    result = check_vague_reasoning(
        action,
        {"vuln_class": "rce"},
        action.args,
        banned_phrases=("custom_marker_phrase",),
    )
    assert result.passed


def test_default_banned_phrases_fire_without_overrides() -> None:
    """Default banned phrases still fire when no overrides are provided."""
    from quarry_models.guards import check_vague_reasoning

    action = _make_action(
        hypothesis="test the exploit at src/admin.py:31",  # default banned phrase
    )
    result = check_vague_reasoning(action, {"vuln_class": "rce"}, action.args)
    assert not result.passed
    assert "lexicon" in result.failed_checks


def test_custom_banned_evidence_is_caught() -> None:
    """A custom evidence phrase injected via banned_evidence kwarg must fire."""
    from quarry_models.guards import check_vague_reasoning

    action = _make_action(expected_evidence="custom_evidence_marker")
    result = check_vague_reasoning(
        action,
        {"vuln_class": "rce"},
        action.args,
        banned_evidence=("custom_evidence_marker",),
    )
    assert not result.passed
    assert "lexicon" in result.failed_checks


def test_custom_evidence_not_triggered_for_clean_action() -> None:
    """Custom evidence override must not reject clean expected_evidence."""
    from quarry_models.guards import check_vague_reasoning

    action = _make_action()  # default expected_evidence — no custom evidence phrase
    result = check_vague_reasoning(
        action,
        {"vuln_class": "rce"},
        action.args,
        banned_evidence=("custom_evidence_marker",),
    )
    assert result.passed


# ---------------------------------------------------------------------------
# Config schema: QuarryConfig must accept [scan.reasoning_lexicon]
# ---------------------------------------------------------------------------


def test_config_schema_has_reasoning_lexicon_section() -> None:
    """QuarryConfig should expose a scan.reasoning_lexicon section."""
    from quarry.panel_config import QuarryConfig, ReasoningLexiconConfig, ScanConfig

    cfg = QuarryConfig(
        scan=ScanConfig(
            reasoning_lexicon=ReasoningLexiconConfig(
                banned_phrases=["my_custom_phrase"],
                banned_evidence=["my_custom_evidence"],
            )
        )
    )
    assert cfg.scan.reasoning_lexicon is not None
    assert "my_custom_phrase" in cfg.scan.reasoning_lexicon.banned_phrases
    assert "my_custom_evidence" in cfg.scan.reasoning_lexicon.banned_evidence


def test_config_schema_lexicon_defaults_to_none() -> None:
    """A QuarryConfig with no scan section must default to None lexicon overrides."""
    from quarry.panel_config import QuarryConfig

    cfg = QuarryConfig()
    assert cfg.scan.reasoning_lexicon is None


def test_config_schema_loads_from_toml_fragment() -> None:
    """A TOML fragment with [scan.reasoning_lexicon] must parse into config."""
    import tomllib

    from quarry.panel_config import QuarryConfig

    toml_text = """
[scan.reasoning_lexicon]
banned_phrases = ["probe it", "examine this"]
banned_evidence = ["looks fine"]
"""
    raw = tomllib.loads(toml_text)
    cfg = QuarryConfig.model_validate(raw)
    assert cfg.scan.reasoning_lexicon is not None
    assert "probe it" in cfg.scan.reasoning_lexicon.banned_phrases
    assert "looks fine" in cfg.scan.reasoning_lexicon.banned_evidence
