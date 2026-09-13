"""Governance: third-party attribution names Mantis (Apache-2.0) via Shannon.

cpc slice 7, task 7.3 (design D6: "attribution travels with content").
Lifted prompt content in prompts/ carries the header; the top-level
``THIRD_PARTY_NOTICES`` file and ``openspec/config.yaml``'s attribution rule
must name the upstream provenance too — Mantis security-review skills
(Apache-2.0), via Keygraph Shannon 3.0's static engine.

Written RED first.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
_NOTICES = _REPO_ROOT / "THIRD_PARTY_NOTICES.md"
_CONFIG = _REPO_ROOT / "openspec" / "config.yaml"

_EXPECTED_LICENSE = "Apache-2.0"


def test_third_party_notices_exists() -> None:
    assert _NOTICES.exists(), "THIRD_PARTY_NOTICES.md is missing at the repo root"


def test_third_party_notices_names_mantis_via_shannon() -> None:
    text = _NOTICES.read_text(encoding="utf-8")
    assert "Mantis" in text
    assert "Shannon" in text
    assert _EXPECTED_LICENSE in text


def test_config_yaml_attribution_rule_names_mantis() -> None:
    text = _CONFIG.read_text(encoding="utf-8")
    assert "Mantis" in text, (
        "openspec/config.yaml's attribution rule must name Mantis (Apache-2.0) "
        "via Shannon so future artifacts preserve the reference-design attribution"
    )


def test_lifted_prompt_headers_still_present() -> None:
    """The per-template headers added by earlier slices stay intact."""
    for name in ("calibrate/calibrate.1.0.0.j2", "recon/knowledge_base.1.0.0.j2"):
        source = (_REPO_ROOT / "prompts" / name).read_text(encoding="utf-8")
        assert "Mantis" in source, f"{name} lost its Mantis attribution header"
