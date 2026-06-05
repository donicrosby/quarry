"""Tests for recon_subsystem_activity provider selection via panel_json.

Written RED first — these fail until panel_json is wired into the activity.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from quarry.panel_config import RoleConfig
from quarry.schemas import Provider, SubsystemAssignment
from quarry_models.mock_client import MockModelClient


def _make_assignment() -> SubsystemAssignment:
    return SubsystemAssignment(
        name="main",
        root_paths=["."],
        languages=["python"],
        responsibility="handler",
    )


def test_recon_subsystem_uses_mock_when_panel_json_is_none(tmp_path: Path) -> None:
    """panel_json=None defaults to MockModelClient (the safe default)."""
    from quarry_activities.recon_subsystem import recon_subsystem_activity

    assignment = _make_assignment()
    result = recon_subsystem_activity(assignment, str(tmp_path), "scan-1", panel_json=None)

    assert result.name == "main"


def test_recon_subsystem_uses_mock_when_panel_json_specifies_mock(tmp_path: Path) -> None:
    """panel_json with provider='mock' still uses MockModelClient."""
    from quarry_activities.recon_subsystem import recon_subsystem_activity

    assignment = _make_assignment()
    role_config = RoleConfig(provider=Provider.MOCK, model="mock-v1")
    panel_json = role_config.model_dump_json()

    result = recon_subsystem_activity(assignment, str(tmp_path), "scan-1", panel_json=panel_json)
    assert result.name == "main"


def test_recon_subsystem_uses_litellm_when_panel_json_specifies_litellm(tmp_path: Path) -> None:
    """panel_json with provider='litellm' selects LiteLLMModelClient."""
    from quarry_activities.recon_subsystem import recon_subsystem_activity
    from quarry_models.litellm_client import LiteLLMModelClient

    assignment = _make_assignment()
    role_config = RoleConfig(provider=Provider.LITELLM, model="claude-opus-4-8")
    panel_json = role_config.model_dump_json()

    # Patch build_model_client to capture which provider was requested
    captured_providers: list[Provider] = []

    def _mock_factory(provider: Provider, **kw):  # type: ignore[override]
        captured_providers.append(provider)
        # Return a mock client so the activity doesn't need a live network call
        from pydantic import BaseModel
        from quarry_models.loop import ToolCallRequest
        from quarry_activities.recon_subsystem import _SubsystemAnalysis
        return MockModelClient(
            default=_SubsystemAnalysis(
                entry_points=[],
                responsibility=assignment.responsibility,
                notes="",
                tool_calls=[],
            )
        )

    with patch("quarry_activities.recon_subsystem.build_model_client", side_effect=_mock_factory):
        result = recon_subsystem_activity(
            assignment, str(tmp_path), "scan-1", panel_json=panel_json
        )

    assert captured_providers == [Provider.LITELLM], (
        f"Expected LiteLLM client, but factory was called with: {captured_providers}"
    )
    assert result.name == "main"
