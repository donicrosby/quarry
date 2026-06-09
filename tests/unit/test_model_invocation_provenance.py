"""Tests for ModelInvocation prompt provenance fields.

Written RED first — these fail until the new fields are added to ModelInvocation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from quarry.schemas import Provider, VulnerabilityClass, AgentTask
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec


def _make_task() -> AgentTask:
    return AgentTask(
        id="t1",
        scan_id="s1",
        role="hunt",
        task_name="hunt-command_injection",
        task_prompt="Look for exec sinks.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        status="pending",
        created_at=datetime.now(UTC),
    )


def test_model_invocation_has_prompt_template_fields() -> None:
    """ModelInvocation schema has the new template provenance fields."""
    from quarry.schemas import ModelInvocation, RedactionStatus

    inv = ModelInvocation(
        id="inv-1",
        scan_id="s1",
        workspace_id="local",
        task_name="hunt",
        role="hunt",
        provider="mock",
        model="mock-v1",
        prompt_template_id="hunt/hunt",
        prompt_template_version="1.0.0",
        template_sha256="a" * 64,
        system_prompt_hash="b" * 64,
        user_prompt_hash="c" * 64,
        evidence_hashes=[],
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=datetime.now(UTC),
    )
    assert inv.prompt_template_id == "hunt/hunt"
    assert inv.prompt_template_version == "1.0.0"
    assert inv.system_prompt_hash == "b" * 64


def test_model_invocation_new_fields_have_defaults() -> None:
    """New provenance fields default to empty strings / empty list (backward compat)."""
    from quarry.schemas import ModelInvocation, RedactionStatus

    inv = ModelInvocation(
        id="inv-2",
        scan_id="s1",
        workspace_id="local",
        task_name="hunt",
        role="hunt",
        provider="mock",
        model="mock-v1",
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=datetime.now(UTC),
    )
    assert inv.prompt_template_id == ""
    assert inv.prompt_template_version == ""
    assert inv.template_sha256 == ""
    assert inv.system_prompt_hash == ""
    assert inv.user_prompt_hash == ""
    assert inv.evidence_hashes == []
