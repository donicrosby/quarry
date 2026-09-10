"""Tests for CLI invocation metadata on EntryPoint (ADR-024 §C.2).

The prove agent must not guess how to invoke a CLI target. EntryPoint carries
``invocation`` (command + argv template) and ``attacker_controlled_input`` so
the prove stage can run the binary. Ground-truth fixtures express
``cli_invocation``; these fields are its pipeline-schema home.
"""

from __future__ import annotations

from typing import Literal

import pydantic
import pytest

from quarry.schemas import EntryPoint

ACI = Literal["args", "stdin", "env", "config_file", "none"]


def _entrypoint(invocation: list[str] | None = None, aci: ACI = "none") -> EntryPoint:
    return EntryPoint(
        repo=".",
        file="src/main.rs",
        function="main",
        kind="cli_arg",
        invocation=invocation or [],
        attacker_controlled_input=aci,
    )


def test_invocation_and_attacker_controlled_input_present() -> None:
    ep = _entrypoint(invocation=["./target/release/vulnerable-cli"], aci="args")
    assert ep.invocation == ["./target/release/vulnerable-cli"]
    assert ep.attacker_controlled_input == "args"


@pytest.mark.parametrize("val", ["args", "stdin", "env", "config_file", "none"])
def test_attacker_controlled_input_enum_values(val: ACI) -> None:
    ep = _entrypoint(invocation=["./bin"], aci=val)
    assert ep.attacker_controlled_input == val


def test_attacker_controlled_input_rejects_invalid() -> None:
    with pytest.raises(pydantic.ValidationError):
        EntryPoint(
            repo=".",
            file="src/main.rs",
            function="main",
            kind="cli_arg",
            invocation=["./bin"],
            attacker_controlled_input="network",  # type: ignore[arg-type]
        )


def test_fields_default_for_backward_compat() -> None:
    """Existing EntryPoints (no invocation metadata) must still validate."""
    ep = EntryPoint(repo=".", file="app.py", function="main", kind="main")
    assert ep.invocation == []
    assert ep.attacker_controlled_input == "none"


def test_invocation_round_trips_through_serialization() -> None:
    ep = _entrypoint(invocation=["./target/release/vulnerable-cli", "--run-cmd"], aci="args")
    ep2 = EntryPoint.model_validate(ep.model_dump())
    assert ep2.invocation == ep.invocation
    assert ep2.attacker_controlled_input == ep.attacker_controlled_input
    # JSON round-trip too (Temporal payloads)
    ep3 = EntryPoint.model_validate_json(ep.model_dump_json())
    assert ep3.invocation == ep.invocation


def test_vulnerable_cli_acceptance() -> None:
    """Acceptance: vulnerable-cli recon shape (invocation + args input)."""
    ep = _entrypoint(invocation=["./target/release/vulnerable-cli"], aci="args")
    assert ep.invocation == ["./target/release/vulnerable-cli"]
    assert ep.attacker_controlled_input == "args"
