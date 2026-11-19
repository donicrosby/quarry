"""Focus resolution for the C8/C9 CLI-side vulnerability classes.

Covers the vuln-class-focus spec scenarios for ``tempfile_race`` and
``terminal_escape``: both are focusable (``--focus <class>`` selects only them)
and both appear in the valid-class list shown when an invalid focus is rejected.
The focus machinery reads ``VulnerabilityClass`` directly (``resolve_focus``
defaults to ``list(VulnerabilityClass)``), so the two new members are picked up
with no list edits anywhere.
"""

from __future__ import annotations

import pytest

from quarry.panel_config import resolve_focus
from quarry.schemas import VulnerabilityClass


@pytest.mark.parametrize(
    "member",
    [VulnerabilityClass.TEMPFILE_RACE, VulnerabilityClass.TERMINAL_ESCAPE],
    ids=["tempfile_race", "terminal_escape"],
)
def test_cli_class_is_focusable(member: VulnerabilityClass) -> None:
    """Scenario: <class>-is-focusable."""
    assert resolve_focus(cli_focus=[member.value], config_focus=[]) == [member]


def test_new_classes_are_in_the_default_class_set() -> None:
    default = resolve_focus(cli_focus=None, config_focus=[])

    assert VulnerabilityClass.TEMPFILE_RACE in default
    assert VulnerabilityClass.TERMINAL_ESCAPE in default


@pytest.mark.parametrize("value", ["tempfile_race", "terminal_escape"])
def test_new_classes_are_listed_in_valid_classes(value: str) -> None:
    """Scenario: <class>-is-listed-in-valid-classes."""
    with pytest.raises(ValueError) as excinfo:
        resolve_focus(cli_focus=["not_a_real_class"], config_focus=[])

    assert value in str(excinfo.value)
