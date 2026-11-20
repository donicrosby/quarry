"""Registry isolation guards — the pytest-shard mock-leak class.

``discover_activities()`` reads module globals across ``quarry_activities`` and
``quarry_plugins``. pytest-shard splits the suite by hash of test-FILE names, so
every PR that adds or removes a test file changes which tests share a worker
with the discovery callers. A test that leaves a ``unittest.mock`` in a walked
module's globals therefore turned an UNRELATED PR's CI red —
``TypeError: '<' not supported between instances of 'MagicMock' and 'str'``
raised from the sort inside ``discover_activities`` — only on some shard splits,
and it reran green with no code change.

Two guards retire the class. These tests pin the half that lives in production
code; the other half is the autouse ``_isolate_activity_registry`` fixture in
``tests/conftest.py``, which rolls the walked globals back after every test and
reports the leak against the test that made it.
"""

from __future__ import annotations

from unittest.mock import MagicMock, NonCallableMock

import pytest

from quarry_activities.registry import activity_name, discover_activities


def _names() -> set[str]:
    return {activity_name(fn) for fn in discover_activities()}


def test_leaked_mock_in_a_walked_module_is_skipped_not_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mock in a walked module's globals must not kill discovery.

    This reproduces the CI signature directly: the mock auto-creates an activity
    marker whose ``.name`` is itself a mock, which used to make the
    ``(module, name)`` sort raise ``TypeError`` comparing a ``str`` against a
    ``MagicMock`` — poisoning every later ``discover_activities()`` call in the
    worker, including the ones on an unrelated PR.
    """
    import quarry_activities.dedup as dedup

    clean = _names()
    monkeypatch.setattr(dedup, "not_really_an_activity", MagicMock(), raising=False)

    leaked = _names()  # must not raise

    assert leaked == clean, "a leaked mock must not add itself to the registry"
    assert all(isinstance(name, str) for name in leaked)


def test_registry_is_mock_free_and_names_are_strings() -> None:
    """Invariant: discovery yields no mock object and only ``str`` names."""
    discovered = discover_activities()

    assert discovered, "sanity: the registry is non-empty"
    assert not [fn for fn in discovered if isinstance(fn, NonCallableMock)]
    names = [activity_name(fn) for fn in discovered]
    assert all(isinstance(name, str) for name in names)
    assert len(set(names)) == len(names)
