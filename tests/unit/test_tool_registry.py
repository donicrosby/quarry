"""Tests for the quarry_tools registry loader.

The entry-points loader merges BUILTIN_REGISTRY with tools discovered
via importlib.metadata entry points. This test verifies that opengrep and
treesitter_query appear under the 'hunt' role after loading.
"""

from __future__ import annotations


def test_load_registry_contains_builtin_tools() -> None:
    from quarry_tools.registry import load_registry

    registry = load_registry()
    assert "read_file" in registry
    assert "grep" in registry
    assert "list_dir" in registry
    assert "search_code" in registry


def test_load_registry_contains_extension_tools() -> None:
    """opengrep and treesitter_query must appear after entry-point loading."""
    from quarry_tools.registry import load_registry

    registry = load_registry()
    assert "opengrep" in registry, "opengrep must be registered via entry-points"
    assert "treesitter_query" in registry, "treesitter_query must be registered via entry-points"


def test_opengrep_registered_for_hunt_role() -> None:
    from quarry_tools.registry import load_registry

    registry = load_registry()
    assert "hunt" in registry["opengrep"].roles


def test_treesitter_registered_for_hunt_role() -> None:
    from quarry_tools.registry import load_registry

    registry = load_registry()
    assert "hunt" in registry["treesitter_query"].roles
