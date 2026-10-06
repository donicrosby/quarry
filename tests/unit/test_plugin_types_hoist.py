"""Cycle-direction regression tests for the codebase-cruft-purge change (§4.7).

These are rule-guard tests: they read repository source (the repo's established
pattern for fossil rules) and pin the one-way import direction, so a regression
fails in CI instead of re-introducing the plugins↔integrations / plugins↔tools
import cycles the leaf-type hoist collapsed.

Pinned invariants:

1. ``quarry.plugin_types`` is a dependency-free leaf: importing it must not pull
   ANY ``quarry_*`` sibling package into ``sys.modules``.
2. ``quarry_plugins.base`` no longer imports ``quarry_integrations`` or
   ``quarry_tools`` (source-level AST check).
3. ``quarry_integrations.sinks`` and ``quarry_tools`` no longer import
   ``quarry_plugins.base`` for ``PluginType`` (source-level AST check).
4. Back-compat shims hold: the old import paths re-export the SAME objects as
   the leaf (identity, not structural equality — runtime_checkable Protocol
   identity is keyed on the class object).
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2] / "src"

# Sibling packages quarry.plugin_types must never import, directly or
# transitively. quarry_models is included: the leaf is quarry-core only.
_FORBIDDEN_PREFIXES = (
    "quarry_activities",
    "quarry_artifacts",
    "quarry_integrations",
    "quarry_models",
    "quarry_persistence",
    "quarry_plugins",
    "quarry_prompts",
    "quarry_tools",
    "quarry_workflows",
)


def _module_tree(rel_path: str) -> ast.Module:
    return ast.parse((SRC_ROOT / rel_path).read_text())


def _imported_modules(tree: ast.Module) -> list[tuple[str, int]]:
    """(module, lineno) for every top-level import in *tree*."""
    out: list[tuple[str, int]] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            out.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            out.append((node.module, node.lineno))
    return out


def test_plugin_types_leaf_imports_no_sibling_package() -> None:
    """§4.7: importing quarry.plugin_types must not pull any quarry_* sibling
    into sys.modules — the leaf is what collapses the plugins↔integrations /
    plugins↔tools cycles, so any transitive sibling import defeats it."""
    code = (
        "import sys\n"
        "import quarry.plugin_types\n"
        f"forbidden = {_FORBIDDEN_PREFIXES!r}\n"
        "offenders = sorted(\n"
        "    name for name in sys.modules\n"
        "    if any(name == p or name.startswith(p + '.') for p in forbidden)\n"
        ")\n"
        "print('\\n'.join(offenders), end='')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    offenders = [line for line in result.stdout.splitlines() if line]
    assert offenders == [], (
        "quarry.plugin_types must be a dependency-free leaf; importing it pulled "
        f"sibling packages into sys.modules: {offenders}"
    )


def test_plugins_base_does_not_import_integrations_or_tools() -> None:
    """§4.7: quarry_plugins.base (the former cycle apex) must not import
    quarry_integrations or quarry_tools — PluginType/FindingSink/ToolSpec now
    come from the quarry core leaf."""
    offenders = [
        f"{module} (line {lineno})"
        for module, lineno in _imported_modules(_module_tree("quarry_plugins/base.py"))
        if module == "quarry_integrations"
        or module.startswith("quarry_integrations.")
        or module == "quarry_tools"
        or module.startswith("quarry_tools.")
    ]
    assert offenders == [], (
        "quarry_plugins/base.py must not import quarry_integrations/quarry_tools "
        f"(cycle re-introduced): {offenders}"
    )


def test_sinks_and_tools_no_longer_import_plugin_type_from_plugins_base() -> None:
    """§4.7: internal consumers re-pointed to the leaf — sinks and tools must
    not import PluginType from quarry_plugins.base."""
    offenders: list[str] = []
    for rel_path in (
        "quarry_integrations/sinks/__init__.py",
        "quarry_integrations/sinks/file_sink.py",
        "quarry_integrations/sinks/jira_dry_run.py",
        "quarry_integrations/sinks/slack_dry_run.py",
        "quarry_tools/treesitter.py",
        "quarry_tools/opengrep.py",
        "quarry_tools/registry.py",
    ):
        tree = _module_tree(rel_path)
        for node in ast.iter_child_nodes(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "quarry_plugins.base"
                and any(alias.name == "PluginType" for alias in node.names)
            ):
                offenders.append(f"{rel_path}:{node.lineno}")
    assert offenders == [], (
        "internal consumers must import PluginType from quarry.plugin_types, "
        f"not quarry_plugins.base: {offenders}"
    )


def test_back_compat_shims_reexport_same_objects() -> None:
    """§4.7: the three origin modules re-export the leaf's objects by identity
    (not copies) so every pre-hoist import path keeps working."""
    from quarry.plugin_types import FindingSink, PluginType, ToolSpec
    from quarry_integrations.base import FindingSink as CompatFindingSink
    from quarry_plugins.base import PluginType as CompatPluginType
    from quarry_tools.spec import ToolSpec as CompatToolSpec

    assert PluginType is CompatPluginType
    assert FindingSink is CompatFindingSink
    assert ToolSpec is CompatToolSpec

    # Enum wire values unchanged by the move (pure-move pin).
    assert PluginType.TOOL.value == "tool"
    assert PluginType.FINDING_SINK.value == "finding_sink"
