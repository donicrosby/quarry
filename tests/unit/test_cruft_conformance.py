"""Spec-conformance tests for the codebase-cruft-purge change (§2.3, §2.4, §2.5, §4.1).

These are rule-guard tests: they read repository source (the repo's established
pattern for fossil rules) and pin the module surface, so a regression fails in
CI instead of surfacing as a Temporal replay hazard or a hand-counted drift.
The §2.4 worker-wiring assertion itself lives in test_server_lifespan.py, where
the hand-counted literal used to be.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json
import pkgutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    EnvProfile,
    TriageLabel,
    VulnerabilityClass,
)

SRC_ROOT = Path(__file__).resolve().parents[2] / "src"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _module_source(rel_path: str) -> str:
    return (SRC_ROOT / rel_path).read_text()


def _module_tree(rel_path: str) -> ast.Module:
    return ast.parse(_module_source(rel_path))


def _function_and_method_defs(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _contains_name(node: ast.AST, name: str) -> bool:
    """True when *node*'s source expression mentions the identifier *name*."""
    return any(
        (isinstance(sub, ast.Name) and sub.id == name)
        or (isinstance(sub, ast.Attribute) and sub.attr == name)
        for sub in ast.walk(node)
    )


def _assign_value(tree: ast.AST, name: str) -> ast.expr:
    """The RHS of a (possibly annotated) module/class-level assignment to *name*."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return node.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            if node.value is None:
                raise AssertionError(f"annotation-only assignment to {name!r}")
            return node.value
    raise AssertionError(f"no assignment to {name!r} found")


def _derives_from(
    tree: ast.AST,
    node: ast.expr,
    name: str,
    _seen: frozenset[str] = frozenset(),
) -> bool:
    """True when *node* mentions *name* directly or via a module-level alias
    assigned (directly or transitively) from an expression that does."""
    if _contains_name(node, name):
        return True
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id not in _seen:
            try:
                rhs = _assign_value(tree, sub.id)
            except AssertionError:
                continue
            if _derives_from(tree, rhs, name, _seen | {sub.id}):
                return True
    return False


def _dict_entries(node: ast.expr, key: str) -> list[ast.expr]:
    """Values bound to *key* in a dict-literal expression."""
    if isinstance(node, ast.Dict):
        return [
            value
            for k, value in zip(node.keys, node.values, strict=True)
            if isinstance(k, ast.Constant) and k.value == key
        ]
    return []


def _single(entries: list[ast.expr], what: str) -> ast.expr:
    assert len(entries) == 1, f"expected exactly one {what!r} entry, found {len(entries)}"
    return entries[0]


def _workflow_module_names() -> list[str]:
    import quarry_workflows

    return [
        "quarry_workflows",
        *(
            m.name
            for m in pkgutil.walk_packages(quarry_workflows.__path__, prefix="quarry_workflows.")
        ),
    ]


def _workflow_module_files() -> list[Path]:
    """Every file backing the quarry_workflows package (root + submodules)."""
    files: list[Path] = []
    for name in _workflow_module_names():
        module = importlib.import_module(name)
        assert module.__file__ is not None
        files.append(Path(module.__file__))
    return files


def _workflow_defn_classes() -> set[type[Any]]:
    """Every @workflow.defn-decorated class exported by quarry_workflows modules."""
    classes: set[type[Any]] = set()
    for name in _workflow_module_names():
        module = importlib.import_module(name)
        for obj in vars(module).values():
            if inspect.isclass(obj) and hasattr(obj, "__temporal_workflow_definition"):
                classes.add(obj)
    return classes


def _make_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="test-finding",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Hardcoded secret: ADMIN_API_KEY",
        hypothesis="Test finding.",
        confidence=Confidence.MEDIUM,
        created_by="test",
        created_at=datetime.now(UTC),
        metadata={"key_name": "ADMIN_API_KEY", "value_length": 28},
    )


# ---------------------------------------------------------------------------
# 2.3 — no in-function imports in workflow modules
# ---------------------------------------------------------------------------


def test_quarry_workflows_modules_have_no_in_function_imports() -> None:
    """Workflow modules must import at module top level: the Temporal sandbox
    loads modules before freezing, so in-function imports are a replay hazard
    (the repo's own import-hub rule, run_scan.py header comment)."""
    offenders: list[str] = []
    for path in _workflow_module_files():
        rel_path = path.relative_to(SRC_ROOT).as_posix()
        tree = _module_tree(rel_path)
        for fn in _function_and_method_defs(tree):
            for child in ast.walk(fn):
                if child is fn:
                    continue
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    offenders.append(f"{rel_path}:{child.lineno} (inside {fn.name})")
    assert offenders == [], (
        "quarry_workflows modules must not import inside functions "
        f"(Temporal sandbox/freeze rule); offenders: {offenders}"
    )


# ---------------------------------------------------------------------------
# 2.4 — the workflow registry is complete; the worker list derives from it
# ---------------------------------------------------------------------------


def test_discover_workflows_covers_every_defn_class() -> None:
    """§2.4: discover_workflows() yields every @workflow.defn class in the
    package (app.py wires it into the worker directly, mirroring the
    discover_activities() pattern of PR #51), so the registered workflow set
    can never silently drift from the declared workflows; the
    RunDiffScanWorkflow membership pin from the hand-counted era is kept."""
    from quarry_workflows import RunDiffScanWorkflow
    from quarry_workflows.registry import discover_workflows

    discovered = discover_workflows()
    assert RunDiffScanWorkflow in discovered
    assert set(discovered) == _workflow_defn_classes()
    # Stable, duplicate-free ordering (deterministic worker registration).
    names = [f"{w.__module__}.{w.__qualname__}" for w in discovered]
    assert names == sorted(names)
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# 2.5(a) — 'oos' triage labels go through TriageLabel
# ---------------------------------------------------------------------------


def test_run_scan_oos_triage_labels_use_triage_label_enum() -> None:
    """run_scan.py must label out-of-scope candidates with TriageLabel.OOS
    (quarry/schemas.py:114), never the raw 'oos' string literal; the
    triage_label field is TriageLabel | None so this keeps pydantic
    round-trips byte-identical."""
    assert TriageLabel.OOS.value == "oos"

    tree = _module_tree("quarry_workflows/run_scan.py")
    raw_oos = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == "oos"]
    assert raw_oos == [], (
        "raw 'oos' string literals in run_scan.py (candidate triage labeling) "
        f"must use TriageLabel.OOS instead; found at lines {[n.lineno for n in raw_oos]}"
    )

    # Pydantic round-trip stays identical through the enum-typed field.
    candidate = _make_candidate()
    labeled = candidate.model_copy(update={"triage_label": TriageLabel.OOS})
    assert labeled.model_dump(mode="json")["triage_label"] == "oos"
    reparsed = CandidateFinding.model_validate(labeled.model_dump(mode="json"))
    assert reparsed.triage_label is TriageLabel.OOS


# ---------------------------------------------------------------------------
# 2.5(b) — sandbox tool env_profile wired to EnvProfile
# ---------------------------------------------------------------------------


def test_sandbox_tool_env_profile_wired_to_env_profile_enum() -> None:
    """sandbox_tool.py must take the 'none'/'repo_readonly' wire strings from
    EnvProfile (quarry/schemas.py:1479) — the JSON wire format pinned
    byte-identical (tool-schema enum + dispatch payload default)."""
    from quarry_tools.sandbox_tool import RUN_IN_SANDBOX_TOOL

    tree = _module_tree("quarry_tools/sandbox_tool.py")

    # Source level: the tool-schema enum must be derived from EnvProfile.
    schema = _assign_value(tree, "input_schema")
    properties = _single(_dict_entries(schema, "properties"), "properties")
    env_profile = _single(_dict_entries(properties, "env_profile"), "env_profile")
    enum_node = _single(_dict_entries(env_profile, "enum"), "enum")
    assert _derives_from(tree, enum_node, "EnvProfile"), (
        "env_profile tool-schema enum is a raw string list; derive it from "
        "EnvProfile (e.g. [e.value for e in EnvProfile]) keeping the same wire values"
    )

    # Source level: the dispatch payload default must be derived from EnvProfile.
    dispatch = _assign_value(tree, "dispatch_payload")
    default_node = _single(_dict_entries(dispatch, "env_profile"), "env_profile")
    assert _derives_from(tree, default_node, "EnvProfile"), (
        "dispatch env_profile default is the raw 'none' literal; derive it from "
        "EnvProfile.NONE.value keeping the same wire value"
    )

    # Runtime level: wire format is byte-identical to the pre-change contract.
    schema_obj: dict[str, Any] = RUN_IN_SANDBOX_TOOL.input_schema
    enum_value: list[str] = schema_obj["properties"]["env_profile"]["enum"]
    assert enum_value == [e.value for e in EnvProfile]
    assert json.dumps(schema_obj).count('"enum": ["none", "repo_readonly"]') == 1

    default_out = RUN_IN_SANDBOX_TOOL.run({"command": "nmap"}, Path("."))
    assert json.loads(default_out)["env_profile"] == "none"
    assert '"env_profile": "none"' in default_out
    readonly_out = RUN_IN_SANDBOX_TOOL.run(
        {"command": "nmap", "env_profile": "repo_readonly"}, Path(".")
    )
    assert json.loads(readonly_out)["env_profile"] == "repo_readonly"
    assert '"env_profile": "repo_readonly"' in readonly_out


# ---------------------------------------------------------------------------
# 4.1 — run_fake_scan deleted from the package surface
# ---------------------------------------------------------------------------


def test_run_fake_scan_removed_from_package_surface() -> None:
    """The verified-dead legacy alias must be gone: no definition in run_scan,
    no re-export in the package __init__, no textual residue."""
    import quarry_workflows
    from quarry_workflows import run_scan

    assert not hasattr(run_scan, "run_fake_scan")
    assert not hasattr(quarry_workflows, "run_fake_scan")
    assert "run_fake_scan" not in quarry_workflows.__all__
    for rel in ("quarry_workflows/run_scan.py", "quarry_workflows/__init__.py"):
        assert "run_fake_scan" not in _module_source(rel), f"run_fake_scan residue in {rel}"
    # Positive control: the real entry point survives the alias deletion.
    # (package attribute `run_scan` is the re-exported function; the module
    # itself lives in sys.modules under the same name)
    run_scan_module = sys.modules["quarry_workflows.run_scan"]
    assert callable(run_scan_module.run_scan)
    assert hasattr(quarry_workflows, "RunScanWorkflow")
