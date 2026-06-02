"""Command-injection candidate scanner plugin.

Detects route handlers that pass request-controlled values into a shell sink
(``subprocess.*`` with ``shell=True``, or ``os.system``/``os.popen``). Static
analysis only: parses source with ``ast`` and never performs HTTP requests. The
candidate records the route and the request parameter that flows into the sink so
the dynamic prover knows what to probe.
"""

from __future__ import annotations

import ast
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from temporalio import activity
from temporalio.exceptions import CancelledError as TemporalCancelledError

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.schemas import (
    AttackSurfaceItem,
    CandidateFinding,
    Confidence,
    Severity,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.inputs import CommandInjectionScanInput

SUBPROCESS_SINKS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
OS_SHELL_SINKS = frozenset({"system", "popen"})
SHELL_SINK_EVIDENCE_KIND = "shell_subprocess_sink"


@dataclass(frozen=True)
class CmdiMatch:
    line_number: int
    route: str
    param: str
    sink: str
    handler_file: str
    handler_symbol: str | None


@activity.defn(name="scan-attack-surface-for-command-injection")
def scan_attack_surface_for_command_injection(
    input: CommandInjectionScanInput | dict[str, object],
) -> list[CandidateFinding]:
    if isinstance(input, dict):
        input = CommandInjectionScanInput(**cast(dict[str, Any], input))
    return _scan_impl(input)


def _scan_impl(input: CommandInjectionScanInput) -> list[CandidateFinding]:
    repo_root = Path(input.repo_root)
    findings: list[CandidateFinding] = []
    for i, item in enumerate(input.attack_surface_items):
        if i % 10 == 0:
            _heartbeat(f"Scanned {i}/{len(input.attack_surface_items)} routes")
        if _activity_cancel_requested():
            raise TemporalCancelledError("Command-injection scan cancelled")

        handler_path = repo_root / item.handler_file
        if not handler_path.is_file():
            continue
        handler_source = handler_path.read_text(encoding="utf-8", errors="replace")
        for match in scan_handler_for_command_injection(item, handler_source):
            findings.append(
                command_injection_match_to_candidate_finding(
                    match,
                    scan_id=input.scan_id,
                    workspace_id=input.workspace_id,
                )
            )
    return findings


def scan_handler_for_command_injection(
    attack_surface_item: AttackSurfaceItem,
    handler_source: str,
) -> list[CmdiMatch]:
    handler_node = _find_handler_node(handler_source, attack_surface_item)
    if handler_node is None:
        return []

    params = _handler_param_names(handler_node)
    if not params:
        return []

    matches: list[CmdiMatch] = []
    seen: set[tuple[str, str]] = set()
    for call in _iter_calls(handler_node):
        sink = _shell_sink_name(call)
        if sink is None or not call.args:
            continue
        tainted = _first_param_in_expr(call.args[0], params)
        if tainted is None:
            continue
        if (sink, tainted) in seen:
            continue
        seen.add((sink, tainted))
        matches.append(
            CmdiMatch(
                line_number=call.lineno,
                route=attack_surface_item.route,
                param=tainted,
                sink=sink,
                handler_file=attack_surface_item.handler_file,
                handler_symbol=attack_surface_item.handler_symbol,
            )
        )
    return matches


def command_injection_match_to_candidate_finding(
    match: CmdiMatch,
    *,
    scan_id: str,
    workspace_id: str = "local",
    created_by: str = "command-injection-scanner",
    created_at: datetime | None = None,
) -> CandidateFinding:
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        file_path=match.handler_file,
        start_line=match.line_number,
        key_name=match.param,
        evidence_kind=SHELL_SINK_EVIDENCE_KIND,
    )
    root_cause_key = compute_root_cause_key(
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        file_path=match.handler_file,
        sink=f"{match.sink}:{match.param}",
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id=workspace_id,
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title=f"Potential command injection via {match.param}",
        hypothesis=(
            f"Route {match.route} in {match.handler_file}:{match.line_number} passes "
            f"request parameter '{match.param}' into shell sink {match.sink}(...)."
        ),
        root_cause_key=root_cause_key,
        affected_component=match.handler_file,
        severity=Severity.CRITICAL,
        source_refs=[
            SourceRef(
                file_path=match.handler_file,
                start_line=match.line_number,
                end_line=match.line_number,
                symbol=match.handler_symbol,
            )
        ],
        confidence=Confidence.HIGH,
        created_by=created_by,
        created_at=created_at or utc_now(),
        metadata={
            "route": match.route,
            "param": match.param,
            "sink": match.sink,
            "evidence_kind": SHELL_SINK_EVIDENCE_KIND,
        },
    )


def _heartbeat(message: str) -> None:
    with suppress(RuntimeError):
        activity.heartbeat(message)


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False


def _find_handler_node(
    handler_source: str,
    attack_surface_item: AttackSurfaceItem,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    try:
        tree = ast.parse(handler_source)
    except SyntaxError:
        return None

    fallback: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name == attack_surface_item.handler_symbol:
            return node
        if fallback is None and _has_matching_route_decorator(node, attack_surface_item.route):
            fallback = node
    return fallback


def _has_matching_route_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route: str,
) -> bool:
    return any(_decorator_route(decorator) == route for decorator in node.decorator_list)


def _decorator_route(decorator: ast.expr) -> str | None:
    if not isinstance(decorator, ast.Call) or not decorator.args:
        return None
    first_arg = decorator.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return first_arg.value
    return None


def _handler_param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = node.args
    names = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _iter_calls(node: ast.AST) -> list[ast.Call]:
    return [child for child in ast.walk(node) if isinstance(child, ast.Call)]


def _shell_sink_name(call: ast.Call) -> str | None:
    func = call.func
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
        return None
    module, attr = func.value.id, func.attr
    if module == "subprocess" and attr in SUBPROCESS_SINKS and _has_shell_true(call):
        return f"subprocess.{attr}"
    if module == "os" and attr in OS_SHELL_SINKS:
        return f"os.{attr}"
    return None


def _has_shell_true(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value is True
    return False


def _first_param_in_expr(expr: ast.expr, params: set[str]) -> str | None:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in params:
            return node.id
    return None
