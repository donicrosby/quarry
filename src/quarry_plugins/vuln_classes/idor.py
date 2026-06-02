"""IDOR candidate scanner plugin.

Detects FastAPI route handlers with object-like path parameters and no obvious
authentication or ownership checks. This scanner is static analysis only: it
parses source with ``ast`` and never performs HTTP requests.
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
    SourceRef,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.inputs import IdorScanInput

IDOR_PATH_PARAMS = frozenset({"id", "user_id", "account_id", "org_id", "project_id"})
AUTH_NAME_FRAGMENTS = frozenset(
    {
        "current_user",
        "get_current_user",
        "authenticated_user",
        "require_auth",
        "requires_auth",
        "authorize",
        "authorized",
        "permission",
        "permissions",
        "owner",
        "ownership",
    }
)
MISSING_AUTH_EVIDENCE_KIND = "missing_auth_check"


@dataclass(frozen=True)
class IdrMatch:
    line_number: int
    route: str
    path_param: str
    handler_file: str
    handler_symbol: str | None


@activity.defn(name="scan-attack-surface-for-idor")
def scan_attack_surface_for_idor(
    input: IdorScanInput | dict[str, object],
) -> list[CandidateFinding]:
    if isinstance(input, dict):
        input = IdorScanInput(**cast(dict[str, Any], input))
    return _scan_attack_surface_for_idor_impl(input)


def _scan_attack_surface_for_idor_impl(input: IdorScanInput) -> list[CandidateFinding]:
    repo_root = Path(input.repo_root)
    findings: list[CandidateFinding] = []
    for i, item in enumerate(input.attack_surface_items):
        if i % 10 == 0:
            _heartbeat(f"Scanned {i}/{len(input.attack_surface_items)} routes")
        if _activity_cancel_requested():
            raise TemporalCancelledError("IDOR scan cancelled")

        handler_path = repo_root / item.handler_file
        if not handler_path.is_file():
            continue
        handler_source = handler_path.read_text(encoding="utf-8", errors="replace")
        for match in scan_handler_for_idor(item, handler_source):
            findings.append(
                idor_match_to_candidate_finding(
                    match,
                    scan_id=input.scan_id,
                    workspace_id=input.workspace_id,
                )
            )
    return findings


def scan_handler_for_idor(
    attack_surface_item: AttackSurfaceItem,
    handler_source: str,
) -> list[IdrMatch]:
    risky_params = _risky_path_params(attack_surface_item)
    if not risky_params:
        return []

    handler_node = _find_handler_node(handler_source, attack_surface_item)
    if handler_node is None:
        return []
    if _has_authorization_pattern(handler_node):
        return []

    return [
        IdrMatch(
            line_number=_handler_evidence_line(handler_node, attack_surface_item.route),
            route=attack_surface_item.route,
            path_param=path_param,
            handler_file=attack_surface_item.handler_file,
            handler_symbol=attack_surface_item.handler_symbol,
        )
        for path_param in risky_params
    ]


def idor_match_to_candidate_finding(
    match: IdrMatch,
    *,
    scan_id: str,
    workspace_id: str = "local",
    created_by: str = "idor-scanner",
    created_at: datetime | None = None,
) -> CandidateFinding:
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.IDOR,
        file_path=match.handler_file,
        start_line=match.line_number,
        key_name=match.path_param,
        evidence_kind=MISSING_AUTH_EVIDENCE_KIND,
    )
    sink = _match_sink(match)
    root_cause_key = compute_root_cause_key(
        vuln_class=VulnerabilityClass.IDOR,
        file_path=match.handler_file,
        sink=sink,
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id=workspace_id,
        vuln_class=VulnerabilityClass.IDOR,
        title=f"Potential IDOR via {match.path_param}",
        hypothesis=(
            f"Route {match.route} in {match.handler_file}:{match.line_number} accepts "
            f"object identifier '{match.path_param}' without an obvious authorization check."
        ),
        root_cause_key=root_cause_key,
        affected_component=match.handler_file,
        source_refs=[
            SourceRef(
                file_path=match.handler_file,
                start_line=match.line_number,
                end_line=match.line_number,
                symbol=match.handler_symbol,
            )
        ],
        confidence=Confidence.MEDIUM,
        created_by=created_by,
        created_at=created_at or utc_now(),
        metadata={
            "route": match.route,
            "path_param": match.path_param,
            "handler_symbol": match.handler_symbol,
            "evidence_kind": MISSING_AUTH_EVIDENCE_KIND,
        },
    )


def _heartbeat(message: str) -> None:
    with suppress(RuntimeError):
        activity.heartbeat(message)


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False


def _risky_path_params(attack_surface_item: AttackSurfaceItem) -> list[str]:
    params = attack_surface_item.params or _extract_path_params(attack_surface_item.route)
    return [path_param for path_param in params if path_param in IDOR_PATH_PARAMS]


def _extract_path_params(route: str) -> list[str]:
    return [
        segment[1:-1]
        for segment in route.split("/")
        if segment.startswith("{") and segment.endswith("}")
    ]


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


def _handler_evidence_line(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route: str,
) -> int:
    for decorator in node.decorator_list:
        if _decorator_route(decorator) == route:
            return decorator.lineno
    return node.lineno


def _decorator_route(decorator: ast.expr) -> str | None:
    if not isinstance(decorator, ast.Call) or not decorator.args:
        return None
    first_arg = decorator.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return first_arg.value
    return None


def _has_authorization_pattern(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(_node_contains_auth_name(child) for child in ast.walk(node))


def _node_contains_auth_name(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return _is_auth_name(node.id)
    if isinstance(node, ast.arg):
        return _is_auth_name(node.arg)
    if isinstance(node, ast.Attribute):
        return _is_auth_name(node.attr)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _is_auth_name(node.value)
    return False


def _is_auth_name(value: str) -> bool:
    normalized = value.lower()
    return any(fragment in normalized for fragment in AUTH_NAME_FRAGMENTS)


def _match_sink(match: IdrMatch) -> str:
    if match.handler_symbol is None:
        return match.path_param
    return f"{match.handler_symbol}:{match.path_param}"
