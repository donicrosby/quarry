"""Planted-regression target: reachable, firing sinks + scoring (bench 2.3).

Mirrors ``test_benchmark_web_fixtures.py`` for ``examples/vulnerable-planted``.
The invariant under test is the one the fixture inventory warns about: a
ground-truth entry MUST NOT exist without a reachable sink at the location it
names, or the benchmark reports a permanent miss for a class nothing could ever
score. Each entry is verified against the app that actually serves the route —
by calling the handler, never by grepping for a token — and the planted data/
seed the file route reads is exercised so a missing fixture turns this red.

The command half of task 2.3 (``quarry benchmark local --repo <path>
--ground-truth <path>`` scores the target) is exercised by driving the exact
function the CLI calls, ``quarry_cli.main._benchmark_local_command``, against the
planted repo + manifest and asserting the emitted ``BenchmarkRunResult`` scores
every planted class.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import pickle
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, ClassVar, Self, cast

import pytest

from quarry.benchmark import load_ground_truth
from quarry.benchmark_artifacts import BenchmarkRunResult
from quarry.benchmark_inventory import build_inventory
from quarry.config import QuarrySettings
from quarry.schemas import (
    FinalFinding,
    Scan,
    ScanProfile,
    ScanStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)
from quarry_cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]
PLANTED_DIR = REPO_ROOT / "examples/vulnerable-planted"
TARGET_APP = PLANTED_DIR / "app.py"
GROUND_TRUTH_PATH = REPO_ROOT / "tests/golden/ground_truth/vulnerable-planted.json"
HUNT_DIR = REPO_ROOT / "prompts/hunt"
PROMPTS_DIR = REPO_ROOT / "prompts"

_PLANTED_MODULES = ("admin", "serialization", "weak_crypto", "app")

# class -> (route, expected_proof_type, file, sink) for the planted fixtures.
PLANTED_FIXTURES: dict[str, tuple[str, str, str, str]] = {
    "command_injection": ("/exec", "command_output", "app.py", "exec_cmd"),
    "path_traversal": ("/files", "file_read", "app.py", "read_file"),
    "weak_crypto": ("/password", "code_evidence", "weak_crypto.py", "hash_password"),
    "auth": ("/admin/status", "response_evidence", "admin.py", "admin_status"),
    "insecure_deserialization": (
        "/profile",
        "code_evidence",
        "serialization.py",
        "load_profile",
    ),
}


@contextmanager
def _planted_app() -> Generator[dict[str, Any], None, None]:
    """Import the target's modules with its directory on ``sys.path``.

    ``app.py`` imports its helpers as top-level modules (``from admin import ...``),
    exactly as ``uvicorn --app-dir`` resolves them, so the example directory must
    be on ``sys.path`` while the modules load.
    """
    example = str(PLANTED_DIR)
    sys.path.insert(0, example)
    for name in _PLANTED_MODULES:
        sys.modules.pop(name, None)
    try:
        modules = {name: importlib.import_module(name) for name in _PLANTED_MODULES}
        yield cast("dict[str, Any]", modules)
    finally:
        if example in sys.path:
            sys.path.remove(example)
        for name in _PLANTED_MODULES:
            sys.modules.pop(name, None)


def _ground_truth() -> list[dict[str, Any]]:
    raw = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, list)
    return cast("list[dict[str, Any]]", raw)


def _entry_for(vuln_class: str) -> dict[str, Any]:
    matches = [entry for entry in _ground_truth() if entry["vuln_class"] == vuln_class]
    assert len(matches) == 1, f"expected exactly one ground-truth entry for {vuln_class}"
    return matches[0]


def test_manifest_is_loadable_and_fully_flagged_planted() -> None:
    truth = load_ground_truth(GROUND_TRUTH_PATH)

    assert {item.vuln_class.value for item in truth} == set(PLANTED_FIXTURES)
    assert all(item.planted for item in truth)
    assert all(item.route for item in truth)


@pytest.mark.parametrize("vuln_class", sorted(PLANTED_FIXTURES))
def test_entry_records_class_location_and_expected_proof_type(vuln_class: str) -> None:
    entry = _entry_for(vuln_class)
    route, proof_type, file_name, sink = PLANTED_FIXTURES[vuln_class]

    assert entry["file_path"] == file_name
    assert entry["route"] == route
    assert entry["expected_proof_type"] == proof_type
    assert entry["expected_fingerprint_hint"] == f"{vuln_class}:{file_name}:{sink}"


@pytest.mark.parametrize("vuln_class", sorted(PLANTED_FIXTURES))
def test_each_planted_class_is_huntable_and_benchmarkable(vuln_class: str) -> None:
    assert list(HUNT_DIR.glob(f"{vuln_class}.*.j2")), f"no hunt template for {vuln_class}"

    rows = {
        row.vuln_class: row
        for row in build_inventory(
            prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_PATH.parent
        )
    }
    row = rows[vuln_class]
    assert row.hunt_template is True
    assert row.benchmarkable is True, "ground-truth entry missing for this class"


@pytest.mark.parametrize("vuln_class", sorted(PLANTED_FIXTURES))
def test_entry_route_is_served_by_the_target(vuln_class: str) -> None:
    entry = _entry_for(vuln_class)
    with _planted_app() as modules:
        paths = {getattr(route, "path", None) for route in modules["app"].app.routes}

    assert entry["route"] in paths, f"{entry['route']} is not a route on the target app"


@pytest.mark.parametrize("vuln_class", sorted(PLANTED_FIXTURES))
def test_entry_sink_exists_on_the_target(vuln_class: str) -> None:
    _, _, file_name, sink = PLANTED_FIXTURES[vuln_class]
    module_name = file_name.removesuffix(".py")

    with _planted_app() as modules:
        assert callable(getattr(modules[module_name], sink, None)), f"{module_name}.{sink} missing"


def test_data_seed_the_file_route_reads_is_committed() -> None:
    """The /files seed must exist on disk or the sink 500s on every input (B2)."""
    seed = PLANTED_DIR / "data" / "welcome.txt"

    assert seed.is_file(), "examples/vulnerable-planted/data seed is missing from the tree"


def test_path_traversal_sink_reads_seed_and_escapes_the_data_dir() -> None:
    with _planted_app() as modules:
        read_file = modules["app"].read_file

    seed = read_file("welcome.txt")
    assert "planted-regression target" in seed["content"].lower()

    # A normalised join would refuse the ``../`` payload; the planted sink escapes
    # DATA_DIR and returns a file outside it.
    escaped = read_file("../app.py")
    assert "Planted-regression target" in escaped["content"]


def test_command_injection_sink_executes_shell_metacharacters() -> None:
    with _planted_app() as modules:
        exec_cmd = modules["app"].exec_cmd

    result = exec_cmd("qrmark; echo QRYINJECTED")

    assert "qrmark" in result["stdout"]
    assert "QRYINJECTED" in result["stdout"]  # only reachable if `;` ran in a shell


def test_weak_crypto_sink_hashes_unsalted_md5() -> None:
    with _planted_app() as modules:
        hash_password = modules["weak_crypto"].hash_password

    digest = hash_password("qrmark")

    assert digest == hashlib.md5(b"qrmark", usedforsecurity=False).hexdigest()
    assert len(digest) == 32


def test_missing_authz_sink_leaks_internal_state_to_any_caller() -> None:
    with _planted_app() as modules:
        admin_status = modules["admin"].admin_status

    leaked = admin_status("not-an-admin")

    assert leaked["requested_by"] == "not-an-admin"
    assert leaked["users"] == "42"
    assert leaked["uptime_hours"] == "1337"


def test_deserialization_sink_executes_attacker_supplied_pickle() -> None:
    with _planted_app() as modules:
        load_profile = modules["serialization"].load_profile

    # A benign pickle whose __reduce__ calls a callable during unpickling: proof
    # that attacker bytes execute, not merely decode.
    class _ExecOnLoad:
        def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
            return (eval, ("'QRYPICKLE'",))

    payload = pickle.dumps(_ExecOnLoad()).hex()
    result = load_profile(payload)

    assert result["profile"] == "QRYPICKLE"


# ---------------------------------------------------------------------------
# bench 2.3 — `quarry benchmark local` scores the planted target
# ---------------------------------------------------------------------------


def _planted_findings() -> list[FinalFinding]:
    """Findings a correct hunt would produce for the planted manifest."""
    findings: list[FinalFinding] = []
    for entry in _ground_truth():
        findings.append(
            FinalFinding(
                id=entry["id"],
                scan_id="scan-planted",
                workspace_id="local",
                fingerprint=f"fp-{entry['id']}",
                vuln_class=VulnerabilityClass(entry["vuln_class"]),
                severity=Severity(entry["severity"]),
                title=entry["id"],
                summary="planted regression fixture",
                affected_component=entry["file_path"],
                source_refs=[SourceRef(file_path=entry["file_path"])],
                validation_result_id="v1",
                created_at=utc_now(),
            )
        )
    return findings


class _FakePlantedClient:
    """Async client stub returning a completed scan that found the manifest."""

    started: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    async def start_scan(self, **kwargs: Any) -> dict[str, str]:
        type(self).started.append(kwargs)
        return {"scan_id": "scan-planted", "status": "RUNNING"}

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        return {"scan_id": scan_id, "status": "COMPLETED"}

    async def get_scan(self, scan_id: str) -> Scan:
        classes = [VulnerabilityClass(name) for name in sorted(PLANTED_FIXTURES)]
        return Scan(
            id=scan_id,
            workspace_id="local",
            target_id="target-planted",
            requested_by="cli",
            profile=ScanProfile(id="benchmark", name="benchmark", vuln_classes=classes),
            status=ScanStatus.COMPLETED,
            attack_classes=classes,
            created_at=utc_now(),
        )

    async def get_findings(self, scan_id: str) -> dict[str, list[Any]]:
        return {"candidate_findings": [], "final_findings": _planted_findings()}


def test_benchmark_local_command_scores_the_planted_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main, "QuarryClient", _FakePlantedClient)
    _FakePlantedClient.started = []
    artifact_root = tmp_path / "benchmarks"

    lines = asyncio.run(
        main._benchmark_local_command(  # type: ignore[reportPrivateUsage]
            QuarrySettings(server_url="http://test"),
            str(PLANTED_DIR),
            str(GROUND_TRUTH_PATH),
            None,
            artifact_root=artifact_root,
        )
    )

    artifact = artifact_root / "local-scan-planted" / "result.json"
    assert artifact.is_file(), lines
    result = BenchmarkRunResult.load(artifact)
    # Scoring ran against the planted manifest: every planted class is recalled,
    # with no false positives.
    assert set(result.metrics.recall_per_class) == set(PLANTED_FIXTURES)
    assert all(rate == 1.0 for rate in result.metrics.recall_per_class.values())
    assert result.metrics.fp_rate == 0.0
    assert result.provenance.config["repo"] == str(PLANTED_DIR)
    assert result.provenance.config["ground_truth"] == str(GROUND_TRUTH_PATH)
    assert _FakePlantedClient.started
    assert _FakePlantedClient.started[0]["benchmark"] is True
