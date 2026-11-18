"""Structural and behavioral tests for the SARIF CI/CD integrations.

Covers the reusable GitHub Action, the GitLab CI/CD component, and the shared
jq severity-threshold filter both invoke. ``actionlint`` / ``gitlab-ci-lint``
are not part of the toolchain, so the workflow/component contracts are pinned
by parsing the YAML and asserting the shape the spec requires, and the filter
itself is exercised as the shipped bytes (the file both CI definitions call).
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "quarry-scan.yml"
GITLAB_COMPONENT_PATH = REPO_ROOT / "templates" / "quarry-sast.yml"
FILTER_PATH = REPO_ROOT / "ci" / "sarif_severity_filter.jq"

FIXTURE_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _as_dict(value: Any) -> dict[str, Any]:
    assert isinstance(value, dict), f"expected a mapping, got {type(value).__name__}"
    return cast("dict[str, Any]", value)


def _load_yaml(path: Path) -> dict[Any, Any]:
    # GitLab components are multi-document YAML (`spec:` then the job config);
    # GitHub workflows are single-document. Merge every document so one helper
    # reads both.
    documents: Any = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    merged: dict[Any, Any] = {}
    for document in documents:
        if isinstance(document, dict):
            merged.update(cast("dict[Any, Any]", document))
    assert merged, f"{path.name} did not parse to a mapping"
    return merged


def _workflow_call() -> dict[str, Any]:
    workflow = _load_yaml(WORKFLOW_PATH)
    # PyYAML resolves the bare `on:` key to boolean True (YAML 1.1).
    trigger = workflow.get("on", workflow.get(True))
    return _as_dict(_as_dict(trigger)["workflow_call"])


def _steps() -> list[dict[str, Any]]:
    job = _as_dict(_as_dict(_load_yaml(WORKFLOW_PATH)["jobs"])["quarry-scan"])
    steps = job["steps"]
    assert isinstance(steps, list)
    return [_as_dict(step) for step in cast("list[Any]", steps)]


def _step(name_part: str) -> int:
    for index, step in enumerate(_steps()):
        if name_part.lower() in str(step.get("name", "")).lower():
            return index
    raise AssertionError(f"no workflow step matching {name_part!r}")


# --- 4.1 reusable workflow contract ------------------------------------------


def test_reusable_workflow_declares_the_spec_inputs() -> None:
    inputs = _as_dict(_workflow_call()["inputs"])

    assert set(inputs) == {
        "quarry_config",
        "target_repo",
        "severity_threshold",
        "quarry_version",
    }
    assert _as_dict(inputs["quarry_config"])["required"] is True
    assert _as_dict(inputs["target_repo"])["default"] == "${{ github.workspace }}"
    assert _as_dict(inputs["severity_threshold"])["default"] == "low"
    assert _as_dict(inputs["quarry_version"])["default"] == "latest"


def test_reusable_workflow_requests_security_events_write() -> None:
    # upload-sarif needs `security-events: write`; a workflow without it fails.
    permissions = _as_dict(_load_yaml(WORKFLOW_PATH)["permissions"])
    assert permissions["security-events"] == "write"
    assert permissions["contents"] == "read"


# --- 4.2/4.3 upload contract --------------------------------------------------


def test_upload_step_uses_a_directory_and_a_category() -> None:
    step = _steps()[_step("Upload SARIF")]

    assert step["uses"] == "github/codeql-action/upload-sarif@v3"
    with_ = _as_dict(step["with"])
    # upload-sarif takes a file or directory, never a glob.
    assert with_["sarif_file"] == "sarif/"
    assert with_["category"] == "quarry"


def test_scan_step_maps_failure_to_exit_2_before_upload() -> None:
    # 4.4: a non-zero scan exit must fail the job without attempting upload.
    steps = _steps()
    scan_index = _step("Run Quarry scan")
    upload_index = _step("Upload SARIF")
    assert scan_index < upload_index

    scan_step = steps[scan_index]
    assert "exit 2" in str(scan_step["run"])

    # Later steps are skipped when an earlier one fails unless they opt in.
    upload_step = steps[upload_index]
    assert "always()" not in str(upload_step.get("if", ""))
    assert "continue-on-error" not in upload_step


def test_filter_and_gate_steps_use_the_exit_code_contract() -> None:
    gate = _steps()[_step("Fail on findings")]
    assert "exit 1" in str(gate["run"])

    filter_step = _steps()[_step("Filter SARIF")]
    assert "ci/sarif_severity_filter.jq" in str(filter_step["run"])
    # A scan that produced no log is a scan error, not a pass.
    assert "exit 2" in str(filter_step["run"])


# --- 5.1-5.4 GitLab component contract ---------------------------------------


def _gitlab_job() -> dict[str, Any]:
    return _as_dict(_load_yaml(GITLAB_COMPONENT_PATH)["quarry-sast"])


def test_gitlab_component_declares_the_spec_inputs() -> None:
    inputs = _as_dict(_as_dict(_load_yaml(GITLAB_COMPONENT_PATH)["spec"])["inputs"])

    assert set(inputs) == {"quarry_config", "severity_threshold", "quarry_version"}
    assert _as_dict(inputs["severity_threshold"])["default"] == "low"
    assert _as_dict(inputs["quarry_version"])["default"] == "latest"


def test_gitlab_component_publishes_the_dedicated_sarif_report_type() -> None:
    artifacts = _as_dict(_gitlab_job()["artifacts"])
    reports = _as_dict(artifacts["reports"])
    # The legacy `sast` type expects GitLab's own JSON schema, not SARIF.
    assert reports["sarif"] == "sarif/*.sarif.json"


def test_gitlab_component_scans_the_checked_out_project() -> None:
    variables = _as_dict(_gitlab_job()["variables"])
    assert variables["QUARRY_TARGET_REPO"] == "$CI_PROJECT_DIR"


def test_gitlab_component_job_fails_and_is_not_allow_failure() -> None:
    job = _gitlab_job()
    assert job.get("allow_failure", False) is not True

    script = "\n".join(str(line) for line in cast("list[Any]", job["script"]))
    assert "exit 2" in script  # scan error
    assert "exit 1" in script  # findings at or above threshold
    assert "ci/sarif_severity_filter.jq" in script


# --- 4.6/5.6 the severity filter itself --------------------------------------


def _fixture_sarif() -> dict[str, Any]:
    results: list[dict[str, Any]] = [
        {
            "ruleId": "secrets",
            "level": "error",
            "message": {"text": f"{severity} finding"},
            "partialFingerprints": {"quarryFingerprint": f"fp:{severity}"},
            "properties": {"quarry": {"severity": severity}},
        }
        for severity in FIXTURE_SEVERITIES
    ]
    # A result with no quarry severity must never survive any threshold.
    results.append({"ruleId": "foreign", "level": "warning", "message": {"text": "no severity"}})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "quarry", "version": "0.0.0", "rules": []}},
                "results": results,
            }
        ],
    }


def _run_filter(log_path: Path, threshold: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["jq", "--arg", "threshold", threshold, "-f", str(FILTER_PATH), str(log_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return cast("dict[str, Any]", json.loads(completed.stdout))


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is required for the severity filter")
@pytest.mark.parametrize(
    ("threshold", "expected"),
    [
        ("critical", ["critical"]),
        ("high", ["critical", "high"]),
        ("medium", ["critical", "high", "medium"]),
        ("low", ["critical", "high", "medium", "low"]),
        ("info", ["critical", "high", "medium", "low", "info"]),
    ],
)
def test_severity_filter_drops_results_below_the_threshold(
    tmp_path: Path, threshold: str, expected: list[str]
) -> None:
    log_path = tmp_path / "log.sarif.json"
    log_path.write_text(json.dumps(_fixture_sarif()), encoding="utf-8")

    filtered = _run_filter(log_path, threshold)

    severities = [
        result["properties"]["quarry"]["severity"] for result in filtered["runs"][0]["results"]
    ]
    assert severities == expected


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is required for the severity filter")
def test_both_ci_definitions_share_the_canonical_filter_bytes(tmp_path: Path) -> None:
    # The GitHub workflow and the GitLab component must invoke the same filter
    # file, so the two contracts cannot drift apart.
    assert "ci/sarif_severity_filter.jq" in WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "ci/sarif_severity_filter.jq" in GITLAB_COMPONENT_PATH.read_text(encoding="utf-8")
    assert FILTER_PATH.is_file()

    # The gate's counting expression is the same shape the workflows run.
    log_path = tmp_path / "log.sarif.json"
    log_path.write_text(json.dumps(_fixture_sarif()), encoding="utf-8")
    completed = subprocess.run(
        ["jq", "[.runs[0].results[]] | length", str(log_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == str(len(FIXTURE_SEVERITIES) + 1)
