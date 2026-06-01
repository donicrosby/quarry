"""Secrets scanner plugin.

Detects hardcoded secret-like assignments in source files using regex.
Scans for variable names containing API_KEY, SECRET, TOKEN, PASSWORD
with non-empty, non-placeholder string values.

Intentionally simple: no entropy analysis, no multi-file correlation,
no allowlist management beyond common placeholder patterns.
"""

import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from temporalio import activity

from quarry.fingerprints import compute_fingerprint
from quarry.schemas import (
    CandidateFinding,
    Confidence,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.inputs import ScanSecretsInput

SECRET_NAME_PATTERN = re.compile(
    r"^\s*([A-Z_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_KEY)[A-Z_]*)\s*=\s*[\"'](.+?)[\"']\s*$",
    re.MULTILINE,
)

PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "placeholder",
        "example",
        "test",
        "xxx",
        "your-api-key",
        "your_api_key",
        "your-api-key-here",
        "replace_me",
        "TODO",
        "FIXME",
    }
)

PLACEHOLDER_PATTERNS = re.compile(
    r"(?:<|\\[|\\{).*(?:>|\\]|\\})|^sk-test|^pk-test|^ghp_test|^xoxb-test",
)


@dataclass(frozen=True)
class SecretMatch:
    line_number: int
    key_name: str
    value: str
    file_path: str


def scan_file_for_secrets(file_path: Path, repo_root: Path) -> list[SecretMatch]:
    """Scan a single file for hardcoded secret assignments."""
    if not _is_text_file(file_path):
        return []

    source = file_path.read_text(encoding="utf-8", errors="replace")
    relative_path = file_path.relative_to(repo_root).as_posix()
    matches: list[SecretMatch] = []

    for match in SECRET_NAME_PATTERN.finditer(source):
        key_name = match.group(1)
        value = match.group(2)
        if _is_placeholder(value):
            continue
        line_number = source[: match.start(1)].count("\n") + 1
        matches.append(
            SecretMatch(
                line_number=line_number,
                key_name=key_name,
                value=value,
                file_path=relative_path,
            )
        )

    return matches


@activity.defn(name="scan-repo-for-secrets")
def scan_repo_for_secrets(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[SecretMatch]:
    """Scan all source files in a repository for hardcoded secrets."""
    file_paths: tuple[str, ...] | None = None
    if isinstance(repo_root, dict):
        repo_root = ScanSecretsInput(**cast(dict[str, Any], repo_root))
    if isinstance(repo_root, ScanSecretsInput):
        file_paths = repo_root.file_paths
        repo_root = Path(repo_root.repo_root)
    return _scan_repo_for_secrets_impl(repo_root, file_paths)


def _scan_repo_for_secrets_impl(
    repo_root: Path,
    file_paths: tuple[str, ...] | None = None,
) -> list[SecretMatch]:
    all_matches: list[SecretMatch] = []
    files = _candidate_secret_files(repo_root, file_paths)
    for i, path in enumerate(files):
        if not path.is_file():
            continue
        if _is_ignored_path(path, repo_root):
            continue
        if i > 0 and i % 50 == 0:
            with suppress(RuntimeError):
                activity.heartbeat(f"Scanned {i}/{len(files)} files")
        all_matches.extend(scan_file_for_secrets(path, repo_root))
    return all_matches


def _candidate_secret_files(repo_root: Path, file_paths: tuple[str, ...] | None) -> list[Path]:
    if file_paths is None:
        return sorted(repo_root.rglob("*"))
    return [repo_root / file_path for file_path in file_paths]


def secret_match_to_candidate_finding(
    match: SecretMatch,
    *,
    scan_id: str,
    workspace_id: str = "local",
    created_by: str = "secrets-scanner",
) -> CandidateFinding:
    """Convert a secret match into a CandidateFinding."""
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path=match.file_path,
        start_line=match.line_number,
        key_name=match.key_name,
        evidence_kind="hardcoded_assignment",
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id=workspace_id,
        vuln_class=VulnerabilityClass.SECRETS,
        title=f"Hardcoded secret: {match.key_name}",
        hypothesis=f"Variable '{match.key_name}' in {match.file_path}:{match.line_number} "
        f"contains a hardcoded value that may be a secret.",
        affected_component=match.file_path,
        source_refs=[
            SourceRef(
                file_path=match.file_path,
                start_line=match.line_number,
                end_line=match.line_number,
                symbol=match.key_name,
            )
        ],
        confidence=Confidence.MEDIUM,
        created_by=created_by,
        created_at=utc_now(),
        metadata={
            "key_name": match.key_name,
            "value_length": len(match.value),
            "evidence_kind": "hardcoded_assignment",
        },
    )


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().lower()
    if stripped in PLACEHOLDER_VALUES:
        return True
    return bool(PLACEHOLDER_PATTERNS.search(stripped))


def _is_text_file(path: Path) -> bool:
    text_extensions = frozenset(
        {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".env",
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".cfg",
            ".ini",
            ".conf",
            ".sh",
            ".bash",
            ".rb",
            ".go",
            ".rs",
            ".java",
        }
    )
    return path.suffix.lower() in text_extensions


def _is_ignored_path(path: Path, repo_root: Path) -> bool:
    ignored_dirs = frozenset(
        {
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            ".quarry",
            ".ruff_cache",
            ".venv",
            "__pycache__",
            "build",
            "dist",
            "node_modules",
        }
    )
    relative_parts = path.relative_to(repo_root).parts
    return any(part in ignored_dirs for part in relative_parts)
