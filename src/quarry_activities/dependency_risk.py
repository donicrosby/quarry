"""Deterministic dependency-manifest supply-chain scanner activity.

Reads the five manifest formats the recon orchestrator already knows about
(``requirements.txt``, ``pyproject.toml``, ``package.json``, ``Cargo.toml``,
``go.mod``) and emits one :class:`CandidateFinding` per detected supply-chain
risk: unpinned version specifiers (HIGH), git/URL-sourced dependencies (HIGH),
configurable typosquat name matches (MEDIUM), npm pre/postinstall script
presence (MEDIUM), and ``curl``/``wget`` piped into a shell interpreter in npm
scripts (CRITICAL).

The activity is pure static analysis: it constructs no model client, consumes no
budget, and performs no network access. Its output is a deterministic function
of the manifest bytes, so identical manifests always yield identical findings in
the same order.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict
from temporalio import activity

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.schemas import (
    CandidateFinding,
    Confidence,
    EvidencePathElement,
    Severity,
    SourceRef,
    VulnerabilityClass,
)

# How a dependency's version is sourced: a package registry, a git reference,
# or a direct URL download.
SourceKind = Literal["registry", "git", "url"]

CREATED_BY = "dependency-risk-scanner"

# Fixed timestamp so repeated runs on identical manifests yield byte-identical
# findings (the determinism requirement). The workflow re-stamps ``created_at``
# to ``workflow.now()`` before persisting a candidate.
_PLACEHOLDER_CREATED_AT = datetime(1970, 1, 1, tzinfo=UTC)

_GIT_PREFIXES: tuple[str, ...] = ("git+", "git://", "git@", "ssh://")
_URL_PREFIXES: tuple[str, ...] = ("http://", "https://")
_INSTALL_HOOKS: tuple[str, ...] = ("preinstall", "postinstall")

# curl|shell or wget|shell — the classic remote-code-execution install pattern.
_CURL_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash|zsh|ksh|dash|fish)\b",
    re.IGNORECASE,
)

# PEP 508 / pip requirement: ``name[extras] <version-specifier>``.
_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


class Dependency(BaseModel):
    """One parsed dependency with its location and source classification."""

    model_config = ConfigDict(frozen=True)

    name: str
    version_specifier: str | None = None
    source_kind: SourceKind = "registry"
    file_path: str = ""
    line: int = 1


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _find_line(text: str, needle: str) -> int:
    """First 1-indexed line containing *needle*, or 1 when absent."""
    if needle:
        for idx, line in enumerate(text.splitlines(), start=1):
            if needle in line:
                return idx
    return 1


def _classify_source(spec: str) -> SourceKind:
    """Classify a version/source string as registry, git, or url."""
    lowered = spec.strip().lower()
    if lowered.startswith(_GIT_PREFIXES) or lowered.endswith(".git"):
        return "git"
    if lowered.startswith(_URL_PREFIXES):
        return "url"
    return "registry"


def _source_ref(spec: str) -> str | None:
    """Extract a pinned git/URL reference (npm ``#ref`` or pip ``@ref``)."""
    if "#" in spec:
        ref = spec.rsplit("#", 1)[1].strip()
        if ref:
            return ref
    stripped = spec.strip()
    if stripped.lower().startswith("git+"):
        head, sep, tail = stripped.rpartition("@")
        # ``git+ssh://git@host/...`` has the marker inside the prefix, not as a
        # trailing pin — require a path/ref split to count it.
        if sep and "/" in head and tail.strip() and "/" not in tail:
            return tail.strip()
    return None


def _name_from_url(url: str) -> str:
    """Derive a best-effort package name from a source URL."""
    tail = url.rstrip("/").split("/")[-1]
    tail = re.split(r"[#@]", tail)[0]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail or url


def _dig(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = cast("dict[str, Any]", current).get(key)
    return current


# ---------------------------------------------------------------------------
# Manifest parsers (no model calls)
# ---------------------------------------------------------------------------


def _dependency_from_requirement(entry: str, path: Path, text: str) -> Dependency | None:
    """Parse one PEP 508 requirement (``name>=1.0`` / ``name @ url`` / bare URL)."""
    spec_line = entry.split(";", 1)[0].strip()
    if not spec_line:
        return None
    if " @ " in spec_line:
        raw_name, _, raw_spec = spec_line.partition(" @ ")
        name = raw_name.strip()
        if not name:
            return None
        source = _classify_source(raw_spec)
        version = _source_ref(raw_spec) if source != "registry" else None
        return Dependency(
            name=name,
            version_specifier=version,
            source_kind=source,
            file_path=str(path),
            line=_find_line(text, name),
        )
    if spec_line.lower().startswith(_GIT_PREFIXES + _URL_PREFIXES):
        name = _name_from_url(spec_line)
        source = _classify_source(spec_line)
        version = _source_ref(spec_line) if source != "registry" else None
        return Dependency(
            name=name,
            version_specifier=version,
            source_kind=source,
            file_path=str(path),
            line=_find_line(text, name),
        )
    match = _REQUIREMENT_RE.match(spec_line)
    if match is None:
        return None
    name = match.group(1)
    return Dependency(
        name=name,
        version_specifier=match.group(3).strip() or None,
        source_kind="registry",
        file_path=str(path),
        line=_find_line(text, name),
    )


def parse_requirements_txt(path: Path) -> list[Dependency]:
    """Parse pip-style requirements, detecting unpinned and git/URL sources."""
    text = _read_text(path)
    deps: list[Dependency] = []
    for raw in text.splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("-"):
            if entry.startswith(("-e ", "--editable ")):
                parts = entry.split(None, 1)
                entry = parts[1].strip() if len(parts) > 1 else ""
            else:
                continue
        if not entry or entry.startswith("#"):
            continue
        dep = _dependency_from_requirement(entry, path, text)
        if dep is not None:
            deps.append(dep)
    return deps


def _poetry_dependency(name: str, spec: Any, path: Path, text: str) -> Dependency:
    line = _find_line(text, name)
    if isinstance(spec, str):
        return Dependency(name=name, version_specifier=spec or None, file_path=str(path), line=line)
    if isinstance(spec, dict):
        spec_map = cast("dict[str, Any]", spec)
        git = spec_map.get("git")
        if isinstance(git, str) and git:
            ref = spec_map.get("rev") or spec_map.get("tag") or spec_map.get("branch")
            return Dependency(
                name=name,
                version_specifier=str(ref) if ref else None,
                source_kind="git",
                file_path=str(path),
                line=line,
            )
        url = spec_map.get("url")
        if isinstance(url, str) and url:
            return Dependency(
                name=name,
                version_specifier=_source_ref(url),
                source_kind="url",
                file_path=str(path),
                line=line,
            )
        version = spec_map.get("version")
        return Dependency(
            name=name,
            version_specifier=str(version) if version else None,
            file_path=str(path),
            line=line,
        )
    return Dependency(name=name, file_path=str(path), line=line)


def parse_pyproject_toml(path: Path) -> list[Dependency]:
    """Parse ``[project] dependencies`` and ``[tool.poetry.dependencies]``."""
    text = _read_text(path)
    data: dict[str, Any] = tomllib.loads(text)
    deps: list[Dependency] = []
    project = data.get("project")
    if isinstance(project, dict):
        raw_deps = cast("dict[str, Any]", project).get("dependencies")
        if isinstance(raw_deps, list):
            for entry in cast("list[object]", raw_deps):
                dep = _dependency_from_requirement(str(entry), path, text)
                if dep is not None:
                    deps.append(dep)
    poetry = _dig(data, ("tool", "poetry", "dependencies"))
    if isinstance(poetry, dict):
        for name, spec in cast("dict[str, Any]", poetry).items():
            if str(name).lower() == "python":
                continue
            deps.append(_poetry_dependency(str(name), spec, path, text))
    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    """Parse npm ``dependencies`` / ``devDependencies``, detecting git/URL sources."""
    text = _read_text(path)
    data: dict[str, Any] = json.loads(text)
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for raw_name, raw_spec in cast("dict[str, Any]", block).items():
            name = str(raw_name)
            spec = str(raw_spec)
            source = _classify_source(spec)
            version = _source_ref(spec) if source != "registry" else spec
            deps.append(
                Dependency(
                    name=name,
                    version_specifier=version or None,
                    source_kind=source,
                    file_path=str(path),
                    line=_find_line(text, f'"{name}"'),
                )
            )
    return deps


def parse_package_json_scripts(path: Path) -> dict[str, str]:
    """Extract the npm ``scripts`` block (empty when absent)."""
    data: dict[str, Any] = json.loads(_read_text(path))
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {str(k): str(v) for k, v in cast("dict[str, Any]", scripts).items()}


def _package_json_name(path: Path) -> str:
    data: dict[str, Any] = json.loads(_read_text(path))
    name = data.get("name")
    return str(name) if isinstance(name, str) and name else "package.json"


def _cargo_dependency(name: str, spec: Any, path: Path, text: str) -> Dependency:
    line = _find_line(text, name)
    if isinstance(spec, str):
        return Dependency(name=name, version_specifier=spec or None, file_path=str(path), line=line)
    if isinstance(spec, dict):
        spec_map = cast("dict[str, Any]", spec)
        git = spec_map.get("git")
        if isinstance(git, str) and git:
            ref = spec_map.get("rev") or spec_map.get("tag") or spec_map.get("branch")
            return Dependency(
                name=name,
                version_specifier=str(ref) if ref else None,
                source_kind="git",
                file_path=str(path),
                line=line,
            )
        url = spec_map.get("url")
        if isinstance(url, str) and url:
            return Dependency(
                name=name,
                version_specifier=_source_ref(url),
                source_kind="url",
                file_path=str(path),
                line=line,
            )
        version = spec_map.get("version")
        return Dependency(
            name=name,
            version_specifier=str(version) if version else None,
            file_path=str(path),
            line=line,
        )
    return Dependency(name=name, file_path=str(path), line=line)


def parse_cargo_toml(path: Path) -> list[Dependency]:
    """Parse the Cargo ``[dependencies]`` table, detecting git sources."""
    text = _read_text(path)
    data: dict[str, Any] = tomllib.loads(text)
    block = data.get("dependencies")
    if not isinstance(block, dict):
        return []
    return [
        _cargo_dependency(str(name), spec, path, text)
        for name, spec in cast("dict[str, Any]", block).items()
    ]


def _record_require(fragment: str, idx: int, requires: dict[str, tuple[str | None, int]]) -> None:
    tokens = fragment.split()
    if not tokens:
        return
    requires[tokens[0]] = (tokens[1] if len(tokens) > 1 else None, idx)


def _record_replace(fragment: str, replaces: dict[str, tuple[str, str | None]]) -> None:
    if "=>" not in fragment:
        return
    left, _, right = fragment.partition("=>")
    left_tokens = left.split()
    right_tokens = right.split()
    if not left_tokens or not right_tokens:
        return
    replaces[left_tokens[0]] = (right_tokens[0], right_tokens[1] if len(right_tokens) > 1 else None)


def parse_go_mod(path: Path) -> list[Dependency]:
    """Parse the go.mod ``require`` block, resolving ``replace`` directives.

    A replaced module keeps the source kind implied by its replacement target
    (git/url for a git or URL target, registry otherwise — local-path
    replacements are not a specced risk and stay classified as registry).
    """
    text = _read_text(path)
    requires: dict[str, tuple[str | None, int]] = {}
    replaces: dict[str, tuple[str, str | None]] = {}
    in_require = False
    in_replace = False
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line in ("require (", "replace ("):
            in_require = line.startswith("require")
            in_replace = line.startswith("replace")
            continue
        if line == ")":
            in_require = False
            in_replace = False
            continue
        if line.startswith("require "):
            _record_require(line[len("require ") :], idx, requires)
            continue
        if line.startswith("replace "):
            _record_replace(line[len("replace ") :], replaces)
            continue
        if in_require:
            _record_require(line, idx, requires)
        elif in_replace:
            _record_replace(line, replaces)

    deps: list[Dependency] = []
    for module, (version, idx) in requires.items():
        source: SourceKind = "registry"
        resolved_version = version
        replacement = replaces.get(module)
        if replacement is not None:
            target, target_version = replacement
            resolved_version = target_version
            source = _classify_source(target)
        deps.append(
            Dependency(
                name=module,
                version_specifier=resolved_version,
                source_kind=source,
                file_path=str(path),
                line=idx,
            )
        )
    return deps


# ---------------------------------------------------------------------------
# Risk checks (deterministic, per-dependency)
# ---------------------------------------------------------------------------


def _is_unpinned(dep: Dependency) -> bool:
    spec = (dep.version_specifier or "").strip()
    if dep.source_kind != "registry":
        return spec == ""
    if not spec:
        return True
    lowered = spec.lower()
    if lowered in {"*", "x", "latest"}:
        return True
    if lowered.startswith((">=", ">")):
        return True
    return any(part.lower() in {"x", "*"} for part in re.split(r"[.,\s]+", spec))


def _build_finding(
    *,
    dep: Dependency,
    kind: str,
    severity: Severity,
    title: str,
    hypothesis: str,
    symbol: str | None = None,
    extra: dict[str, object] | None = None,
) -> CandidateFinding:
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.SUPPLY_CHAIN,
        file_path=dep.file_path,
        start_line=dep.line,
        key_name=symbol or dep.name,
        evidence_kind=kind,
    )
    root_cause_key = compute_root_cause_key(
        vuln_class=VulnerabilityClass.SUPPLY_CHAIN,
        file_path=dep.file_path,
        sink=symbol or dep.name,
    )
    metadata: dict[str, object] = {"evidence_kind": kind, "dependency": dep.name}
    if extra:
        metadata.update(extra)
    return CandidateFinding(
        id=fingerprint[:32],
        # Stamped by the workflow (the activity has no scan identity of its own).
        scan_id="",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SUPPLY_CHAIN,
        title=title,
        hypothesis=hypothesis,
        root_cause_key=root_cause_key,
        affected_component=dep.file_path,
        source_refs=[
            SourceRef(
                file_path=dep.file_path,
                start_line=dep.line,
                end_line=dep.line,
                symbol=symbol or dep.name,
            )
        ],
        evidence_path=[EvidencePathElement(path=dep.file_path, line=dep.line)],
        confidence=Confidence.MEDIUM,
        severity=severity,
        created_by=CREATED_BY,
        created_at=_PLACEHOLDER_CREATED_AT,
        metadata=metadata,
    )


def check_unpinned_version(dep: Dependency) -> CandidateFinding | None:
    """Flag a lower-bound-only, wildcard, ``latest``, or absent version specifier."""
    if not _is_unpinned(dep):
        return None
    display = dep.version_specifier or "(unversioned)"
    return _build_finding(
        dep=dep,
        kind="unpinned_version",
        severity=Severity.HIGH,
        title=f"Unpinned dependency: {dep.name}",
        hypothesis=(
            f"Dependency '{dep.name}' in {dep.file_path} uses the unpinned version "
            f"specifier '{display}'; the resolved version can drift between installs."
        ),
    )


def check_git_url_dep(dep: Dependency) -> CandidateFinding | None:
    """Flag a dependency sourced from git or a direct http/https URL."""
    if dep.source_kind not in ("git", "url"):
        return None
    return _build_finding(
        dep=dep,
        kind=f"{dep.source_kind}_dependency",
        severity=Severity.HIGH,
        title=f"{dep.source_kind.capitalize()} dependency: {dep.name}",
        hypothesis=(
            f"Dependency '{dep.name}' in {dep.file_path} is sourced from a "
            f"{dep.source_kind} location rather than a package registry."
        ),
    )


def check_typosquat(dep: Dependency, patterns: list[str]) -> CandidateFinding | None:
    """Flag a name matching a configured typosquat pattern (no-op when empty)."""
    lowered = dep.name.lower()
    for pattern in patterns:
        needle = pattern.strip().lower()
        if needle and needle in lowered:
            return _build_finding(
                dep=dep,
                kind="typosquat",
                severity=Severity.MEDIUM,
                title=f"Typosquat-risk dependency: {dep.name}",
                hypothesis=(
                    f"Dependency '{dep.name}' in {dep.file_path} matches the "
                    f"configured typosquat pattern '{pattern}'."
                ),
                extra={"matched_pattern": pattern},
            )
    return None


def check_npm_install_scripts(dep: Dependency, scripts: dict[str, str]) -> CandidateFinding | None:
    """Flag npm ``preinstall`` / ``postinstall`` hook presence."""
    hooks = [hook for hook in _INSTALL_HOOKS if hook in scripts]
    if not hooks:
        return None
    joined = ", ".join(hooks)
    return _build_finding(
        dep=dep,
        kind="npm_install_script",
        severity=Severity.MEDIUM,
        title=f"npm install hook script: {joined}",
        hypothesis=(
            f"{dep.file_path} defines npm install hook(s) {joined} that run "
            f"automatically on install."
        ),
        symbol=hooks[0],
        extra={"install_hooks": hooks},
    )


def check_curl_pipe_sh(dep: Dependency, scripts: dict[str, str]) -> CandidateFinding | None:
    """Flag a ``curl``/``wget`` piped into a shell interpreter in an npm script.

    Takes the package *dep* (for the manifest location) alongside *scripts* so the
    emitted finding can cite the script line, alongside the matched script name.
    """
    for name in sorted(scripts):
        if _CURL_PIPE_RE.search(scripts[name]):
            return _build_finding(
                dep=dep,
                kind="curl_pipe_shell",
                severity=Severity.CRITICAL,
                title=f"curl-pipe-shell in npm script: {name}",
                hypothesis=(
                    f"npm script '{name}' in {dep.file_path} pipes curl/wget into "
                    f"a shell interpreter."
                ),
                symbol=name,
                extra={"script_name": name},
            )
    return None


# ---------------------------------------------------------------------------
# Activity entry point
# ---------------------------------------------------------------------------

_MANIFEST_PARSERS: tuple[tuple[str, Callable[[Path], list[Dependency]]], ...] = (
    ("requirements.txt", parse_requirements_txt),
    ("pyproject.toml", parse_pyproject_toml),
    ("package.json", parse_package_json),
    ("Cargo.toml", parse_cargo_toml),
    ("go.mod", parse_go_mod),
)


def _npm_script_findings(manifest: Path, rel: str) -> list[CandidateFinding]:
    scripts = parse_package_json_scripts(manifest)
    if not scripts:
        return []
    text = _read_text(manifest)
    findings: list[CandidateFinding] = []
    hooks = [hook for hook in _INSTALL_HOOKS if hook in scripts]
    if hooks:
        hook_dep = Dependency(
            name=_package_json_name(manifest),
            file_path=rel,
            line=_find_line(text, f'"{hooks[0]}"'),
        )
        install_finding = check_npm_install_scripts(hook_dep, scripts)
        if install_finding is not None:
            findings.append(install_finding)
    for name in sorted(scripts):
        script_dep = Dependency(name=name, file_path=rel, line=_find_line(text, f'"{name}"'))
        pipe_finding = check_curl_pipe_sh(script_dep, {name: scripts[name]})
        if pipe_finding is not None:
            findings.append(pipe_finding)
    return findings


def _scan_manifests(root: Path, typosquat_patterns: list[str]) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []
    for rel, parser in _MANIFEST_PARSERS:
        manifest = root / rel
        if not manifest.is_file():
            continue
        deps = [dep.model_copy(update={"file_path": rel}) for dep in parser(manifest)]
        for dep in deps:
            for check in (check_unpinned_version, check_git_url_dep):
                finding = check(dep)
                if finding is not None:
                    findings.append(finding)
            typosquat = check_typosquat(dep, typosquat_patterns)
            if typosquat is not None:
                findings.append(typosquat)
        if rel == "package.json":
            findings.extend(_npm_script_findings(manifest, rel))
    return findings


def _resolve_typosquat_patterns(config_json: str | None) -> list[str]:
    """Resolve the configured typosquat patterns from *config_json*.

    Accepts ``{"typosquat_patterns": [...]}`` or a bare JSON array; ``None`` or an
    empty string disables the check (returns an empty list).
    """
    if config_json is None or not config_json.strip():
        return []
    payload: Any = json.loads(config_json)
    if isinstance(payload, list):
        return [str(item) for item in cast("list[object]", payload)]
    if isinstance(payload, dict):
        raw = cast("dict[str, Any]", payload).get("typosquat_patterns")
        if isinstance(raw, list):
            return [str(item) for item in cast("list[object]", raw)]
        return []
    msg = "dependency-risk-scanner config_json must be a JSON object or array"
    raise ValueError(msg)


@activity.defn(name="dependency-risk-scanner")
def dependency_risk_scanner_activity(
    repo_root: Path | str, config_json: str | None = None
) -> list[CandidateFinding]:
    """Temporal activity: deterministic supply-chain sweep over dependency manifests.

    *config_json* carries ``{"typosquat_patterns": [...]}``; when absent the
    typosquat check is a no-op.
    """
    with suppress(RuntimeError):
        activity.heartbeat()
    root = Path(repo_root)
    patterns = _resolve_typosquat_patterns(config_json)
    return _scan_manifests(root, patterns)
