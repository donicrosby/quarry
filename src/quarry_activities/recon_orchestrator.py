"""Recon orchestrator activity.

Reads the top-level directory layout and package manifests to produce
SubsystemAssignment objects. No model call — pure structural analysis.
"""

from __future__ import annotations

import json
from contextlib import suppress
from pathlib import Path
from typing import Any

from temporalio import activity

from quarry.schemas import SubsystemAssignment

# Manifest filenames that signal a language/ecosystem
_MANIFEST_FILES: dict[str, str] = {
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "yarn.lock": "javascript",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "kotlin",
}

_SOURCE_SUFFIX_LANGUAGE: dict[str, str] = {
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".rs": "rust",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".kt": "kotlin",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
}

_IGNORED_DIRS = frozenset(
    {".git", ".venv", "node_modules", "__pycache__", ".ruff_cache", "dist", "build"}
)


def _detect_languages_from_root(root: Path) -> list[str]:
    """Detect languages by scanning manifest files and source extensions."""
    langs: set[str] = set()

    # Check known manifests
    for fname, lang in _MANIFEST_FILES.items():
        if (root / fname).exists():
            langs.add(lang)

    # Count source file extensions (non-recursive, just top-level + one level)
    def _scan_dir(d: Path, depth: int = 0) -> None:
        if depth > 2:
            return
        try:
            for entry in d.iterdir():
                if entry.is_dir() and entry.name not in _IGNORED_DIRS:
                    _scan_dir(entry, depth + 1)
                elif entry.is_file():
                    lang = _SOURCE_SUFFIX_LANGUAGE.get(entry.suffix.lower())
                    if lang:
                        langs.add(lang)
        except PermissionError:
            pass

    _scan_dir(root)
    return sorted(langs)


def _read_manifest_info(root: Path) -> dict[str, Any]:
    """Read key manifest files and return a summary dict."""
    info: dict[str, Any] = {}

    package_json = root / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
            info["name"] = data.get("name", "")
            info["description"] = data.get("description", "")
            info["main"] = data.get("main", "")
            info["dependencies"] = list(data.get("dependencies", {}).keys())[:10]
        except (json.JSONDecodeError, OSError):
            pass

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8")
        # Simple extraction — avoid adding tomllib as a dependency here
        for line in text.splitlines():
            if line.startswith("name ="):
                info["name"] = line.split("=", 1)[1].strip().strip('"').strip("'")

    go_mod = root / "go.mod"
    if go_mod.exists():
        for line in go_mod.read_text(encoding="utf-8").splitlines():
            if line.startswith("module "):
                info["module"] = line.split(" ", 1)[1].strip()

    return info


def _identify_subsystems(root: Path, languages: list[str]) -> list[SubsystemAssignment]:
    """Heuristically identify subsystems from directory structure."""
    assignments: list[SubsystemAssignment] = []

    # Candidate directories that often represent subsystems
    subsystem_dir_hints = {
        "routes": "HTTP route handlers",
        "controllers": "HTTP controllers",
        "handlers": "Request handlers",
        "api": "API layer",
        "cmd": "CLI entry points",
        "internal": "Internal packages",
        "pkg": "Shared packages",
        "lib": "Library code",
        "src": "Source code",
        "app": "Application logic",
        "core": "Core business logic",
        "services": "Service layer",
        "models": "Data models",
    }

    found_subsystem_dirs: list[tuple[Path, str]] = []
    try:
        for entry in root.iterdir():
            if entry.is_dir() and entry.name not in _IGNORED_DIRS:
                hint = subsystem_dir_hints.get(entry.name.lower())
                if hint:
                    found_subsystem_dirs.append((entry, hint))
    except PermissionError:
        pass

    if found_subsystem_dirs:
        for sub_dir, responsibility in found_subsystem_dirs:
            assignments.append(
                SubsystemAssignment(
                    name=sub_dir.name,
                    root_paths=[sub_dir.name],
                    languages=languages,
                    responsibility=responsibility,
                )
            )
    else:
        # No named subsystem dirs found — treat the whole repo as one subsystem
        manifest_info = _read_manifest_info(root)
        name = manifest_info.get("name", root.name) or root.name
        assignments.append(
            SubsystemAssignment(
                name=name,
                root_paths=["."],
                languages=languages,
                responsibility="Main application",
            )
        )

    return assignments


@activity.defn(name="recon-orchestrator")
def recon_orchestrator_activity(repo_root: Path | str, scan_id: str) -> list[SubsystemAssignment]:
    """Analyse the repo structure and return subsystem assignments.

    No model call — pure structural analysis using file layout and manifests.
    Returns at least one SubsystemAssignment even for empty repositories.
    """
    root = Path(repo_root).resolve()
    with suppress(RuntimeError):
        activity.heartbeat()

    # Detect languages
    languages = _detect_languages_from_root(root)
    if not languages:
        languages = ["unknown"]

    assignments = _identify_subsystems(root, languages)
    return assignments
