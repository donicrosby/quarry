"""Binary analysis tools — read-only static inspection of repository binaries.

Six :class:`~quarry.plugin_types.ToolSpec` tools let the hunter inspect compiled
artifacts that are otherwise opaque to source-level analysis:

``file_type`` / ``extract_strings`` / ``checksec`` / ``linked_libraries`` wrap the
system ``file``, ``strings`` and ``readelf`` binaries; ``suid_sgid_detect`` and
``symlink_analysis`` read filesystem metadata directly. Every tool is read-only
and its path inputs are confined to the repository root — ``ToolRunner`` enforces
the same boundary for the agent loop, and :func:`resolve_in_repo` enforces it for
the deterministic activity that calls the tools directly.

A missing external binary raises :class:`ToolUnavailableError` so the caller can
degrade gracefully (the activity records it in the report; the loop surfaces it
to the model) rather than crashing the scan.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from quarry.plugin_types import ToolRegistry
from quarry_tools.errors import ToolSecurityError, ToolUnavailableError

_TIMEOUT_SECONDS = 10

# Roles allowed to call the binary analysis tools. ``recon``/``hunt``/``prove``
# covers the static-inspection surfaces; the deterministic activity calls the
# structured helpers directly and is not role-gated.
_ROLES = ["recon", "hunt", "prove"]

# Printable byte set used by the pure-Python strings fallback: ASCII printable
# (0x20-0x7E) plus tab (0x09). Newline (0x0A) is NOT included, so it terminates a
# sequence — matching GNU ``strings`` behaviour (which keeps tab in sequences but
# not newline).
_PRINTABLE_BYTES = frozenset(range(0x20, 0x7F)) | {0x09}

DEFAULT_MIN_STRING_LENGTH = 4

# The per-binary strings dump is capped so a large binary cannot bloat the
# report artifact; ``strings_total`` still records the full count.
STRINGS_SAMPLE_LIMIT = 100


def resolve_in_repo(path_str: str, repo_root: Path) -> Path:
    """Resolve *path_str* inside *repo_root*, raising on escape.

    Mirrors the confinement ``ToolRunner`` applies to the agent-loop path so the
    deterministic activity obeys the same boundary when it calls the tools
    directly.
    """
    candidate = Path(path_str)
    resolved = candidate.resolve() if candidate.is_absolute() else (repo_root / candidate).resolve()
    root = repo_root.resolve()
    if not resolved.is_relative_to(root):
        msg = (
            f"Path security violation: '{path_str}' resolves to '{resolved}' "
            f"which escapes the repo root '{root}'."
        )
        raise ToolSecurityError(msg)
    return resolved


def _run_command(args: list[str], repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Run *args* read-only with a bounded timeout, mapping a missing binary.

    ``FileNotFoundError`` becomes :class:`ToolUnavailableError` (the tool binary
    is absent); a timeout returns a synthetic non-zero result so callers can
    report it instead of raising out of the activity.
    """
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            cwd=str(repo_root),
        )
    except FileNotFoundError as exc:
        binary = args[0] if args else "?"
        raise ToolUnavailableError(
            f"{binary}(1) is not installed or not on PATH. "
            f"Install it with: apt-get install {_package_for(binary)} (or: brew install {binary})"
        ) from exc
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, returncode=124, stdout="", stderr="timed out")


def _package_for(binary: str) -> str:
    """Return the apt package that ships *binary* (for the install hint)."""
    if binary == "file":
        return "file"
    if binary == "strings":
        return "binutils"
    return "binutils"


def _file_description(path: Path, repo_root: Path) -> str:
    """Return ``file -b`` output for *path* (never raises for a readable file)."""
    result = _run_command(["file", "-b", str(path)], repo_root)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "file(1) failed"
        return f"[file(1) error: {detail}]"
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# file_type
# ---------------------------------------------------------------------------


class _FileType:
    name = "file_type"
    description = (
        "Determine a file's type and architecture using file(1) — e.g. "
        "'ELF 64-bit LSB pie executable, x86-64'. Read-only."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path relative to repo root."},
        },
        "required": ["path"],
    }
    roles = list(_ROLES)

    def describe(self, path: Path, repo_root: Path) -> str:
        """Structured-file-type helper: ``file -b`` text for *path*."""
        return _file_description(path, repo_root)

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        resolved = resolve_in_repo(str(inputs["path"]), repo_root)
        return self.describe(resolved, repo_root)


# ---------------------------------------------------------------------------
# extract_strings
# ---------------------------------------------------------------------------


def extract_printable_bytes(data: bytes, min_length: int) -> list[str]:
    """Pure-Python fallback: printable runs of >= *min_length* bytes.

    Printable set is ASCII 0x20-0x7E plus tab; any other byte (including newline)
    terminates the current run. The returned list preserves file order.
    """
    results: list[str] = []
    current = bytearray()
    for byte in data:
        if byte in _PRINTABLE_BYTES:
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(current.decode("ascii"))
            current.clear()
    if len(current) >= min_length:
        results.append(current.decode("ascii"))
    return results


def _extract_strings(path: Path, repo_root: Path, min_length: int) -> list[str]:
    """Extract printable strings from *path*, preferring the system ``strings``.

    Falls back to the pure-Python scan when ``strings`` is unavailable; when
    ``strings`` runs but finds nothing, an empty list is returned (not a
    fallback — the system tool is authoritative when present).
    """
    try:
        result = _run_command(["strings", "-n", str(min_length), str(path)], repo_root)
    except ToolUnavailableError:
        data = _read_bytes(path)
        return extract_printable_bytes(data, min_length)
    if result.returncode != 0:
        data = _read_bytes(path)
        return extract_printable_bytes(data, min_length)
    return [line for line in result.stdout.splitlines() if line]


def _read_bytes(path: Path) -> bytes:
    """Read *path* fully, returning empty bytes when it cannot be read."""
    try:
        return path.read_bytes()
    except OSError:
        return b""


class _ExtractStrings:
    name = "extract_strings"
    description = (
        "Extract printable ASCII/UTF-8 string sequences from a binary using "
        "strings(1) (pure-Python fallback when absent). One string per line."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path relative to repo root."},
            "min_length": {
                "type": "integer",
                "description": "Minimum string length (default 4).",
                "minimum": 1,
            },
        },
        "required": ["path"],
    }
    roles = list(_ROLES)

    def extract(self, path: Path, repo_root: Path, min_length: int) -> list[str]:
        """Structured helper: the extracted strings for *path*."""
        return _extract_strings(path, repo_root, min_length)

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        resolved = resolve_in_repo(str(inputs["path"]), repo_root)
        min_length = _min_length(inputs.get("min_length"))
        return "\n".join(self.extract(resolved, repo_root, min_length))


def _min_length(raw: Any) -> int:
    """Coerce the ``min_length`` input to a positive int (default 4)."""
    if raw is None:
        return DEFAULT_MIN_STRING_LENGTH
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MIN_STRING_LENGTH
    return value if value >= 1 else DEFAULT_MIN_STRING_LENGTH


# ---------------------------------------------------------------------------
# checksec
# ---------------------------------------------------------------------------

_PROGRAM_HEADER_RE = re.compile(r"^\s*(GNU_STACK|GNU_RELRO)\b(.*)$")
_ELF_TYPE_RE = re.compile(r"Type:\s+(\S+)")
_DT_RE = re.compile(r"\((?P<tag>[A-Z_0-9]+)\)\s+(?P<value>.*)")
_ELF_MAGIC = b"\x7fELF"


def is_elf(path: Path) -> bool:
    """True when *path* starts with the ELF magic bytes."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) == _ELF_MAGIC
    except OSError:
        return False


def _program_headers(path: Path, repo_root: Path) -> list[str] | None:
    """``readelf -lW`` output lines, or None when *path* is not ELF."""
    result = _run_command(["readelf", "-lW", str(path)], repo_root)
    if result.returncode != 0:
        return None
    return result.stdout.splitlines()


def _dynamic_section(path: Path, repo_root: Path) -> list[str] | None:
    """``readelf -dW`` output lines, or None when *path* is not ELF."""
    result = _run_command(["readelf", "-dW", str(path)], repo_root)
    if result.returncode != 0:
        return None
    return result.stdout.splitlines()


def _dynamic_tags(lines: list[str]) -> list[tuple[str, str]]:
    """Parse ``(TAG) value`` pairs out of a ``readelf -dW`` section."""
    tags: list[tuple[str, str]] = []
    for line in lines:
        match = _DT_RE.search(line)
        if match is not None:
            tags.append((match.group("tag"), match.group("value").strip()))
    return tags


def build_checksec_report(path: Path, repo_root: Path) -> dict[str, Any]:
    """Structured hardening audit for *path*.

    Returns ``{"error": ...}`` for a non-ELF file; otherwise the RELRO / NX /
    PIE / canary / RPATH / RUNPATH fields described in the binary-analysis spec.
    """
    headers = _program_headers(path, repo_root)
    if headers is None:
        return {"error": "not an ELF file"}

    has_relro = False
    nx = "Disabled"
    for line in headers:
        match = _PROGRAM_HEADER_RE.match(line)
        if match is None:
            continue
        segment, rest = match.group(1), match.group(2)
        tokens = rest.split()
        # Trailing columns are: ... MemSiz Flg Align — flags are second-to-last.
        flags = tokens[-2] if len(tokens) >= 2 else ""
        if segment == "GNU_RELRO":
            has_relro = True
        elif segment == "GNU_STACK":
            nx = "Disabled" if "E" in flags else "Enabled"

    dynamic = _dynamic_section(path, repo_root)
    tags = _dynamic_tags(dynamic) if dynamic is not None else []
    bind_now = any(tag == "BIND_NOW" for tag, _ in tags) or any(
        tag in ("FLAGS", "FLAGS_1") and "NOW" in value for tag, value in tags
    )

    if has_relro and bind_now:
        relro = "Full"
    elif has_relro:
        relro = "Partial"
    else:
        relro = "None"

    elf_type = _elf_type(path, repo_root)
    pie = "Enabled" if elf_type == "DYN" else "Disabled"

    dynamic_symbols = _run_command(["readelf", "--dyn-syms", "-W", str(path)], repo_root)
    canary = "Enabled" if "__stack_chk_fail" in dynamic_symbols.stdout else "Disabled"

    rpath = _first_tag(tags, "RPATH")
    runpath = _first_tag(tags, "RUNPATH")

    return {
        "relro": relro,
        "nx": nx,
        "pie": pie,
        "canary": canary,
        "rpath": rpath,
        "runpath": runpath,
    }


def _elf_type(path: Path, repo_root: Path) -> str | None:
    """Return the ELF ``e_type`` string (e.g. ``DYN``), or None."""
    result = _run_command(["readelf", "-hW", str(path)], repo_root)
    if result.returncode != 0:
        return None
    match = _ELF_TYPE_RE.search(result.stdout)
    return match.group(1) if match is not None else None


def _first_tag(tags: list[tuple[str, str]], tag: str) -> str | None:
    """First value for *tag*, extracting a ``[...]`` payload when present."""
    for candidate, value in tags:
        if candidate != tag:
            continue
        return _bracket_value(value) or value
    return None


class _Checksec:
    name = "checksec"
    description = (
        "Audit an ELF binary's hardening: RELRO (Full/Partial/None), NX, PIE, "
        "stack canary, and RPATH/RUNPATH. Wraps readelf(1). Read-only."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "ELF file path relative to repo root."},
        },
        "required": ["path"],
    }
    roles = list(_ROLES)

    def audit(self, path: Path, repo_root: Path) -> dict[str, Any]:
        """Structured helper: the hardening report for *path*."""
        return build_checksec_report(path, repo_root)

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        resolved = resolve_in_repo(str(inputs["path"]), repo_root)
        report = self.audit(resolved, repo_root)
        if "error" in report:
            return f"[checksec: {report['error']}]"
        return "\n".join(
            [
                f"RELRO: {report['relro']}",
                f"NX: {report['nx']}",
                f"PIE: {report['pie']}",
                f"Canary: {report['canary']}",
                f"RPATH: {report['rpath'] or '(none)'}",
                f"RUNPATH: {report['runpath'] or '(none)'}",
            ]
        )


# ---------------------------------------------------------------------------
# linked_libraries
# ---------------------------------------------------------------------------


def _bracket_value(value: str) -> str | None:
    """Extract the first ``[...]`` payload from a ``readelf -dW`` value field."""
    match = re.search(r"\[([^\]]*)\]", value)
    return match.group(1) if match is not None else None


def list_linked_libraries(path: Path, repo_root: Path) -> dict[str, Any]:
    """Structured linked-library inventory for *path*.

    Returns ``{"error": ...}`` for a non-ELF file, ``{"dynamic": False,
    "libraries": []}`` for a statically linked binary (no dynamic section), and
    ``{"dynamic": True, "libraries": [soname, ...]}`` otherwise.
    """
    dynamic = _dynamic_section(path, repo_root)
    if dynamic is None:
        return {"error": "not an ELF file"}
    joined = "\n".join(dynamic)
    if "no dynamic section" in joined:
        return {"dynamic": False, "libraries": []}
    libraries = [
        soname
        for tag, value in _dynamic_tags(dynamic)
        if tag == "NEEDED" and (soname := _bracket_value(value)) is not None
    ]
    if not libraries:
        return {"dynamic": False, "libraries": []}
    return {"dynamic": True, "libraries": libraries}


class _LinkedLibraries:
    name = "linked_libraries"
    description = (
        "List the shared libraries an ELF binary links against (readelf -dW "
        "NEEDED sonames). Reports none for a static binary. Read-only."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "ELF file path relative to repo root."},
        },
        "required": ["path"],
    }
    roles = list(_ROLES)

    def list_libraries(self, path: Path, repo_root: Path) -> dict[str, Any]:
        """Structured helper: linked libraries for *path*."""
        return list_linked_libraries(path, repo_root)

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        resolved = resolve_in_repo(str(inputs["path"]), repo_root)
        report = self.list_libraries(resolved, repo_root)
        if "error" in report:
            return f"[linked_libraries: {report['error']}]"
        libraries = report["libraries"]
        if not libraries:
            return "no dynamic libraries (statically linked)"
        return "\n".join(str(library) for library in libraries)


# ---------------------------------------------------------------------------
# suid_sgid_detect
# ---------------------------------------------------------------------------


def detect_suid_sgid(repo_root: Path) -> list[dict[str, str]]:
    """Return every regular file under *repo_root* with a setuid/setgid bit.

    Each hit is ``{"path": <repo-relative>, "mode": <4-digit octal>}``. Symlinks
    are skipped (they are not regular files); a setgid *directory* is skipped too.
    Results are sorted by path for determinism.
    """
    findings: list[dict[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                findings.append(
                    {
                        "path": _relpath(path, repo_root),
                        "mode": format(info.st_mode & 0o7777, "04o"),
                    }
                )
    findings.sort(key=lambda finding: finding["path"])
    return findings


def _relpath(path: Path, repo_root: Path) -> str:
    """Repo-relative POSIX path for *path* WITHOUT following symlinks.

    ``Path.resolve()`` follows a symlink to its target, which would misreport a
    link as its destination; ``relative_to`` on the walked path preserves the
    link's own name.
    """
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        try:
            return path.relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()


class _SuidSgidDetect:
    name = "suid_sgid_detect"
    description = (
        "Walk the repo root and report every regular file with the setuid or "
        "setgid bit set, with its repo-relative path and octal mode."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
    }
    roles = list(_ROLES)

    def scan(self, repo_root: Path) -> list[dict[str, str]]:
        """Structured helper: the SUID/sgid findings under *repo_root*."""
        return detect_suid_sgid(repo_root)

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        findings = self.scan(repo_root)
        if not findings:
            return "no setuid/setgid files"
        return "\n".join(f"{hit['path']} ({hit['mode']})" for hit in findings)


# ---------------------------------------------------------------------------
# symlink_analysis
# ---------------------------------------------------------------------------


def analyze_links(repo_root: Path) -> dict[str, list[dict[str, Any]]]:
    """Return symlinks and hardlink groups under *repo_root*.

    ``symlinks`` is a list of ``{"path", "target"}`` where ``target`` is the
    target exactly as the link records it (``os.readlink``) — resolving it to an
    absolute path would embed machine-specific paths in the persisted report, so
    the report stays reproducible. ``hardlinks`` is a list of ``{"paths": [...]}``
    for inode groups shared by more than one regular file: hard links are
    DETECTED by comparing ``(st_dev, st_ino)``, but the raw inode/device numbers
    are not reported — they differ across checkouts of the same repo state, which
    would break the report's determinism. Both lists are sorted.
    """
    symlinks: list[dict[str, Any]] = []
    inode_paths: dict[tuple[int, int], list[str]] = {}

    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames.sort()
        for name in list(dirnames) + sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                try:
                    target = os.readlink(path)
                except OSError:
                    continue
                symlinks.append({"path": _relpath(path, repo_root), "target": str(target)})
                continue
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                key = (info.st_dev, info.st_ino)
                inode_paths.setdefault(key, []).append(_relpath(path, repo_root))

    groups: list[list[str]] = [sorted(paths) for paths in inode_paths.values() if len(paths) > 1]
    groups.sort()
    hardlinks: list[dict[str, Any]] = [{"paths": group} for group in groups]
    symlinks.sort(key=lambda link: link["path"])
    return {"symlinks": symlinks, "hardlinks": hardlinks}


class _SymlinkAnalysis:
    name = "symlink_analysis"
    description = (
        "Walk the repo root and report every symbolic link (with target) and "
        "hard-link group (inode shared by multiple paths). Read-only."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
    }
    roles = list(_ROLES)

    def scan(self, repo_root: Path) -> dict[str, list[dict[str, Any]]]:
        """Structured helper: the symlink/hardlink findings under *repo_root*."""
        return analyze_links(repo_root)

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        report = self.scan(repo_root)
        lines = [f"symlink: {link['path']} -> {link['target']}" for link in report["symlinks"]]
        for group in report["hardlinks"]:
            paths = ", ".join(str(path) for path in group["paths"])
            lines.append(f"hardlink: {paths}")
        if not lines:
            return "no symlinks or hardlinks"
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# registry entry
# ---------------------------------------------------------------------------

FILE_TYPE_TOOL = _FileType()
EXTRACT_STRINGS_TOOL = _ExtractStrings()
CHECKSEC_TOOL = _Checksec()
LINKED_LIBRARIES_TOOL = _LinkedLibraries()
SUID_SGID_TOOL = _SuidSgidDetect()
SYMLINK_ANALYSIS_TOOL = _SymlinkAnalysis()

BINARY_ANALYSIS_TOOLS: ToolRegistry = {
    FILE_TYPE_TOOL.name: FILE_TYPE_TOOL,  # type: ignore[dict-item]
    EXTRACT_STRINGS_TOOL.name: EXTRACT_STRINGS_TOOL,  # type: ignore[dict-item]
    CHECKSEC_TOOL.name: CHECKSEC_TOOL,  # type: ignore[dict-item]
    LINKED_LIBRARIES_TOOL.name: LINKED_LIBRARIES_TOOL,  # type: ignore[dict-item]
    SUID_SGID_TOOL.name: SUID_SGID_TOOL,  # type: ignore[dict-item]
    SYMLINK_ANALYSIS_TOOL.name: SYMLINK_ANALYSIS_TOOL,  # type: ignore[dict-item]
}
