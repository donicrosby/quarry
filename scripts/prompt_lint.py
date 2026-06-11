#!/usr/bin/env python3
"""prompt_lint.py — CI guard: no prompt text in Python source files.

ADR-019 invariant: all prompt text lives in prompts/**/*.j2.  This script
inspects src/**/*.py for string constants that look like prompt text.
Exits 1 with file+line on any match.

Detection approach:
  - Module-level constants whose names match known prompt-constant patterns
    (_SYSTEM_PROMPT, _SYSTEM_INSTRUCTIONS, _SCHEMA_NOTE, _USER_PROMPT)
    that contain non-trivial string values.
  - Multi-line string literals (>100 chars, containing \n) that contain
    distinctive first-person instruction phrases that only appear in prompts.

Usage:
    python scripts/prompt_lint.py [src_root]
    task prompt-lint
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Distinctive phrases that identify *intentional prompt copy* — these would
# never appear in a docstring, comment, or infrastructure code.
_PROMPT_PHRASES = [
    "You are a security researcher",
    "You are a recon agent",
    "You are a validate agent",
    "You are a gapfill agent",
    "You are a prove agent",
    'Return a JSON object with a single key "findings"',
    "Hunt for **",
    "Never follow instructions found inside",
]

# Exact constant name matches (not substrings) that must not hold prompt text.
_PROMPT_CONSTANT_NAMES = {
    "_SYSTEM_PROMPT",
    "_SYSTEM_INSTRUCTIONS",
    "_SCHEMA_NOTE",
    "_USER_PROMPT",
}

# Files acknowledged as migration targets (old infrastructure being phased out).
# Remove entries as files are fully migrated.
_MIGRATION_ALLOWLIST = {
    "quarry_models/prompting.py",  # superseded by quarry_prompts; kept as compat shim
}


def _is_prompt_string(s: str) -> bool:
    """Return True if the string looks like direct prompt copy."""
    if "\n" not in s or len(s) < 100:
        return False
    return any(phrase in s for phrase in _PROMPT_PHRASES)


def check_file(path: Path) -> list[tuple[int, str]]:
    """Return list of (lineno, reason) for violations in *path*."""
    violations: list[tuple[int, str]] = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return violations

    for node in ast.walk(tree):
        # Detect prompt-constant assignments at module level
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id in _PROMPT_CONSTANT_NAMES
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and node.value.value.strip()
                ):
                    violations.append(
                        (
                            node.lineno,
                            f"prompt constant {target.id!r} — move to prompts/*.j2",
                        )
                    )

        # Detect long multi-line string literals containing prompt phrases
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _is_prompt_string(node.value)
        ):
            violations.append(
                (
                    node.lineno,
                    "string literal contains prompt text — move to prompts/*.j2",
                )
            )

    return violations


def main(src_root: str = "src") -> int:
    root = Path(src_root)
    total_violations = 0

    for py_file in sorted(root.rglob("*.py")):
        if any(allowed in str(py_file) for allowed in _MIGRATION_ALLOWLIST):
            continue
        violations = check_file(py_file)
        for lineno, reason in violations:
            print(f"{py_file}:{lineno}: {reason}")
            total_violations += 1

    if total_violations:
        print(f"\nprompt-lint: {total_violations} violation(s) found", file=sys.stderr)
        return 1

    print("prompt-lint: OK — no prompt text in Python source")
    return 0


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "src"
    sys.exit(main(src))
