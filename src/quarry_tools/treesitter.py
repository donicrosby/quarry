"""treesitter_query extension tool.

Runs a tree-sitter S-expression query against all source files of a given
language within the repository scope.  Supported languages this week:
javascript, c, go.

Unsupported languages raise ToolUnavailableError with a message directing
the caller to use the builtin 'grep' tool instead.
"""

from __future__ import annotations

import signal
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from quarry_tools.errors import ToolUnavailableError

_TIMEOUT_SECONDS = 15

_LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "javascript": [".js", ".mjs", ".cjs", ".jsx"],
    "c": [".c", ".h"],
    "go": [".go"],
}


def _load_language(language: str) -> Any:
    """Return the tree-sitter Language object for a supported language."""
    import tree_sitter

    if language == "javascript":
        import tree_sitter_javascript as _ts_js
        return tree_sitter.Language(_ts_js.language())
    if language == "c":
        import tree_sitter_c as _ts_c
        return tree_sitter.Language(_ts_c.language())
    if language == "go":
        import tree_sitter_go as _ts_go
        return tree_sitter.Language(_ts_go.language())

    raise ToolUnavailableError(
        f"unsupported language: {language!r}; use grep instead"
    )


@contextmanager
def _timeout(seconds: int) -> Any:
    """Context manager that raises TimeoutError after *seconds*."""

    def _handler(signum: int, frame: Any) -> None:
        raise TimeoutError(f"treesitter_query timed out after {seconds}s")

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _query_file(
    ts_lang: Any,
    query_obj: Any,
    file_path: Path,
) -> list[dict[str, Any]]:
    """Parse *file_path* and run *query_obj* against it, returning match dicts."""
    import tree_sitter

    source = file_path.read_bytes()
    parser = tree_sitter.Parser(ts_lang)
    tree = parser.parse(source)

    cursor = tree_sitter.QueryCursor(query_obj)
    captures = cursor.captures(tree.root_node)

    results: list[dict[str, Any]] = []
    for _capture_name, nodes in captures.items():
        for node in nodes:
            start_row, _ = node.start_point
            end_row, _ = node.end_point
            text = node.text.decode("utf-8", errors="replace") if node.text else ""
            results.append(
                {
                    "file": str(file_path),
                    "start_line": start_row + 1,
                    "end_line": end_row + 1,
                    "text": text,
                }
            )
    return results


class _TreeSitterTool:
    name = "treesitter_query"
    description = (
        "Run a tree-sitter S-expression query over source files of a given language "
        "within the repository scope. Returns matched nodes with file path, line range, "
        "and matched text. Supported languages: javascript, c, go. "
        "For other languages raise ToolUnavailableError and use 'grep' instead."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "language": {
                "type": "string",
                "description": "Source language: 'javascript', 'c', or 'go'.",
            },
            "query": {
                "type": "string",
                "description": "Tree-sitter S-expression query string.",
            },
            "scope": {
                "type": ["string", "null"],
                "description": "Sub-path within the repo to restrict the search (optional).",
            },
        },
        "required": ["language", "query"],
    }
    roles = ["hunt", "validate", "prove"]

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        import tree_sitter

        language: str = inputs["language"].lower()
        query_str: str = inputs["query"]
        scope: str | None = inputs.get("scope")

        # Raises ToolUnavailableError for unsupported languages
        ts_lang = _load_language(language)

        target = repo_root / scope if scope else repo_root
        try:
            target = target.resolve()
            target.relative_to(repo_root.resolve())
        except ValueError as exc:
            from quarry_tools.errors import ToolSecurityError
            raise ToolSecurityError(f"scope '{scope}' escapes repo root") from exc

        extensions = _LANGUAGE_EXTENSIONS[language]
        source_files = [
            p for p in target.rglob("*")
            if p.is_file() and p.suffix in extensions
        ]

        if not source_files:
            return f"(no {language} files found in scope)"

        try:
            query_obj = tree_sitter.Query(ts_lang, query_str)
        except Exception as exc:
            return f"[treesitter_query] invalid query: {exc}"

        all_matches: list[dict[str, Any]] = []
        try:
            with _timeout(_TIMEOUT_SECONDS):
                for file_path in source_files:
                    try:
                        matches = _query_file(ts_lang, query_obj, file_path)
                        all_matches.extend(matches)
                    except Exception:
                        pass
        except TimeoutError as exc:
            return f"[treesitter_query timed out after {_TIMEOUT_SECONDS}s]"

        if not all_matches:
            return f"(no matches for query in {language} files)"

        lines: list[str] = []
        for m in all_matches:
            rel = Path(m["file"]).relative_to(repo_root.resolve()) if repo_root.resolve() in Path(m["file"]).parents else m["file"]
            snippet = m["text"].replace("\n", " ")[:80]
            lines.append(f"{rel}:{m['start_line']}-{m['end_line']}: {snippet}")

        return "\n".join(lines)


TREESITTER_TOOL = _TreeSitterTool()
