"""PromptRegistry — loads and caches versioned Jinja templates from prompts/."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from jinja2 import TemplateSyntaxError, UndefinedError
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import FileSystemLoader, StrictUndefined


class TemplateNotFoundError(FileNotFoundError):
    """Raised when a requested template file does not exist in prompts/."""


@dataclass(frozen=True)
class PromptTemplateRef:
    """Immutable reference to a loaded template."""

    id: str      # "{role}/{name}"
    version: str
    sha256: str  # hex-encoded SHA-256 of the raw template bytes


@dataclass
class LoadedTemplate:
    """A compiled Jinja template with its provenance reference."""

    ref: PromptTemplateRef
    _source: str  # raw template source (not the compiled object)
    _env: SandboxedEnvironment

    def render(self, variables: dict[str, Any]) -> str:
        """Render the template with *variables*.

        Raises ``jinja2.UndefinedError`` on any missing variable (StrictUndefined).
        """
        template = self._env.from_string(self._source)
        return template.render(**variables)


class PromptRegistry:
    """Loads Jinja templates from a ``prompts/`` directory.

    Templates are stored at ``{prompts_root}/{role}/{name}.{version}.j2``.
    The registry uses ``jinja2.sandbox.SandboxedEnvironment`` with
    ``StrictUndefined`` so:
    - Undefined variables raise immediately (fail-fast).
    - SSTI via template bodies is blocked by the sandbox.

    Evidence strings must **never** be compiled as templates — they are passed
    as plain Python string variables and rendered verbatim.
    """

    def __init__(self, prompts_root: Path) -> None:
        self._root = Path(prompts_root)
        self._cache: dict[tuple[str, str, str], LoadedTemplate] = {}
        self._env = SandboxedEnvironment(
            loader=FileSystemLoader(str(self._root)),
            undefined=StrictUndefined,
            autoescape=False,
            keep_trailing_newline=True,
        )

    def load(self, role: str, name: str, version: str) -> LoadedTemplate:
        """Load and cache the template at ``{role}/{name}.{version}.j2``."""
        key = (role, name, version)
        if key in self._cache:
            return self._cache[key]

        template_path = self._root / role / f"{name}.{version}.j2"
        if not template_path.exists():
            raise TemplateNotFoundError(
                f"Prompt template not found: {template_path}  "
                f"(role={role!r}, name={name!r}, version={version!r})"
            )

        source = template_path.read_text(encoding="utf-8")
        # Validate syntax by parsing (raises TemplateSyntaxError on bad templates)
        self._env.parse(source)

        digest = sha256(source.encode("utf-8")).hexdigest()
        ref = PromptTemplateRef(id=f"{role}/{name}", version=version, sha256=digest)
        loaded = LoadedTemplate(ref=ref, _source=source, _env=self._env)
        self._cache[key] = loaded
        return loaded
