"""build_prompt — the sole chokepoint for assembling model message lists.

See ADR-019: evidence strings are passed as data (never compiled as Jinja
templates), scrubbed via scrub() before render, and wrapped in <target_content>
fences by the evidence.j2 envelope macro — the only place that fence appears.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from quarry_models.redaction import scrub
from quarry_models.types import ModelMessage
from quarry_prompts.registry import LoadedTemplate, PromptRegistry, PromptTemplateRef

# Sentinel markers emitted by _envelope/*.j2 templates to delimit the four parts.
_SENTINEL_RE = re.compile(r"<!-- QUARRY:PART:(\w+) -->")

_PROVENANCE_HEADER_START = "# QUARRY PROMPT PROVENANCE"
_PROVENANCE_HEADER_END = "# END QUARRY PROMPT PROVENANCE"


@dataclass
class RenderedPrompt:
    """Result of build_prompt: messages, per-part hashes, and template provenance."""

    messages: list[ModelMessage]
    ref: PromptTemplateRef
    part_hashes: dict[str, str]  # part_name -> sha256 hex
    evidence_hashes: list[str]  # sha256 of each scrubbed evidence chunk
    header_yaml: str            # YAML provenance front-matter (prepended to system msg)
    scrubber_hits: int = 0


def _hash(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _split_by_sentinels(rendered: str) -> dict[str, str]:
    """Split rendered template text into named parts using QUARRY:PART: sentinels.

    Everything before the first sentinel is discarded.  Each sentinel starts a
    new part that runs until the next sentinel or end-of-string.
    """
    parts: dict[str, str] = {}
    matches = list(_SENTINEL_RE.finditer(rendered))
    for i, match in enumerate(matches):
        part_name = match.group(1)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(rendered)
        parts[part_name] = rendered[start:end].strip()
    return parts


def _build_header(ref: PromptTemplateRef, part_hashes: dict[str, str], evidence_hashes: list[str]) -> str:
    lines = [
        _PROVENANCE_HEADER_START,
        f"template_id: {ref.id}",
        f"template_version: {ref.version}",
        f"template_sha256: {ref.sha256}",
    ]
    for name, h in part_hashes.items():
        lines.append(f"{name}_hash: {h}")
    if evidence_hashes:
        lines.append("evidence_hashes:")
        for eh in evidence_hashes:
            lines.append(f"  - {eh}")
    lines.append(_PROVENANCE_HEADER_END)
    return "\n".join(lines)


def strip_provenance_header(text: str) -> tuple[dict[str, str], str]:
    """Strip the YAML provenance header from a system message.

    Returns ``(header_dict, body_text)``.  If no header is present, returns
    ``({}, text)`` unchanged.
    """
    start_marker = _PROVENANCE_HEADER_START
    end_marker = _PROVENANCE_HEADER_END

    if start_marker not in text:
        return {}, text

    start_idx = text.index(start_marker)
    end_idx = text.index(end_marker) + len(end_marker)
    header_text = text[start_idx:end_idx]
    body = (text[:start_idx] + text[end_idx:]).strip()

    # Parse the YAML-like header into a dict
    header_dict: dict[str, str] = {}
    for line in header_text.splitlines():
        if ":" in line and not line.startswith("#"):
            k, _, v = line.partition(":")
            header_dict[k.strip()] = v.strip()

    return header_dict, body


def build_prompt(
    registry: PromptRegistry,
    role: str,
    name: str,
    version: str,
    variables: dict[str, Any],
) -> RenderedPrompt:
    """Render a prompt template and return a RenderedPrompt.

    Evidence strings in ``variables["evidence_chunks"]`` (if present) are
    passed through ``scrub()`` before render.  They are Jinja context values
    (plain strings), **not** compiled as Jinja templates.  This prevents SSTI
    regardless of their content.

    The returned ``RenderedPrompt.messages`` is the canonical list passed to
    ``run_agent_loop``.  The system message is prefixed with a YAML provenance
    header that the ``ModelClient`` dispatch path strips before sending to the
    provider.
    """
    template: LoadedTemplate = registry.load(role, name, version)

    # Scrub evidence chunks before they enter the render context.
    raw_chunks: list[str] = list(variables.get("evidence_chunks", []))
    scrubbed_chunks: list[str] = []
    evidence_hashes: list[str] = []
    total_scrubber_hits = 0

    for chunk in raw_chunks:
        result = scrub(chunk)
        scrubbed_chunks.append(result.text)
        evidence_hashes.append(_hash(result.text))
        total_scrubber_hits += result.hits

    render_vars = {**variables, "evidence_chunks": scrubbed_chunks}
    rendered = template.render(render_vars)

    parts = _split_by_sentinels(rendered)
    part_hashes = {name: _hash(text) for name, text in parts.items()}

    header = _build_header(template.ref, part_hashes, evidence_hashes)

    # Assemble messages.
    # Convention: "system" part → system role; everything else → user role messages.
    system_text = parts.get("system", "")
    developer_text = parts.get("developer", "")
    evidence_text = parts.get("evidence", "")
    schema_text = parts.get("output_schema", "")

    user_parts = [p for p in [developer_text, evidence_text, schema_text] if p]
    user_text = "\n\n".join(user_parts)

    messages: list[ModelMessage] = [
        ModelMessage(role="system", content=f"{header}\n{system_text}"),
        ModelMessage(role="user", content=user_text),
    ]

    return RenderedPrompt(
        messages=messages,
        ref=template.ref,
        part_hashes=part_hashes,
        evidence_hashes=evidence_hashes,
        header_yaml=header,
        scrubber_hits=total_scrubber_hits,
    )
