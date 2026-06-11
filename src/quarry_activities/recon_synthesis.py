"""Recon synthesis activity.

Merges subsystem results into an ArchitectureDoc. Infers primary_language
(most frequent across subsystems) and repo_type from entry point kinds.
"""

from __future__ import annotations

from collections import Counter
from contextlib import suppress
from pathlib import Path
from typing import Any

from temporalio import activity

from quarry.schemas import ArchitectureDoc, EntryPoint, Subsystem, TrustBoundary


def _infer_repo_type(entry_points: list[EntryPoint]) -> str:
    """Infer repo_type from the kinds of entry points present."""
    kinds = {ep.kind for ep in entry_points}
    if "fuzz_harness" in kinds:
        return "fuzzing"
    if "http_handler" in kinds:
        return "web_service"
    if "cli_arg" in kinds or "main" in kinds:
        return "cli"
    return "mixed"


def _primary_language(subsystems: list[Subsystem]) -> str:
    """Return the most frequently appearing language across all subsystems."""
    counter: Counter[str] = Counter()
    for sub in subsystems:
        for lang in sub.languages:
            counter[lang] += 1
    if not counter:
        return "unknown"
    return counter.most_common(1)[0][0]


def _deduplicate_trust_boundaries(subsystems: list[Subsystem]) -> list[TrustBoundary]:
    """Collect trust boundaries from all subsystems, deduplicating by name."""
    seen: dict[str, TrustBoundary] = {}
    for sub in subsystems:
        for tb in getattr(sub, "trust_boundaries", []):
            if tb.name not in seen:
                seen[tb.name] = tb
    return list(seen.values())


def render_architecture_markdown(doc: ArchitectureDoc, scan_id: str = "") -> str:
    """Render an ArchitectureDoc as a human-readable markdown report.

    Gives a reader the program's attack-surface map: repo type/languages, every
    entry point, each subsystem's responsibility, and recon's per-class candidate
    sink/source inventory (the `notes` buckets).
    """
    title = f"# Architecture map — {scan_id}" if scan_id else "# Architecture map"
    out: list[str] = [
        title,
        "",
        f"- **Repository type:** {doc.repo_type}",
        f"- **Primary language:** {doc.primary_language}",
        f"- **Languages:** {', '.join(doc.repo_languages) or 'unknown'}",
        f"- **Attack surface:** {doc.attack_surface_summary or '(none)'}",
        "",
        "## Entry points",
        "",
    ]
    if doc.entry_points:
        out += ["| File | Function | Kind |", "|---|---|---|"]
        out += [f"| {ep.file} | {ep.function} | {ep.kind} |" for ep in doc.entry_points]
    else:
        out.append("_None mapped._")
    out += ["", "## Subsystems", ""]
    for sub in doc.subsystems:
        out += [
            f"### {sub.name}",
            f"- **Paths:** {', '.join(sub.root_paths) or '.'}",
            f"- **Languages:** {', '.join(sub.languages) or 'unknown'}",
            f"- **Responsibility:** {sub.responsibility}",
            f"- **Entry points:** {len(sub.entry_points)}",
        ]
        if sub.notes:
            out += [
                "",
                "**Candidate sinks & input sources (recon notes):**",
                "",
                "```",
                sub.notes,
                "```",
            ]
        out.append("")
    if doc.trust_boundaries:
        out += [f"## Trust boundaries\n\n_{len(doc.trust_boundaries)} recorded._", ""]
    return "\n".join(out) + "\n"


@activity.defn(name="recon-synthesis")
def recon_synthesis_activity(
    # list[Any]: Temporal may hand subsystems across as dicts, not Subsystem objects;
    # the comprehension below coerces them, so both branches are load-bearing.
    subsystems: list[Any],
    repo_root: Path | str,
    scan_id: str,
    output_dir: str | None = None,
) -> ArchitectureDoc:
    """Merge subsystem results into an ArchitectureDoc.

    When *output_dir* is given, also writes a human-readable architecture report
    to ``<output_dir>/reports/<scan_id>-architecture.md`` so the attack-surface
    map is findable on disk right after recon.
    """
    with suppress(RuntimeError):
        activity.heartbeat()

    # Temporal may hand subsystems across as dicts (deserialised payloads) rather
    # than Subsystem objects; coerce defensively like the sibling activities do.
    subsystems = [
        s if isinstance(s, Subsystem) else Subsystem.model_validate(s) for s in subsystems
    ]

    # Collect all entry points from all subsystems
    all_entry_points: list[EntryPoint] = []
    all_languages: list[str] = []
    for sub in subsystems:
        all_entry_points.extend(sub.entry_points)
        all_languages.extend(sub.languages)

    # Unique languages (preserve order of first occurrence)
    seen_langs: set[str] = set()
    repo_languages: list[str] = []
    for lang in all_languages:
        if lang not in seen_langs:
            repo_languages.append(lang)
            seen_langs.add(lang)

    primary_lang = _primary_language(subsystems)
    repo_type = _infer_repo_type(all_entry_points)
    trust_boundaries = _deduplicate_trust_boundaries(subsystems)

    # Simple attack-surface summary
    entry_kinds = Counter(ep.kind for ep in all_entry_points)
    summary_parts = [f"{count} {kind}" for kind, count in entry_kinds.most_common()]
    if summary_parts:
        attack_surface_summary = f"Entry points: {', '.join(summary_parts)}."
    else:
        attack_surface_summary = "No entry points detected."

    doc = ArchitectureDoc(
        repo_languages=repo_languages or ["unknown"],
        primary_language=primary_lang,
        repo_type=repo_type,
        subsystems=subsystems,
        entry_points=all_entry_points,
        trust_boundaries=trust_boundaries,
        build_commands=[],
        attack_surface_summary=attack_surface_summary,
        transcript_refs=[scan_id],
    )

    # Write the human-readable architecture report to disk (best-effort; never
    # fail the scan over the report).
    if output_dir:
        with suppress(OSError):
            report_path = Path(output_dir) / "reports" / f"{scan_id}-architecture.md"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(render_architecture_markdown(doc, scan_id), encoding="utf-8")

    return doc
