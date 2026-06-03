"""Recon synthesis activity.

Merges subsystem results into an ArchitectureDoc. Infers primary_language
(most frequent across subsystems) and repo_type from entry point kinds.
"""

from __future__ import annotations

from collections import Counter
from contextlib import suppress
from pathlib import Path

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


@activity.defn(name="recon-synthesis")
def recon_synthesis_activity(
    subsystems: list[Subsystem],
    repo_root: Path | str,
    scan_id: str,
) -> ArchitectureDoc:
    """Merge subsystem results into an ArchitectureDoc."""
    with suppress(RuntimeError):
        activity.heartbeat()

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

    return ArchitectureDoc(
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
