"""Deterministic finding fingerprint computation.

Fingerprints identify the logical vulnerability across scan reruns.
They are stable when the root cause is unchanged.

Fingerprint inputs:
- vuln_class: vulnerability category
- normalized file path: repo-relative, forward-slash separated
- normalized source span: start_line:end_line as string
- normalized sink or key name: the variable name or endpoint being exploited
- stable evidence kind: what kind of evidence was found

Explicitly excluded:
- scan_id (changes every run)
- timestamps (change every run)
- model output (non-deterministic)
- raw line text (fragile to whitespace changes)
- absolute local paths (machine-dependent)
- random IDs
"""

from hashlib import sha256

from quarry.schemas import VulnerabilityClass


def compute_fingerprint(
    *,
    vuln_class: VulnerabilityClass,
    file_path: str,
    start_line: int,
    end_line: int | None = None,
    key_name: str = "",
    evidence_kind: str = "",
) -> str:
    """Compute a deterministic fingerprint for a finding.

    Returns a hex-encoded SHA-256 digest of the stable inputs.
    """
    normalized_path = _normalize_path(file_path)
    span = _format_span(start_line, end_line)
    raw = f"{vuln_class.value}|{normalized_path}|{span}|{key_name}|{evidence_kind}"
    return sha256(raw.encode("utf-8")).hexdigest()


def compute_root_cause_key(
    *,
    vuln_class: VulnerabilityClass,
    file_path: str,
    sink: str = "",
) -> str:
    """Compute a stable, human-readable dedup key for a finding's root cause.

    Unlike the fingerprint, this is a readable normalized key (not hashed) used
    to group findings that share the same root cause across scans. It excludes
    scan id, timestamps, line numbers, and absolute paths.
    """
    return f"{vuln_class.value}:{_normalize_path(file_path)}:{sink}"


def compute_sink_dedup_key(
    *,
    title: str,
    sink_locator: str,
) -> str:
    """Compute the sink-locator + title dedup key (cpc D4, task 7.1).

    Keys on the *sink* (``evidence_path[0]``) plus the finding title — two
    findings whose unordered ``source_refs`` come back in different orders but
    name the same sink line and title are the same root cause. Title is
    normalized (case/whitespace-insensitive) and the locator's path is
    normalized like every other fingerprint path input. Readable, not hashed,
    so scan logs and the dedup agent can cite it.

    Returns ``sink-<locator>|<normalized title>``.
    """
    return f"sink-{_normalize_locator(sink_locator)}|{_normalize_title(title)}"


def _normalize_locator(locator: str) -> str:
    """Normalize a ``path:line`` locator to repo-relative, forward-slash form."""
    parts = locator.split(":", 1)
    path = _normalize_path(parts[0])
    if len(parts) == 2 and parts[1].strip():
        return f"{path}:{parts[1].strip()}"
    return path


def _normalize_title(title: str) -> str:
    """Normalize a title for dedup: lowercase, collapse all whitespace runs."""
    return " ".join(title.lower().split())


def _normalize_path(file_path: str) -> str:
    """Normalize a file path to repo-relative, forward-slash form."""
    return file_path.replace("\\", "/").strip("/")


def _format_span(start_line: int, end_line: int | None) -> str:
    """Format a source span as 'start:end' or 'start'."""
    if end_line is not None and end_line != start_line:
        return f"{start_line}:{end_line}"
    return str(start_line)
