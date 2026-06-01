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


def _normalize_path(file_path: str) -> str:
    """Normalize a file path to repo-relative, forward-slash form."""
    return file_path.replace("\\", "/").strip("/")


def _format_span(start_line: int, end_line: int | None) -> str:
    """Format a source span as 'start:end' or 'start'."""
    if end_line is not None and end_line != start_line:
        return f"{start_line}:{end_line}"
    return str(start_line)
