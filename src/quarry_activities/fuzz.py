"""Deterministic, non-agentic fuzzing harness (C5 fuzzing-harness).

A ``fuzz`` pass builds a target from its recon-sourced ``BuildCommand``, mutates
the entry point's attacker-controlled ``args`` channel, runs each mutant through
a :class:`~quarry_activities.sandbox.SandboxBackend`, classifies the outcome
(signal death / sanitizer report / boundary / plain non-zero) and dedups crashes
by output hash so one unique crash yields one candidate.

Design notes
------------

* **No model calls.**  Nothing here touches ``ModelClient``; a pass is pure
  plumbing over the sandbox and the seed.
* **Deterministic.**  ``generate_mutants`` derives its whole sequence from
  ``random.Random(seed)`` in a fixed strategy order, so the same seed, corpus,
  dictionary and binary produce the same ordered run sequence.
* **Built-binary execution path (tasks.md 1).**  ``_COMMAND_ALLOWLIST`` does not
  admit arbitrary built binaries, so each mutated invocation is run through
  ``sh -c 'exec "$0" "$@"' <binary> <argv...>`` — ``sh`` IS on the allowlist,
  and the mutated input is passed as a literal argv element (``"$@"``), never
  interpolated into a shell string.  Execution therefore always goes through
  ``SandboxBackend``/``_validate_command`` and never bypasses either.
* **Backend-aware crash oracle (tasks.md 4).**  Tier-1 proc returns negative exit
  codes on rlimit kills; Tier-2 ContainerSandbox passes docker's ``128+N``
  verbatim.  Both are decoded to a signal number, then classified: SIGKILL /
  SIGXCPU (RLIMIT_CPU) and SIGABRT (RLIMIT_AS, no sanitizer) are *boundary*
  outcomes, not crashes; SIGSEGV/SIGBUS are crashes; any ASan/UBSan report is a
  crash regardless of exit code.
"""

from __future__ import annotations

import hashlib
import random
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from temporalio import activity

from quarry.schemas import (
    ArtifactKind,
    BuildCommand,
    EnvProfile,
    RedactionStatus,
    SandboxExecSpec,
)
from quarry_activities.inputs import FuzzCrash, FuzzResult, FuzzSpec
from quarry_activities.sandbox import (
    HARD_TIMEOUT_SECONDS,
    SandboxBackend,
    SandboxResult,
    ToolSecurityError,
)
from quarry_activities.sandbox_exec import build_sandbox_backend
from quarry_artifacts.store import ArtifactStore, build_artifact_store
from quarry_models.redaction import Scrubber

# ---------------------------------------------------------------------------
# Budgets / defaults
# ---------------------------------------------------------------------------

#: Hard cap on total runs in one pass, regardless of ``FuzzSpec.run_budget``.
MAX_RUNS: int = 512

#: Wall-clock cap on a single build command.
BUILD_TIMEOUT_SECONDS: int = 300

#: Mutation strategies, applied round-robin so a budget >= 4 exercises each.
MUTATION_STRATEGIES: tuple[str, ...] = ("bit_flip", "byte_insert", "byte_delete", "dictionary")

#: Default dictionary: format strings, path traversal, shell metacharacters.
DEFAULT_DICTIONARY: tuple[str, ...] = (
    "%s%s%s%s",
    "%n",
    "%s%n%x",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    ";id",
    "|id",
    "&&id",
    "$(id)",
    "`id`",
    "' OR '1'='1",
    "\x00",
)

#: Basename the built binary is staged under inside the sandbox working dir.
STAGED_BINARY_NAME: str = "target"


# ---------------------------------------------------------------------------
# Mutation engine (tasks.md 3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutationRecord:
    """One planned mutant: the input to append and the strategy that produced it."""

    run_index: int
    strategy: str
    mutated_input: str
    seed: int


_PRINTABLE_BYTES: tuple[int, ...] = tuple(range(0x20, 0x7F))


def _apply_bit_flip(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return data
    index = rng.randrange(len(data))
    bit = 1 << rng.randrange(8)
    out = bytearray(data)
    out[index] ^= bit
    return bytes(out)


def _apply_byte_insert(data: bytes, rng: random.Random) -> bytes:
    index = rng.randrange(len(data) + 1)
    char = rng.choice(_PRINTABLE_BYTES)
    return data[:index] + bytes([char]) + data[index:]


def _apply_byte_delete(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return data
    index = rng.randrange(len(data))
    return data[:index] + data[index + 1 :]


def _apply_dictionary(data: bytes, rng: random.Random, dictionary: Sequence[str]) -> bytes:
    token = rng.choice(tuple(dictionary)).encode("utf-8", errors="replace")
    if not data or rng.random() < 0.5:
        index = rng.randrange(len(data) + 1)
        return data[:index] + token + data[index:]
    start = rng.randrange(len(data))
    end = rng.randrange(start, len(data)) + 1
    return data[:start] + token + data[end:]


def _mutate_once(
    strategy: str,
    data: bytes,
    rng: random.Random,
    dictionary: Sequence[str],
) -> bytes:
    if strategy == "bit_flip":
        return _apply_bit_flip(data, rng)
    if strategy == "byte_insert":
        return _apply_byte_insert(data, rng)
    if strategy == "byte_delete":
        return _apply_byte_delete(data, rng)
    return _apply_dictionary(data, rng, dictionary)


def generate_mutants(
    seed_input: str,
    *,
    count: int,
    seed: int,
    dictionary: Sequence[str] = (),
) -> list[MutationRecord]:
    """Return *count* mutants deterministically derived from *seed_input*.

    Strategies are applied round-robin, so any ``count >= 4`` applies every
    strategy at least once (requirement ``each-strategy-is-applied``).  The
    caller-supplied *dictionary* is used when non-empty, else the default.
    """
    active_dictionary = tuple(dictionary) if dictionary else DEFAULT_DICTIONARY
    rng = random.Random(seed)
    base = seed_input.encode("utf-8", errors="replace")
    records: list[MutationRecord] = []
    for index in range(max(0, count)):
        strategy = MUTATION_STRATEGIES[index % len(MUTATION_STRATEGIES)]
        raw = _mutate_once(strategy, base, rng, active_dictionary)
        # The argv channel cannot carry an embedded NUL (execve rejects it), so a
        # mutated NUL byte is dropped rather than smuggled into the invocation.
        raw = raw.replace(b"\x00", b"")
        records.append(
            MutationRecord(
                run_index=index,
                strategy=strategy,
                mutated_input=raw.decode("utf-8", errors="replace"),
                seed=seed,
            )
        )
    return records


# ---------------------------------------------------------------------------
# Crash classification (tasks.md 4)
# ---------------------------------------------------------------------------


class CrashClass(StrEnum):
    """Outcome of one sandboxed run through the crash oracle."""

    CRASH = "crash"
    BOUNDARY = "boundary"
    NON_CRASH = "non_crash"


#: Signals that are sandbox-boundary deaths under the mandated rlimits, not
#: crashes: SIGABRT (RLIMIT_AS allocator abort), SIGKILL (RLIMIT_CPU soft==hard)
#: and SIGXCPU (RLIMIT_CPU soft<hard).
BOUNDARY_SIGNALS: frozenset[int] = frozenset({6, 9, 24})

_SIGNAL_NAMES: dict[int, str] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    31: "SIGSYS",
}

_SANITIZER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"AddressSanitizer", re.IGNORECASE), "asan"),
    (re.compile(r"UndefinedBehaviorSanitizer|runtime error:", re.IGNORECASE), "ubsan"),
)

_HEX_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class Classification:
    """The oracle's verdict for one run."""

    kind: CrashClass
    signal_number: int | None
    signal: str
    sanitizer: str
    reason: str


def decode_signal(exit_code: int) -> int | None:
    """Decode a negative or ``>= 128`` exit code to a signal number, else None.

    Covers both backends: tier-1 proc returns negative codes on signal death;
    tier-2 ContainerSandbox passes docker's ``128 + N`` convention verbatim.
    """
    if exit_code < 0:
        return -exit_code
    if exit_code >= 128:
        return exit_code - 128
    return None


def signal_name(number: int) -> str:
    """Human-readable name for *number* (e.g. ``11`` -> ``SIGSEGV``)."""
    return _SIGNAL_NAMES.get(number, f"SIG{number}")


def detect_sanitizer(stderr: str) -> str:
    """Return ``"asan"``/``"ubsan"`` when *stderr* carries a sanitizer report, else ``""``."""
    for pattern, kind in _SANITIZER_PATTERNS:
        if pattern.search(stderr):
            return kind
    return ""


def classify_result(result: SandboxResult) -> Classification:
    """Classify one :class:`SandboxResult` as crash / boundary / non-crash.

    Sanitizer output is checked FIRST and wins regardless of exit code (so the
    ``(124, timed_out=True, ASan-stderr)`` corner is a crash, not a timeout).
    """
    sanitizer = detect_sanitizer(result.stderr)
    if sanitizer:
        return Classification(
            kind=CrashClass.CRASH,
            signal_number=None,
            signal="",
            sanitizer=sanitizer,
            reason=f"sanitizer:{sanitizer}",
        )
    if result.timed_out:
        return Classification(
            kind=CrashClass.BOUNDARY,
            signal_number=None,
            signal="",
            sanitizer="",
            reason="wall-clock-timeout",
        )
    signal_number = decode_signal(result.exit_code)
    if signal_number is None:
        return Classification(
            kind=CrashClass.NON_CRASH,
            signal_number=None,
            signal="",
            sanitizer="",
            reason="positive-exit",
        )
    name = signal_name(signal_number)
    if signal_number in BOUNDARY_SIGNALS:
        return Classification(
            kind=CrashClass.BOUNDARY,
            signal_number=signal_number,
            signal=name,
            sanitizer="",
            reason=f"rlimit-signal:{name}",
        )
    return Classification(
        kind=CrashClass.CRASH,
        signal_number=signal_number,
        signal=name,
        sanitizer="",
        reason=f"signal:{name}",
    )


# ---------------------------------------------------------------------------
# Crash hash (tasks.md 5)
# ---------------------------------------------------------------------------


def normalize_crash_output(stderr: str) -> str:
    """Normalize *stderr* for dedup: collapse hex addresses and whitespace runs.

    Addresses vary run to run for the same logical crash, so they carry no
    dedup signal; whitespace runs make otherwise-identical output hash apart.
    """
    normalized = _HEX_ADDRESS_RE.sub("0xADDR", stderr)
    normalized = _WHITESPACE_RE.sub(" ", normalized)
    return normalized.strip()


def compute_crash_hash(*, exit_code: int, signal_number: int | None, stderr: str) -> str:
    """sha256 of normalized stderr + exit code + signal (stable per crash)."""
    signal_part = "" if signal_number is None else str(signal_number)
    payload = f"{exit_code}|{signal_part}|{normalize_crash_output(stderr)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Build + execution plumbing (tasks.md 1, 2, 6)
# ---------------------------------------------------------------------------


class BuildError(Exception):
    """Raised when a target's ``BuildCommand`` fails."""


def _run_build_command(build_cmd: BuildCommand, repo_path: Path) -> None:
    """Run one recon-sourced build recipe in *repo_path*.

    The build runs against the trusted snapshot with the host toolchain (cargo,
    go, make, ...), which are deliberately NOT on the sandbox allowlist; the
    fuzz *runs* — the attacker-controlled executions — always go through the
    ``SandboxBackend``.  A failing recipe raises :class:`BuildError`.
    """
    working_dir = build_cmd.working_dir or "."
    cwd = repo_path / working_dir
    if not cwd.is_dir():
        cwd = repo_path
    try:
        proc = subprocess.run(
            ["sh", "-c", build_cmd.command],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"build command {build_cmd.command!r} could not run: {exc}"
        raise BuildError(msg) from exc
    if proc.returncode != 0:
        msg = f"build command {build_cmd.command!r} exited {proc.returncode}"
        raise BuildError(msg)


def _stage_binary(binary_path: Path, work_dir: Path) -> str:
    """Copy the built binary into *work_dir* under a fixed relative name."""
    staged = work_dir / STAGED_BINARY_NAME
    shutil.copy2(binary_path, staged)
    staged.chmod(0o755)
    return STAGED_BINARY_NAME


def _build_exec_spec(spec: FuzzSpec, *, staged_name: str, mutant: str) -> SandboxExecSpec:
    """Build a sandbox spec that runs the target with one mutated argument.

    ``sh`` is on the allowlist; the argv is passed positionally through ``"$@"``
    so the mutated bytes are never interpolated into a shell string.
    """
    argv = [f"./{staged_name}", *spec.invocation[1:], mutant]
    return SandboxExecSpec(
        command="sh",
        args=["-c", 'exec "$0" "$@"', *argv],
        cwd=".",
        env_profile=EnvProfile.NONE,
        timeout_seconds=min(spec.timeout_seconds, HARD_TIMEOUT_SECONDS),
    )


def _classify_and_dedup(
    outcomes: Sequence[tuple[MutationRecord, SandboxResult]],
    *,
    spec: FuzzSpec,
    store: ArtifactStore,
) -> tuple[list[FuzzCrash], int, int]:
    """Classify every run, dedup crashes by hash, store their output as artifacts.

    Returns ``(crashes, boundary_count, non_crash_count)``.  One
    :class:`FuzzCrash` per unique crash hash — the first run to hit a crash wins.
    """
    seen: dict[str, FuzzCrash] = {}
    boundary = 0
    non_crash = 0
    scrubber = Scrubber()
    for mutant, result in outcomes:
        classification = classify_result(result)
        if classification.kind is CrashClass.BOUNDARY:
            boundary += 1
            continue
        if classification.kind is CrashClass.NON_CRASH:
            non_crash += 1
            continue
        crash_hash = compute_crash_hash(
            exit_code=result.exit_code,
            signal_number=classification.signal_number,
            stderr=result.stderr,
        )
        if crash_hash in seen:
            continue
        stdout_scrub = scrubber.scrub(result.stdout)
        stderr_scrub = scrubber.scrub(result.stderr)
        hits = stdout_scrub.hits + stderr_scrub.hits
        redaction_status = RedactionStatus.REDACTED if hits else RedactionStatus.NOT_REQUIRED
        wrapped_stdout = f"<target_content>{stdout_scrub.text}</target_content>"
        wrapped_stderr = f"<target_content>{stderr_scrub.text}</target_content>"
        stderr_ref = store.put_bytes(
            f"{spec.scan_id}/fuzz/{crash_hash}/stderr",
            wrapped_stderr.encode("utf-8"),
            kind=ArtifactKind.TOOL_STDERR,
            content_type="text/plain",
            redaction_status=redaction_status,
        )
        stdout_ref = store.put_bytes(
            f"{spec.scan_id}/fuzz/{crash_hash}/stdout",
            wrapped_stdout.encode("utf-8"),
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            redaction_status=redaction_status,
        )
        kind = "sanitizer" if classification.sanitizer else "signal"
        seen[crash_hash] = FuzzCrash(
            crash_hash=crash_hash,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            kind=kind,
            signal=classification.signal,
            signal_number=classification.signal_number,
            sanitizer=classification.sanitizer,
            seed=mutant.seed,
            run_index=mutant.run_index,
            trigger_input=mutant.mutated_input,
            component=spec.entry_point_file or spec.invocation[0],
            stderr_artifact_ref=stderr_ref.id,
            stdout_artifact_ref=stdout_ref.id,
            stderr_sha256=stderr_ref.sha256,
            stderr_length=len(result.stderr),
        )
    return list(seen.values()), boundary, non_crash


def _run_pass(
    spec: FuzzSpec,
    *,
    sandbox: SandboxBackend,
    store: ArtifactStore,
    work_dir: Path,
    binary_path: Path,
) -> FuzzResult:
    """Stage the binary, run the planned mutants, classify + dedup + store."""
    staged = _stage_binary(binary_path, work_dir)
    budget = min(spec.run_budget, MAX_RUNS)
    mutants = generate_mutants(
        spec.seed_input,
        count=budget,
        seed=spec.seed,
        dictionary=spec.dictionary,
    )
    outcomes: list[tuple[MutationRecord, SandboxResult]] = []
    for mutant in mutants:
        _heartbeat(f"fuzz run {mutant.run_index + 1}/{len(mutants)}")
        exec_spec = _build_exec_spec(spec, staged_name=staged, mutant=mutant.mutated_input)
        try:
            result = sandbox.run(exec_spec, work_dir=work_dir, resolved_env={}, egress_policy=None)
        except ToolSecurityError as exc:
            # Fail closed: a refused command must never be executed directly.
            return FuzzResult(status="failed", reason=f"sandbox-refused: {exc}")
        outcomes.append((mutant, result))
    crashes, boundary, non_crash = _classify_and_dedup(outcomes, spec=spec, store=store)
    return FuzzResult(
        status="ran",
        runs_executed=len(outcomes),
        budget_exhausted=budget > 0,
        boundary_outcomes=boundary,
        non_crash_exits=non_crash,
        crashes=tuple(crashes),
    )


def _heartbeat(message: str) -> None:
    """Best-effort activity heartbeat (no-op outside a Temporal activity)."""
    with suppress(RuntimeError):
        activity.heartbeat(message)


def fuzz_impl(
    spec: FuzzSpec,
    *,
    sandbox: SandboxBackend | None = None,
    work_dir: Path | None = None,
    store: ArtifactStore | None = None,
    build_runner: Callable[[BuildCommand, Path], None] | None = None,
) -> FuzzResult:
    """Run one deterministic fuzz pass for *spec*.

    Gates first (args channel, invocation, build recipe), then builds, then runs
    the mutated invocations through the sandbox.  ``sandbox``/``work_dir``/
    ``store``/``build_runner`` are injectable for tests; production passes none.
    """
    if spec.attacker_controlled_input != "args":
        return FuzzResult(
            status="skipped",
            reason=f"channel-not-args:{spec.attacker_controlled_input}",
        )
    if not spec.invocation:
        return FuzzResult(status="refused", reason="missing-invocation")
    build_cmds = tuple(c for c in spec.build_commands if c.purpose in ("build", "fuzz"))
    if not build_cmds:
        return FuzzResult(status="refused", reason="no-build-command")
    repo_path = Path(spec.repo_path)
    runner: Callable[[BuildCommand, Path], None] = build_runner or _run_build_command
    for build_cmd in build_cmds:
        try:
            runner(build_cmd, repo_path)
        except BuildError as exc:
            return FuzzResult(status="failed", reason=f"build-failed: {exc}")
    binary_rel = Path(spec.binary_path)
    binary_path = binary_rel if binary_rel.is_absolute() else repo_path / binary_rel
    if not binary_path.is_file():
        return FuzzResult(status="failed", reason=f"binary-not-found: {spec.binary_path}")
    backend = sandbox if sandbox is not None else build_sandbox_backend()
    artifact_store = store if store is not None else build_artifact_store(spec.artifact_store_path)
    if work_dir is not None:
        return _run_pass(
            spec,
            sandbox=backend,
            store=artifact_store,
            work_dir=work_dir,
            binary_path=binary_path,
        )
    with tempfile.TemporaryDirectory(prefix="quarry-fuzz-") as tmp:
        return _run_pass(
            spec,
            sandbox=backend,
            store=artifact_store,
            work_dir=Path(tmp),
            binary_path=binary_path,
        )


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------


@activity.defn(name="fuzz")
def fuzz_activity(inp: FuzzSpec) -> FuzzResult:
    """Run a deterministic, non-agentic fuzz pass over a built target."""
    return fuzz_impl(inp)
