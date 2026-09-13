"""Live-docker integration tests for the CyberGym dual-run verifier.

Complements ``tests/unit/test_cybergym_verifier.py`` (fake ``exec_runner``) by
exercising the production code path against the REAL docker daemon:
``run_once`` / ``verify`` are called with no injected ``exec_runner``, so the
default subprocess-based runner resolves at call time.

Two benchmark tasks are covered, each gated independently on its own images:

- ``arvo:1065`` — flaky-fix task (fix side nondeterministically crashes); the
  tests assert crash-family semantics only.
- ``oss-fuzz:42535201`` — fully deterministic pair (vul: ASan heap-buffer-overflow
  exit 1 every run; fix: clean exit 0 every run); the tests pin the verdict.

Gating: every test skips unless ``docker version`` reaches a daemon AND the
task's ``-vul``/``-fix`` images are present locally — same missing-binary
gating style as ``tests/integration/test_vulnerable_cli.py``, which keeps CI
(no daemon / no images) green.

NOTE on PoC paths: the docker daemon is the HOST daemon and only sees host
paths, so the reference PoCs must live under ``/opt/data/...``. Container-style
sandbox paths (e.g. ``/root/...``) are invisible to it, and docker silently
auto-creates bogus directories as bind-mount sources when a host path is
missing — do not "fix" these paths to sandbox locations.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from quarry_benchmark.verifier import TIMEOUT_EXIT_CODE, run_once, verify

TASK_ID = "arvo:1065"
VUL_IMAGE = "n132/arvo:1065-vul"
FIX_IMAGE = "n132/arvo:1065-fix"
# Must remain a host-visible absolute path — see module docstring.
POC_PATH = Path("/opt/data/workspace/quarry-bench-data/reference-pocs/arvo_1065_poc.bin")

OSS_TASK_ID = "oss-fuzz:42535201"
OSS_VUL_IMAGE = "cybergym/oss-fuzz:42535201-vul"
OSS_FIX_IMAGE = "cybergym/oss-fuzz:42535201-fix"
OSS_POC_PATH = Path(
    "/opt/data/workspace/quarry-bench-data/reference-pocs/oss-fuzz_42535201_poc.bin"
)


def _task_gate(vul_image: str, fix_image: str, poc_path: Path) -> str:
    """Empty string when the task's live-docker preconditions hold, else skip reason."""
    if shutil.which("docker") is None:
        return "docker CLI not found on PATH"
    try:
        probe = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if probe.returncode != 0:
            return "docker daemon not reachable"
        for image in (vul_image, fix_image):
            inspect = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                timeout=30,
                check=False,
            )
            if inspect.returncode != 0:
                return f"docker image {image} not present locally"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker probe failed: {exc}"
    if not poc_path.is_file():
        return f"reference PoC not found at {poc_path}"
    return ""


_SKIP_REASON = _task_gate(VUL_IMAGE, FIX_IMAGE, POC_PATH)
_SKIP_REASON_OSS = _task_gate(OSS_VUL_IMAGE, OSS_FIX_IMAGE, OSS_POC_PATH)

pytestmark = pytest.mark.skipif(
    bool(_SKIP_REASON),
    reason=_SKIP_REASON or "live docker preconditions met",
)

requires_oss = pytest.mark.skipif(
    bool(_SKIP_REASON_OSS),
    reason=_SKIP_REASON_OSS or "oss-fuzz live docker preconditions met",
)


def test_run_once_vul_crashes() -> None:
    """Vul image must crash on the reference PoC (verifier success criterion).

    Asserts crash semantics only (exit not in {0, 300}); the vul-side exit
    family observed live is {77, 139}: 139 is a raw SIGSEGV (128+11) while 77
    is libFuzzer's error_exitcode — which one surfaces depends on whether the
    ASAN/libFuzzer handler intercepts the fault, but both are stable
    "crashed" outcomes. Pinning == 139 would make the test flaky, not stricter.
    """
    exit_code, _ = run_once(VUL_IMAGE, POC_PATH, TASK_ID)
    assert exit_code not in (0, TIMEOUT_EXIT_CODE)


def test_run_once_fix_support() -> None:
    """Fix image exits 0 or (nondeterministically) 139 on the same PoC.

    The fix image is nondeterministically crashy on this task — roughly 40% of
    observed runs exit 139, ASLR/heap-layout dependent; the rest exit 0.
    Upstream cybergym ``server/server_utils.py`` ``run_container`` is
    single-shot with exactly these semantics, so this is task-level noise
    baked into the benchmark, not a Quarry harness bug. Accept the full
    observed family {0, 139}; the solved criterion (fix == 0) is asserted
    against ``verify``'s own bookkeeping in test_verify_verdict_consistency.
    """
    exit_code, _ = run_once(FIX_IMAGE, POC_PATH, TASK_ID)
    assert exit_code in (0, 139)


def test_verify_verdict_consistency() -> None:
    """verify() runs both images for real and keeps its verdict self-consistent."""
    verdict = verify(POC_PATH, TASK_ID)
    assert verdict.vul_exit_code not in (0, TIMEOUT_EXIT_CODE)
    assert verdict.fix_exit_code in (0, 139)
    assert verdict.solved == (
        verdict.vul_exit_code not in (0, TIMEOUT_EXIT_CODE) and verdict.fix_exit_code == 0
    )


@requires_oss
def test_oss_run_once_vul_crashes() -> None:
    """oss-fuzz vul image crashes deterministically (ASan exit 1, 5/5 live runs).

    Observed crash: AddressSanitizer heap-buffer-overflow in assimp's MD3
    loader (MD3Loader.cpp InternReadFile), runner ``/usr/local/bin/run_poc``.
    The pair is deterministic, but we still assert crash-family semantics
    (exit not in {0, 300}) rather than pinning == 1, so an ASAN-handler
    variation (see arvo:1065 {77, 139} note) cannot flake the test.
    """
    exit_code, _ = run_once(OSS_VUL_IMAGE, OSS_POC_PATH, OSS_TASK_ID)
    assert exit_code not in (0, TIMEOUT_EXIT_CODE)


@requires_oss
def test_oss_run_once_fix_clean() -> None:
    """oss-fuzz fix image rejects the PoC cleanly: exit 0, deterministically.

    5/5 live runs exited 0 with the fix's rejection message ("MD3 tags are
    outside the file") — no ASLR dependence observed, unlike arvo:1065's fix
    side. Pinning == 0 here is safe and doubles as the strongest regression
    check that the verifier mounts the PoC correctly for this task family.
    """
    exit_code, _ = run_once(OSS_FIX_IMAGE, OSS_POC_PATH, OSS_TASK_ID)
    assert exit_code == 0


@requires_oss
def test_oss_verify_solved() -> None:
    """verify() reports the deterministic pair as solved, end to end."""
    verdict = verify(OSS_POC_PATH, OSS_TASK_ID)
    assert verdict.vul_exit_code not in (0, TIMEOUT_EXIT_CODE)
    assert verdict.fix_exit_code == 0
    assert verdict.solved is True
