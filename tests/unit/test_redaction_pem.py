"""Regression pins for the private-key PEM branch of the redaction scrubber.

The PEM pattern was ``-----BEGIN ...-----.*?-----END ...-----`` (DOTALL). On a
body of many ``-----BEGIN`` markers with no ``-----END`` every start lazily scans
to EOF and the failure is retried from each later BEGIN — quadratic, measured
~28-46 s at the 512 KB body cap and invisible to a run-length guard (that body's
longest alnum run is ``PRIVATE``).  ``_sub_pem_blocks`` reproduces the identical
leftmost-BEGIN / nearest-END pairing in one linear pass.

The timing pins run in SUBPROCESSES with an alarm: an in-suite assertion at this
chokepoint wedges the whole suite when it regresses (sibling patterns share the
loop), and must not be able to hang collection.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from quarry_models import redaction
from quarry_models.redaction import Scrubber

BEGIN = "-----BEGIN PRIVATE KEY-----"
END = "-----END PRIVATE KEY-----"

# Child process: build an adversarial body, scrub it under SIGALRM (30 s), and
# print the module path it imported so the parent can prove it measured the code
# under test and not a stale editable install.
_CHILD = textwrap.dedent(
    """
    import signal, sys, time
    from pathlib import Path

    def _kill(signum, frame):
        print("ALARM", flush=True)
        raise SystemExit(9)

    signal.signal(signal.SIGALRM, _kill)

    case = sys.argv[1]
    size = int(sys.argv[2])

    import quarry_models.redaction as R

    print("MODULE", Path(R.__file__).resolve(), flush=True)

    if case == "repeat":
        unit = b"-----BEGIN PRIVATE KEY-----" + b" " * 8
        body = (unit * (size // len(unit))).decode()
    elif case == "repeat_x":
        unit = b"-----BEGIN PRIVATE KEY-----X"
        body = (unit * (size // len(unit))).decode()
    elif case == "single_control":
        body = "-----BEGIN PRIVATE KEY-----" + " " * (size - 30)
    else:
        raise SystemExit(f"unknown case {case}")

    t0 = time.perf_counter()
    signal.alarm(30)
    res = R.Scrubber().scrub(body)
    signal.alarm(0)
    print(f"ELAPSED {time.perf_counter() - t0:.4f} hits={res.hits}", flush=True)
    """
)

# A 512 KB BEGIN-without-END body finishes in ~0.04 s once the scan is linear;
# the quadratic shape was 28-46 s.  A generous absolute ceiling plus a scaling
# ratio keeps this robust to co-tenant load without admitting the old shape.
_CEILING_S = 4.0


def _run_child(case: str, size: int) -> tuple[float, int]:
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, case, str(size)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.stdout, f"child produced no output: rc={proc.returncode} err={proc.stderr!r}"
    module_line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("MODULE ")), None)
    assert module_line is not None, proc.stdout
    # The child must import the same module file the test imports.
    assert module_line.split(" ", 1)[1] == str(Path(redaction.__file__).resolve()), module_line
    elapsed_line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("ELAPSED ")), None)
    assert elapsed_line is not None, f"no timing (alarm/wedge?): {proc.stdout!r}"
    _, secs, hits = elapsed_line.split()
    return float(secs), int(hits.split("=")[1])


def test_begin_without_end_body_is_linear_not_quadratic() -> None:
    """512 KB of BEGIN-without-END must scrub in linear time, not scan-to-EOF²."""
    small_s, _ = _run_child("repeat", 128 * 1024)
    large_s, hits = _run_child("repeat", 512 * 1024)
    assert hits == 0  # no complete PEM block → nothing to redact, body survives
    assert large_s < _CEILING_S, f"512 KB scrub took {large_s:.2f}s"
    # 4x the input; linear ~4x, quadratic ~16x. Floor the small sample so a
    # scheduling hiccup on the tiny measurement cannot inflate the ratio.
    ratio = large_s / max(small_s, 0.008)
    assert ratio < 10, (
        f"superlinear scaling: 128KB={small_s:.4f}s 512KB={large_s:.4f}s ratio={ratio:.1f}"
    )


def test_x_padded_begin_without_end_body_is_bounded() -> None:
    """The X-padding variant (46 s pre-fix) must also finish fast."""
    secs, hits = _run_child("repeat_x", 512 * 1024)
    assert hits == 0
    assert secs < _CEILING_S, f"512 KB X-padded scrub took {secs:.2f}s"


def test_single_begin_control_is_fast() -> None:
    """Control: one BEGIN plus filler was always fast — the many-starts shape was
    the trigger, so this must stay fast after the fix (no bound over-applied)."""
    secs, _ = _run_child("single_control", 512 * 1024)
    assert secs < _CEILING_S, f"control scrub took {secs:.2f}s"


# ---------------------------------------------------------------------------
# Detection side — the fix must not trade coverage for speed.
# ---------------------------------------------------------------------------

# Deterministic, realistic base64 PEM body (wrapped at 64 columns like openssl).
_RAW = base64.b64encode(bytes(range(256)) * 12).decode()


def _body_lines(count: int = 40) -> str:
    return "\n".join(_RAW[i : i + 64] for i in range(0, count * 64, 64))


def _pem(label: str, *, extra_header: str = "", count: int = 40) -> str:
    header = f"-----BEGIN {label}-----"
    footer = f"-----END {label}-----"
    middle = extra_header + _body_lines(count)
    return f"{header}\n{middle}\n{footer}"


@pytest.mark.parametrize(
    "label",
    [
        "PRIVATE KEY",  # PKCS#8
        "RSA PRIVATE KEY",  # PKCS#1
        "EC PRIVATE KEY",  # SEC1
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",  # PKCS#8 encrypted
    ],
)
def test_realistic_pem_block_is_fully_redacted(label: str) -> None:
    block = _pem(label)
    text = f"<html><pre>\n{block}\n</pre></html>"
    res = Scrubber().scrub(text)

    assert f"-----BEGIN {label}-----" not in res.text
    assert f"-----END {label}-----" not in res.text
    # The base64 body must be gone too, not just the markers.
    assert _RAW[:64] not in res.text
    assert res.hits == 1


def test_legacy_encrypted_pem_with_proc_type_header_is_redacted() -> None:
    # Pre-PKCS#8 encrypted PEMs carry Proc-Type / DEK-Info lines (":", ",", "-")
    # inside the block body — the tempered/naive rewrites mishandle these.
    block = _pem(
        "RSA PRIVATE KEY",
        extra_header=(
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,B300D8F11843C4DFDECDD84E76576250\n\n"
        ),
    )
    res = Scrubber().scrub(f"prefix\n{block}\nsuffix")

    assert "-----BEGIN RSA PRIVATE KEY-----" not in res.text
    assert "DEK-Info" not in res.text
    assert res.hits == 1


def test_multiple_pem_blocks_each_redacted() -> None:
    labels = ["RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
    text = "\n".join(_pem(label) for label in labels)
    res = Scrubber().scrub(text)

    assert res.hits == len(labels)
    assert "-----BEGIN" not in res.text
    assert "-----END" not in res.text


def test_body_held_between_two_begin_markers_is_redacted() -> None:
    """Exact-pairing pin: the original lazy span runs from the FIRST BEGIN to the
    first END after it, so a body held between two BEGIN markers is redacted. A
    rewrite whose body refuses to cross an inner BEGIN would leak it here."""
    text = f"{BEGIN}\nHELDBETWEENBODY\n{BEGIN}\n{END}"
    res = Scrubber().scrub(text)

    assert "HELDBETWEENBODY" not in res.text
    assert "-----BEGIN" not in res.text
    assert res.hits == 1


def test_unmatched_begin_then_complete_block_binds_to_first_begin() -> None:
    """Same leftmost-start semantics across a stray BEGIN: the first BEGIN binds
    to the next END even though a second BEGIN sits between them."""
    text = f"{BEGIN} orphan text {BEGIN}\nREALBODY\n{END}"
    res = Scrubber().scrub(text)

    assert "REALBODY" not in res.text
    assert "orphan text" not in res.text
    assert res.hits == 1


def test_begin_without_any_end_is_left_untouched() -> None:
    """No over-redaction: a BEGIN with no END anywhere is not a block and must
    leave the following text (and the marker) exactly as-is."""
    text = f"intro {BEGIN}\nthere is no end marker in this body at all\n"
    res = Scrubber().scrub(text)

    assert res.text == text
    assert res.hits == 0


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl binary not available")
def test_real_openssl_generated_keys_are_redacted(tmp_path: Path) -> None:
    """End-to-end against real keys openssl emits (PKCS#1, PKCS#8, SEC1/EC)."""
    targets = {
        "rsa_pkcs1.pem": ["openssl", "genrsa", "-traditional", "-out", "{out}", "2048"],
        "rsa_pkcs8.pem": [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            "{out}",
        ],
        "ec.pem": [
            "openssl",
            "ecparam",
            "-genkey",
            "-name",
            "prime256v1",
            "-noout",
            "-out",
            "{out}",
        ],
    }
    blocks: list[str] = []
    for name, argv in targets.items():
        out = tmp_path / name
        subprocess.run(
            [a.replace("{out}", str(out)) if a == "{out}" else a for a in argv],
            check=True,
            capture_output=True,
        )
        blocks.append(out.read_text())

    text = "<pre>\n" + "\n".join(blocks) + "\n</pre>"
    res = Scrubber().scrub(text)

    assert res.hits == len(blocks)
    assert "-----BEGIN" not in res.text
    assert "-----END" not in res.text
