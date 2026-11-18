"""Planted-regression target (FastAPI demo app).

Deliberately vulnerable fixture used to detect harness regressions. The seeded
flaws are authored for this project and are not drawn from any published
benchmark, CVE, or the other example targets, so a model cannot recall them
from training data. Ground truth lives outside this repo tree at
tests/golden/ground_truth/vulnerable-planted.json.
"""

import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException

from admin import admin_status
from serialization import load_profile
from weak_crypto import hash_password

app = FastAPI(title="Quarry Planted Regression Target", debug=True)

# Static data dir the file route below reads from.
DATA_DIR = Path(__file__).parent / "data"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/password")
def password(value: str) -> dict[str, str]:
    return {"hash": hash_password(value)}


@app.get("/admin/status")
def status(user: str) -> dict[str, str]:
    return admin_status(user)


@app.post("/profile")
def profile(payload: str) -> dict[str, str]:
    return load_profile(payload)


@app.get("/files")
def read_file(name: str) -> dict[str, str]:
    # Planted path traversal: attacker-controlled name is joined onto DATA_DIR
    # with no normalization, so ../ escapes the data directory.
    target = DATA_DIR / name
    return {"path": str(target), "content": target.read_text(encoding="utf-8")}


@app.get("/exec")
def exec_cmd(command: str) -> dict[str, str]:
    # Planted command injection: shell=True with unvalidated user input.
    completed = subprocess.run(
        f"echo {command}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    return {"stdout": completed.stdout, "stderr": completed.stderr}


@app.get("/item/{item_id}")
def item(item_id: str) -> dict[str, str]:
    if not item_id:
        raise HTTPException(status_code=404, detail="Unknown item")
    return {"id": item_id}
