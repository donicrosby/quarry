"""Seeded vulnerable FastAPI target for local scanner development."""

import subprocess

from fastapi import FastAPI, HTTPException

app = FastAPI(title="Quarry Vulnerable FastAPI Target")

ADMIN_API_KEY = "demo-admin-key-please-rotate"

USERS = {
    "1": {"id": "1", "name": "Ada", "email": "ada@example.test"},
    "2": {"id": "2", "name": "Grace", "email": "grace@example.test"},
}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict[str, str]:
    return {"admin_api_key": ADMIN_API_KEY}


@app.get("/users/{user_id}")
def read_user(user_id: str) -> dict[str, str]:
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Unknown user")
    return user


@app.get("/debug/ping")
def ping(host: str = "127.0.0.1") -> dict[str, str]:
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    return {"command": result.args, "stdout": result.stdout, "stderr": result.stderr}


@app.get("/fetch-local")
def fetch_local(url: str) -> dict[str, str]:
    if not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        raise HTTPException(status_code=400, detail="Only local URLs are accepted")
    return {"requested_url": url, "note": "Local-only SSRF seed"}
