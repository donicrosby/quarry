"""FastAPI demo target for local scanner development."""

import base64
import subprocess
from typing import Annotated
from urllib.request import urlopen

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI(title="Quarry FastAPI Target")

ADMIN_API_KEY = "demo-admin-key-please-rotate"

USERS = {
    "1": {"id": "1", "name": "Ada", "email": "ada@example.test"},
    "2": {"id": "2", "name": "Grace", "email": "grace@example.test"},
}

BASIC_AUTH_USERS = {
    "user-a": "pass-a",
    "user-b": "pass-b",
}

security = HTTPBasic()


async def get_optional_credentials(request: Request) -> HTTPBasicCredentials | None:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return None
    try:
        encoded = auth_header[6:]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
        return HTTPBasicCredentials(username=username, password=password)
    except Exception:
        return None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict[str, str]:
    return {"admin_api_key": ADMIN_API_KEY}


@app.get("/users/{user_id}")
def read_user(
    user_id: str,
    credentials: Annotated[HTTPBasicCredentials | None, Depends(get_optional_credentials)] = None,
) -> dict[str, str]:
    # Optional Basic auth: if credentials provided, validate them
    if credentials is not None:
        stored_password = BASIC_AUTH_USERS.get(credentials.username)
        if stored_password is None or credentials.password != stored_password:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

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
    with urlopen(url, timeout=2) as resp:  # noqa: S310
        status = resp.status
        body = resp.read(512).decode("utf-8", "replace")
    return {"requested_url": url, "status": str(status), "body": body}
