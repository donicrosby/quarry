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


# --- benchmark web-class sinks (bench 2.2) ---------------------------------
# One deliberately vulnerable route per web VulnerabilityClass so the benchmark
# can score each class end-to-end: sql_injection, xss, ssti, open_redirect and
# file_upload. Each route is paired with a ground-truth entry in
# tests/golden/ground_truth/vulnerable-fastapi.json; the entry never exists
# without a reachable sink here (see tests/unit/test_benchmark_web_fixtures.py).
# Imports stay inside the handlers on purpose: this file is an intentional
# fixture and a top-level import would shift the golden line numbers that
# tests/fixtures/vulnerable-fastapi pins.


@app.get("/search")
def search(q: str = "") -> dict[str, list[dict[str, str]]]:
    """SQL injection: ``q`` is concatenated straight into the query text."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
        conn.executemany("INSERT INTO items (name) VALUES (?)", [("alpha",), ("beta",), ("gamma",)])
        conn.commit()
        query = "SELECT id, name FROM items WHERE name = '" + q + "'"
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()
    return {"results": [{"id": str(row[0]), "name": str(row[1])} for row in rows]}


@app.get("/greet")
def greet(name: str = "world"):
    """XSS: ``name`` is interpolated into HTML with no context encoding."""
    from fastapi.responses import HTMLResponse

    body = "<html><body><h1>Hello " + name + "</h1></body></html>"
    return HTMLResponse(content=body)


@app.get("/render")
def render(template: str = "Hello guest") -> dict[str, str]:
    """SSTI: the request value is compiled and rendered as a Jinja2 template."""
    from jinja2 import Template

    rendered = Template(template).render(name="guest")
    return {"rendered": rendered}


@app.get("/go")
def go(url: str = "/health"):
    """Open redirect: the Location comes straight from the request parameter."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=url)


def _store_upload(filename: str, content: str) -> dict[str, str]:
    """Store an uploaded file under the upload dir with NO validation.

    Unrestricted upload: the client-supplied filename (extension and path
    traversal) and the content are stored verbatim. Files land under the system
    temp dir (never inside the scanned repo) so the fixture stays side-effect
    free for the repo snapshot golden test.
    """
    import tempfile
    from pathlib import Path as _Path

    upload_dir = _Path(tempfile.gettempdir()) / "quarry-vulnerable-uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored = upload_dir / filename
    stored.write_text(content, encoding="utf-8")
    return {"stored": str(stored), "extension": stored.suffix}


def upload(filename: str, content: str) -> dict[str, str]:
    """Unrestricted upload helper: the filename's extension is never validated.

    Kept as a plain function (not the route) so the benchmark fixture can call
    the sink directly; the ``/upload`` route below accepts a real multipart
    ``file`` part and stores it through the same sink.
    """
    return _store_upload(filename, content)


def _multipart_file_part(content_type: str, body: bytes) -> tuple[str, str]:
    """Extract the first file part's (filename, text) from a multipart body.

    A deliberately tiny parser so the fixture accepts a real
    ``multipart/form-data`` upload without pulling in a form-parsing dependency.
    Only the first part carrying a ``filename`` is returned; the declared
    ``Content-Type`` of the part is ignored, exactly as the vulnerable sink does.
    """
    marker = "boundary="
    if marker not in content_type:
        raise HTTPException(status_code=422, detail="multipart/form-data required")
    boundary = content_type.split(marker, 1)[1].strip().strip('"').encode()
    for part in body.split(b"--" + boundary):
        if b"Content-Disposition:" not in part or b'filename="' not in part:
            continue
        head, sep, payload = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        filename = head.split(b'filename="', 1)[1].split(b'"', 1)[0].decode("utf-8", "replace")
        return filename, payload.rstrip(b"\r\n").decode("utf-8", "replace")
    raise HTTPException(status_code=422, detail="a multipart 'file' part is required")


@app.post("/upload")
async def upload_route(request: Request) -> dict[str, str]:
    """Unrestricted upload: the filename's extension and the declared
    content-type are never validated.

    Stores the multipart/form-data ``file`` part the dynamic upload probe forges
    verbatim; a request with no ``file`` part is a 422. The part's declared
    ``Content-Type`` is ignored (never sniffed or checked).
    """
    body = await request.body()
    filename, content = _multipart_file_part(request.headers.get("content-type", ""), body)
    return _store_upload(filename, content)


@app.get("/uploads/{filename:path}")
def serve_upload(filename: str) -> dict[str, str]:
    """Serving sink: returns a stored upload's bytes and extension verbatim.

    Pairs with ``/upload`` so a live probe can fetch an uploaded file back and
    confirm the sink stored it unsanitised: the dangerous extension survives and
    the content is served with no ``Content-Disposition`` hardening. The stored
    name is joined to the upload dir without sanitisation, so a traversal name
    also reads outside it.
    """
    import tempfile
    from pathlib import Path as _Path

    upload_dir = _Path(tempfile.gettempdir()) / "quarry-vulnerable-uploads"
    stored = upload_dir / filename
    if not stored.is_file():
        raise HTTPException(status_code=404, detail="Unknown upload")
    return {
        "name": filename,
        "content": stored.read_text(encoding="utf-8"),
        "extension": stored.suffix,
    }
