"""Stored-XSS fixture target (live-xss-proof task 1.3).

``POST /comment`` stores the ``body`` form field; ``GET /view`` renders every
stored comment **unescaped**. The two-request (inject then read) chain is what
``prove_xss`` stored mode exercises. Run standalone::

    python tests/fixtures/xss_targets/store_app.py [port]
"""

from __future__ import annotations

import sys

from flask import Flask, request

app = Flask(__name__)

_COMMENTS: list[str] = []


@app.post("/comment")
def comment() -> str:
    body = request.form.get("body")
    if body is None:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            body = str(payload.get("body", ""))
        else:
            body = ""
    _COMMENTS.append(body)
    return f"<html><body><p id='status'>stored {len(_COMMENTS)}</p></body></html>"


@app.get("/view")
def view() -> str:
    # Deliberately unescaped: stored payloads render verbatim.
    rendered = "".join(f"<div class='comment'>{c}</div>" for c in _COMMENTS)
    return f"<html><body><div id='comments'>{rendered}</div></body></html>"


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5002
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
