"""Reflected-XSS fixture target (live-xss-proof task 1.2).

``GET /search?q=<x>`` echoes ``q`` into the response body **unescaped** — the
classic reflected-XSS sink. Run standalone::

    python tests/fixtures/xss_targets/reflect_app.py [port]
"""

from __future__ import annotations

import sys

from flask import Flask, request

app = Flask(__name__)


@app.get("/search")
def search() -> str:
    q = request.args.get("q", "")
    # Deliberately unescaped: the reflected payload must reach the DOM verbatim.
    return f"<html><body><h1>Search</h1><div id='results'>{q}</div></body></html>"


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
