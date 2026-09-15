#!/usr/bin/env python3
"""Replay the validate ensemble (reasoner + debater) against ONE candidate
finding from a prior scan DB, using the current code + prompt templates.

Purpose: cheap targeted agent testing. A full scan costs ~$0.40 and ~2h; this
runs ONLY the validate role against a single candidate so a prompt/schema
change's effect on verdict-combination can be measured for cents in seconds.

Usage:
    uv run python scripts/replay_validate.py \
        --db .quarry/quarry.db \
        --scan 7f98a9b0-7cbc-4042-86da-4758f23aee21 \
        --class secrets \
        --repo examples/vulnerable-fastapi \
        --panel chutes

Model routing goes through the same panel config + LiteLLM proxy as a real
scan (QUARRY_PANEL / quarry.toml); never direct to a provider.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

# Ensure repo src is importable when run via `uv run` from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _load_candidate(db_path: str, scan_id: str, vuln_class: str | None) -> dict:
    db = sqlite3.connect(db_path)
    rows = db.execute(
        "select finding_json from candidate_findings where scan_id=?",
        (scan_id,),
    ).fetchall()
    cands = [json.loads(t) for (t,) in rows]
    if vuln_class:
        cands = [c for c in cands if (c.get("vuln_class") or "") == vuln_class]
    if not cands:
        msg = f"no candidate findings for scan={scan_id} class={vuln_class}"
        raise SystemExit(msg)
    return cands[0]


def _resolve_validate_panel_json(panel_name: str | None) -> str:
    """Resolve the validate RoleConfig (incl. debater tier) exactly as a scan.

    Uses the same ``load_quarry_config`` + ``resolve_panel`` the server uses so
    the replay hits the LiteLLM proxy and the configured debater tier — never
    the all-mock DEFAULT_PANEL. Raises when the validate role resolves to mock,
    which would make the replay meaningless.
    """
    from quarry.panel_config import load_quarry_config, resolve_panel
    from quarry.schemas import Provider  # noqa: F401  (re-export check)

    config = load_quarry_config()
    panel = resolve_panel(config, panel_name)
    role_cfg = panel.get("validate")
    if role_cfg is None or role_cfg.provider == Provider.MOCK:
        msg = (
            "validate role resolved to MOCK — check QUARRY_PANEL / quarry.toml "
            "panel config before paying for a replay."
        )
        raise SystemExit(msg)
    return role_cfg.model_dump_json()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--scan", required=True)
    ap.add_argument("--class", dest="vuln_class", default=None)
    ap.add_argument("--repo", required=True, help="repo root the claim cites")
    ap.add_argument("--panel", default=None, help="panel name (else QUARRY_PANEL env)")
    ap.add_argument("--max-iterations", type=int, default=6)
    ap.add_argument("--budget-usd", type=float, default=0.05)
    args = ap.parse_args()

    import os

    panel_name = args.panel or os.environ.get("QUARRY_PANEL")
    if panel_name:
        os.environ["QUARRY_PANEL"] = panel_name

    from quarry_activities.validate import validate_activity

    cand = _load_candidate(args.db, args.scan, args.vuln_class)
    panel_json = _resolve_validate_panel_json(panel_name)
    print(
        f"Replaying validate for candidate [{cand.get('vuln_class')}] "
        f"{str(cand.get('title'))[:60]} (id={cand.get('id')})",
        flush=True,
    )
    result = validate_activity(
        cand,
        args.repo,
        panel_json=panel_json,
        budget_cap_usd=args.budget_usd,
        max_iterations=args.max_iterations,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
