# Dev Log: 2026-05-31

## Time box

Full session

## Goal

Implement week deliverables for attack surface mapping: schema, FastAPI route
extraction, persistence, reporting, TUI widget, and golden fixture.

## Changed

- Added `AttackSurfaceItem` schema to `src/quarry/schemas.py`
- Added `extract_fastapi_routes()` in `src/quarry_activities/attack_surface.py`
  using Python `ast` (no execution of target app)
- Added `AttackSurfaceItemRecord` and repository methods in
  `src/quarry_persistence/repositories.py`
- Updated `render_markdown_report()` to include an attack surface table
- Added `RouteTable` widget in `src/quarry_tui/widgets/route_table.py`
- Added `AttackSurfaceScreen` in `src/quarry_tui/screens/attack_surface.py`
- Added golden fixture `tests/fixtures/vulnerable-fastapi/expected_attack_surface.json`
- Added golden test `tests/golden/test_attack_surface.py`

## Works

- All 17 tests pass
- Route extractor correctly finds 5 routes in vulnerable-fastapi app
- Persistence round-trips `AttackSurfaceItem` through SQLite
- Report renders attack surface as a Markdown table
- Route table widget renders in Textual test harness
- Golden test matches deterministic fixture

## Broken or questionable

- TUI `AttackSurfaceScreen` is not yet wired into the main app navigation
  (it exists but there is no key binding or button to reach it)
- Route extractor only handles `app.method` and `router.method` decorators;
  it does not follow imports to resolve decorator aliases
- No support for FastAPI sub-routers with prefixes
- `auth_required` and `auth_hint` are always null because we do not analyze
  decorator arguments or dependency injection

## Commands run

```text
uv run pytest tests/unit/test_schemas.py -v
uv run pytest tests/unit/test_fastapi_route_extractor.py -v
uv run pytest tests/unit/test_attack_surface_persistence.py -v
uv run pytest tests/unit/test_attack_surface_reporting.py -v
uv run pytest tests/unit/test_route_table.py -v
uv run pytest tests/golden/test_attack_surface.py -v
uv run pytest -v
uv run ruff check .
uv run pyright
```

## Next command to run

```text
uv run quarry tui --db .quarry/quarry.db
```

## Next task

- Wire `AttackSurfaceScreen` into the TUI app with a key binding or scan-row
  action so users can navigate from the dashboard to the route view
- Consider adding route extraction to the scan workflow so attack surface is
  automatically persisted during a scan run

## Open decisions

- See ADR 007: ast-based route extraction scope
