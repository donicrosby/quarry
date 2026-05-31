import json
from pathlib import Path

from quarry_activities.attack_surface import extract_fastapi_routes


def test_vulnerable_fastapi_attack_surface_matches_golden() -> None:
    app_path = Path("examples/vulnerable-fastapi/app.py")
    fixture_path = Path("tests/fixtures/vulnerable-fastapi/expected_attack_surface.json")

    routes = extract_fastapi_routes(app_path)

    actual: list[dict[str, object]] = []
    for route in routes:
        dumped = route.model_dump()
        dumped["id"] = ""
        dumped["scan_id"] = ""
        actual.append(dumped)

    expected = json.loads(fixture_path.read_text())

    assert actual == expected
