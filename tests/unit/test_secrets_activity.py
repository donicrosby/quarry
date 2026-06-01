"""Tests for scan_repo_for_secrets Temporal activity decoration."""

from pathlib import Path

import pytest

from quarry_plugins.vuln_classes.secrets import (
    SecretMatch,
    scan_repo_for_secrets,
)


class TestScanRepoForSecretsActivityDecorator:
    def test_has_temporal_activity_definition_attribute(self) -> None:
        assert hasattr(scan_repo_for_secrets, "__temporal_activity_definition")

    def test_activity_name_is_scan_repo_for_secrets(self) -> None:
        defn = getattr(scan_repo_for_secrets, "__temporal_activity_definition")
        assert defn.name == "scan-repo-for-secrets"

    def test_function_is_not_async(self) -> None:
        defn = getattr(scan_repo_for_secrets, "__temporal_activity_definition")
        assert defn.is_async is False

    def test_wrapped_function_is_still_callable(self) -> None:
        assert callable(scan_repo_for_secrets)


class TestScanRepoForSecretsDirectCall:
    def test_direct_call_returns_matches(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text('API_KEY = "sk-real-key-123"\n', encoding="utf-8")
        matches = scan_repo_for_secrets(tmp_path)
        assert len(matches) == 1
        assert matches[0].key_name == "API_KEY"

    def test_direct_call_returns_empty_for_clean_repo(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text('APP_NAME = "Quarry"\n', encoding="utf-8")
        matches = scan_repo_for_secrets(tmp_path)
        assert matches == []

    def test_direct_call_with_many_files(self, tmp_path: Path) -> None:
        for idx in range(55):
            f = tmp_path / f"file_{idx:03d}.py"
            f.write_text(f'VAR_{idx} = "value_{idx}"\n', encoding="utf-8")
        matches = scan_repo_for_secrets(tmp_path)
        assert isinstance(matches, list)


class TestScanRepoForSecretsVulnerableApp:
    def test_finds_seeded_secret_in_vulnerable_fastapi(self) -> None:
        repo_root = Path("examples/vulnerable-fastapi").resolve()
        if not repo_root.exists():
            pytest.skip("vulnerable-fastapi example not available")
        matches = scan_repo_for_secrets(repo_root)
        key_names = {m.key_name for m in matches}
        assert "ADMIN_API_KEY" in key_names

    def test_match_has_correct_file_path(self) -> None:
        repo_root = Path("examples/vulnerable-fastapi").resolve()
        if not repo_root.exists():
            pytest.skip("vulnerable-fastapi example not available")
        matches = scan_repo_for_secrets(repo_root)
        admin_match = next(m for m in matches if m.key_name == "ADMIN_API_KEY")
        assert admin_match.file_path == "app.py"
        assert isinstance(admin_match, SecretMatch)
