"""Tests for the secrets scanner plugin."""

from pathlib import Path

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_plugins.vuln_classes.secrets import (
    SecretMatch,
    scan_file_for_secrets,
    scan_repo_for_secrets,
    secret_match_to_candidate_finding,
)


@pytest.fixture
def secrets_repo(tmp_path: Path) -> Path:
    """Create a temporary repo with known secret patterns."""
    app_py = tmp_path / "app.py"
    app_py.write_text(
        'ADMIN_API_KEY = "demo-admin-key-please-rotate"\n'
        'PLACEHOLDER = "changeme"\n'
        'SAFE_VAR = "hello"\n'
        'SECRET_TOKEN = "real-secret-value-abc123"\n'
        'DB_PASSWORD = "my-db-pass-456"\n',
        encoding="utf-8",
    )
    return tmp_path


class TestScanFileForSecrets:
    def test_detects_hardcoded_api_key(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text('ADMIN_API_KEY = "sk-abc123"\n', encoding="utf-8")
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 1
        assert matches[0].key_name == "ADMIN_API_KEY"
        assert matches[0].value == "sk-abc123"
        assert matches[0].line_number == 1
        assert matches[0].file_path == "app.py"

    def test_detects_secret_token(self, tmp_path: Path) -> None:
        app_py = tmp_path / "config.py"
        app_py.write_text('SECRET_TOKEN = "real-value"\n', encoding="utf-8")
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 1
        assert matches[0].key_name == "SECRET_TOKEN"

    def test_detects_password(self, tmp_path: Path) -> None:
        app_py = tmp_path / "settings.py"
        app_py.write_text('DB_PASSWORD = "supersecret"\n', encoding="utf-8")
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 1
        assert matches[0].key_name == "DB_PASSWORD"

    def test_ignores_placeholder_values(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text('API_KEY = "changeme"\n', encoding="utf-8")
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 0

    def test_ignores_empty_string_value(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text('API_KEY = ""\n', encoding="utf-8")
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 0

    def test_ignores_non_secret_variable_names(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text('APP_NAME = "Quarry"\n', encoding="utf-8")
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 0

    def test_skips_non_text_files(self, tmp_path: Path) -> None:
        binary = tmp_path / "data.bin"
        binary.write_bytes(b"\x00\x01\x02\x03")
        matches = scan_file_for_secrets(binary, tmp_path)
        assert len(matches) == 0

    def test_handles_multiline_source(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text(
            'import os\n\nAPI_KEY = "sk-real-key"\nname = "test"\n',
            encoding="utf-8",
        )
        matches = scan_file_for_secrets(app_py, tmp_path)
        assert len(matches) == 1
        assert matches[0].line_number == 3


class TestScanRepoForSecrets:
    def test_finds_secrets_across_files(self, secrets_repo: Path) -> None:
        matches = scan_repo_for_secrets(secrets_repo)
        key_names = {m.key_name for m in matches}
        assert "ADMIN_API_KEY" in key_names
        assert "SECRET_TOKEN" in key_names
        assert "DB_PASSWORD" in key_names

    def test_ignores_placeholder_changeme(self, secrets_repo: Path) -> None:
        matches = scan_repo_for_secrets(secrets_repo)
        key_names = {m.key_name for m in matches}
        assert "PLACEHOLDER" not in key_names

    def test_ignores_non_secret_vars(self, secrets_repo: Path) -> None:
        matches = scan_repo_for_secrets(secrets_repo)
        key_names = {m.key_name for m in matches}
        assert "SAFE_VAR" not in key_names

    def test_skips_venv_directory(self, tmp_path: Path) -> None:
        venv_file = tmp_path / ".venv" / "lib" / "app.py"
        venv_file.parent.mkdir(parents=True)
        venv_file.write_text('API_KEY = "real-key"\n', encoding="utf-8")
        matches = scan_repo_for_secrets(tmp_path)
        assert len(matches) == 0

    def test_finds_seeded_secret_in_vulnerable_app(self) -> None:
        repo_root = Path("examples/vulnerable-fastapi").resolve()
        if not repo_root.exists():
            pytest.skip("vulnerable-fastapi example not available")
        matches = scan_repo_for_secrets(repo_root)
        key_names = {m.key_name for m in matches}
        assert "ADMIN_API_KEY" in key_names


class TestSecretMatchToCandidateFinding:
    def test_produces_valid_finding(self) -> None:
        match = SecretMatch(
            line_number=9,
            key_name="ADMIN_API_KEY",
            value="demo-admin-key-please-rotate",
            file_path="app.py",
        )
        finding = secret_match_to_candidate_finding(match, scan_id="scan-1", workspace_id="local")
        assert finding.vuln_class == VulnerabilityClass.SECRETS
        assert "ADMIN_API_KEY" in finding.title
        assert finding.confidence.value == "medium"
        assert finding.source_refs[0].file_path == "app.py"
        assert finding.source_refs[0].start_line == 9
        assert finding.metadata["key_name"] == "ADMIN_API_KEY"

    def test_finding_id_is_fingerprint_prefix(self) -> None:
        match = SecretMatch(
            line_number=9,
            key_name="ADMIN_API_KEY",
            value="secret",
            file_path="app.py",
        )
        finding_a = secret_match_to_candidate_finding(match, scan_id="scan-1")
        finding_b = secret_match_to_candidate_finding(match, scan_id="scan-2")
        assert finding_a.id == finding_b.id
