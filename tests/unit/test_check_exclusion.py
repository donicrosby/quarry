"""Tests for the check_exclusion module-level helper in quarry_tools/runner.py.

Written RED first. These fail until check_exclusion is added to runner.py.

check_exclusion(request_target, vuln_class, exclusion_set) -> ScopeExclusion | None
is the frozen public helper the scope-guard contract is built on (week-14 plan).
"""

from __future__ import annotations

from quarry.schemas import ScopeExclusion


def _exc(kind: str, value: str, block_dynamic: bool = True, reason: str = "test") -> ScopeExclusion:
    return ScopeExclusion(kind=kind, value=value, reason=reason, block_dynamic=block_dynamic)


class TestCheckExclusion:
    def test_import(self) -> None:
        from quarry_tools.runner import check_exclusion

        assert callable(check_exclusion)

    def test_no_match_returns_none(self) -> None:
        from quarry_tools.runner import check_exclusion

        exc = _exc("route", "/admin/*")
        result = check_exclusion("/users/profile", None, [exc])
        assert result is None

    def test_route_match_by_path_returns_exclusion(self) -> None:
        """A route exclusion whose value matches the target path returns the exclusion."""
        from quarry_tools.runner import check_exclusion

        exc = _exc("route", "/admin/*")
        result = check_exclusion("/admin/users", None, [exc])
        assert result is exc

    def test_path_glob_match_returns_exclusion(self) -> None:
        """src/billing/** maps to /billing/ prefix — a target under /billing/ matches."""
        from quarry_tools.runner import check_exclusion

        exc = _exc("path_glob", "src/billing/**")
        result = check_exclusion("/billing/invoices", None, [exc])
        assert result is exc

    def test_vuln_class_match_returns_exclusion(self) -> None:
        from quarry_tools.runner import check_exclusion

        exc = _exc("vuln_class", "sqli")
        result = check_exclusion("/any/path", "sqli", [exc])
        assert result is exc

    def test_vuln_class_no_match_returns_none(self) -> None:
        from quarry_tools.runner import check_exclusion

        exc = _exc("vuln_class", "sqli")
        result = check_exclusion("/any/path", "command_injection", [exc])
        assert result is None

    def test_block_dynamic_false_returns_none(self) -> None:
        """block_dynamic=False exclusions must be ignored by check_exclusion."""
        from quarry_tools.runner import check_exclusion

        exc = _exc("route", "/admin/*", block_dynamic=False)
        result = check_exclusion("/admin/users", None, [exc])
        assert result is None

    def test_first_match_wins(self) -> None:
        """When multiple exclusions match, the first in list order is returned."""
        from quarry_tools.runner import check_exclusion

        exc_a = _exc("route", "/admin/*", reason="first")
        exc_b = _exc("route", "/admin/*", reason="second")
        result = check_exclusion("/admin/users", None, [exc_a, exc_b])
        assert result is exc_a

    def test_empty_exclusion_set_returns_none(self) -> None:
        from quarry_tools.runner import check_exclusion

        result = check_exclusion("/any/path", None, [])
        assert result is None

    def test_vuln_class_none_skips_vuln_class_lookup(self) -> None:
        """When vuln_class is None, vuln_class exclusions must not match."""
        from quarry_tools.runner import check_exclusion

        exc = _exc("vuln_class", "sqli")
        result = check_exclusion("/any/path", None, [exc])
        assert result is None

    def test_returns_the_exclusion_object_not_a_copy(self) -> None:
        """The function must return the exact ScopeExclusion instance from the list."""
        from quarry_tools.runner import check_exclusion

        exc = _exc("vuln_class", "command_injection")
        result = check_exclusion("/x", "command_injection", [exc])
        assert result is exc
