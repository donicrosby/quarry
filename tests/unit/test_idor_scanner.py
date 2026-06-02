"""Tests for the IDOR candidate scanner plugin.

These tests define the expected behavior for detecting Insecure Direct Object Reference
(IDOR) vulnerabilities in FastAPI routes. The scanner should identify routes with path
parameters that lack proper authorization checks.

RED PHASE: These tests are expected to FAIL until the IDOR scanner is implemented.
"""

import pytest

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.schemas import (
    AttackSurfaceItem,
    Confidence,
    VulnerabilityClass,
)

# Import will fail until scanner is implemented - that's expected for RED phase
from quarry_plugins.vuln_classes.idor import (
    IdrMatch,
    idor_match_to_candidate_finding,
    scan_handler_for_idor,
)


class TestIdorDetectsUsersRoute:
    """Test that IDOR scanner detects routes with path parameters lacking auth."""

    def test_idor_detects_users_route(self) -> None:
        """Given AttackSurfaceItem with route='/users/{user_id}' and handler source
        that lacks auth checks, scanner should return CandidateFinding with
        vuln_class=VulnerabilityClass.IDOR."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-1",
            scan_id="scan-1",
            route="/users/{user_id}",
            method="GET",
            handler_file="routes/users.py",
            handler_symbol="get_user",
            params=["user_id"],
            auth_required=False,
        )

        # Handler source without authorization checks
        handler_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"user_id": user_id}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)

        assert len(matches) == 1
        match = matches[0]
        assert match.route == "/users/{user_id}"
        assert match.path_param == "user_id"
        assert match.handler_file == "routes/users.py"
        assert match.line_number == 6

    def test_idor_detects_multiple_path_params(self) -> None:
        """Scanner should detect multiple path parameters in a route."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-2",
            scan_id="scan-1",
            route="/organizations/{org_id}/users/{user_id}",
            method="GET",
            handler_file="routes/orgs.py",
            handler_symbol="get_org_user",
            params=["org_id", "user_id"],
            auth_required=False,
        )

        handler_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/organizations/{org_id}/users/{user_id}")
async def get_org_user(org_id: int, user_id: int):
    return {"org_id": org_id, "user_id": user_id}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)

        # Should detect at least one IDOR vulnerability
        assert len(matches) >= 1
        path_params = {m.path_param for m in matches}
        assert "user_id" in path_params or "org_id" in path_params


class TestIdorIgnoresNoPathParams:
    """Test that routes without path parameters are NOT flagged."""

    def test_idor_ignores_health_endpoint(self) -> None:
        """Routes like /health should NOT be flagged."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-3",
            scan_id="scan-1",
            route="/health",
            method="GET",
            handler_file="routes/health.py",
            handler_symbol="health_check",
            params=[],
            auth_required=False,
        )

        handler_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health_check():
    return {"status": "ok"}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)
        assert len(matches) == 0

    def test_idor_ignores_config_endpoint(self) -> None:
        """Routes like /config should NOT be flagged."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-4",
            scan_id="scan-1",
            route="/config",
            method="GET",
            handler_file="routes/config.py",
            handler_symbol="get_config",
            params=[],
            auth_required=False,
        )

        handler_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/config")
async def get_config():
    return {"setting": "value"}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)
        assert len(matches) == 0

    def test_idor_ignores_static_routes(self) -> None:
        """Static routes without path parameters should NOT be flagged."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-5",
            scan_id="scan-1",
            route="/api/v1/status",
            method="GET",
            handler_file="routes/status.py",
            handler_symbol="get_status",
            params=[],
            auth_required=False,
        )

        handler_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/api/v1/status")
async def get_status():
    return {"status": "running"}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)
        assert len(matches) == 0


class TestIdorIgnoresRoutesWithAuth:
    """Test that routes with path parameters BUT with auth checks are NOT flagged."""

    def test_idor_ignores_routes_with_current_user(self) -> None:
        """Route with {user_id} but handler has `current_user` check should NOT be flagged."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-6",
            scan_id="scan-1",
            route="/users/{user_id}",
            method="GET",
            handler_file="routes/users.py",
            handler_symbol="get_user",
            params=["user_id"],
            auth_required=True,
            auth_hint="Depends(get_current_user)",
        )

        handler_source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/users/{user_id}")
async def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    return {"user_id": user_id, "requested_by": current_user}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)
        assert len(matches) == 0

    def test_idor_ignores_routes_with_get_current_user(self) -> None:
        """Route with {user_id} but handler has `get_current_user` check should NOT be flagged."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-7",
            scan_id="scan-1",
            route="/accounts/{account_id}",
            method="GET",
            handler_file="routes/accounts.py",
            handler_symbol="get_account",
            params=["account_id"],
            auth_required=True,
            auth_hint="Depends(get_current_user)",
        )

        handler_source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/accounts/{account_id}")
async def get_account(account_id: int, user: dict = Depends(get_current_user)):
    return {"account_id": account_id}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)
        assert len(matches) == 0

    def test_idor_ignores_routes_with_require_auth(self) -> None:
        """Route with path param but explicit auth check should NOT be flagged."""
        attack_surface_item = AttackSurfaceItem(
            id="asm-8",
            scan_id="scan-1",
            route="/documents/{doc_id}",
            method="GET",
            handler_file="routes/docs.py",
            handler_symbol="get_document",
            params=["doc_id"],
            auth_required=True,
        )

        handler_source = """
from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.get("/documents/{doc_id}")
async def get_document(doc_id: int, current_user: dict = None):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"doc_id": doc_id}
"""

        matches = scan_handler_for_idor(attack_surface_item, handler_source)
        assert len(matches) == 0


class TestIdorRootCauseKeyStable:
    """Test that fingerprint and root_cause_key are stable (no scan_id or timestamp)."""

    def test_idor_root_cause_key_stable(self) -> None:
        """fingerprint should not include scan_id or timestamp."""
        match = IdrMatch(
            line_number=6,
            route="/users/{user_id}",
            path_param="user_id",
            handler_file="routes/users.py",
            handler_symbol="get_user",
        )

        # Compute root cause key twice - should be identical
        root_cause_key_1 = compute_root_cause_key(
            vuln_class=VulnerabilityClass.IDOR,
            file_path=match.handler_file,
            sink=f"{match.handler_symbol}:{match.path_param}",
        )

        root_cause_key_2 = compute_root_cause_key(
            vuln_class=VulnerabilityClass.IDOR,
            file_path=match.handler_file,
            sink=f"{match.handler_symbol}:{match.path_param}",
        )

        assert root_cause_key_1 == root_cause_key_2
        # Should not contain scan-specific data
        assert "scan" not in root_cause_key_1.lower()

    def test_idor_fingerprint_stable_across_scans(self) -> None:
        """Fingerprint should be identical for the same vulnerability across different scans."""
        match = IdrMatch(
            line_number=6,
            route="/users/{user_id}",
            path_param="user_id",
            handler_file="routes/users.py",
            handler_symbol="get_user",
        )

        fp1 = compute_fingerprint(
            vuln_class=VulnerabilityClass.IDOR,
            file_path=match.handler_file,
            start_line=match.line_number,
            key_name=match.path_param,
            evidence_kind="missing_auth_check",
        )

        fp2 = compute_fingerprint(
            vuln_class=VulnerabilityClass.IDOR,
            file_path=match.handler_file,
            start_line=match.line_number,
            key_name=match.path_param,
            evidence_kind="missing_auth_check",
        )

        assert fp1 == fp2
        # Should be 64-char hex (SHA-256)
        assert len(fp1) == 64
        assert all(c in "0123456789abcdef" for c in fp1)


class TestIdorSetsVulnClassIdor:
    """Test that candidate findings have vuln_class=VulnerabilityClass.IDOR."""

    def test_idor_sets_vuln_class_idor(self) -> None:
        """vuln_class == VulnerabilityClass.IDOR."""
        match = IdrMatch(
            line_number=6,
            route="/users/{user_id}",
            path_param="user_id",
            handler_file="routes/users.py",
            handler_symbol="get_user",
        )

        finding = idor_match_to_candidate_finding(
            match,
            scan_id="scan-1",
            workspace_id="local",
        )

        assert finding.vuln_class == VulnerabilityClass.IDOR
        assert finding.confidence == Confidence.MEDIUM
        assert "user_id" in finding.title or "IDOR" in finding.title
        assert len(finding.source_refs) == 1
        assert finding.source_refs[0].file_path == "routes/users.py"
        assert finding.source_refs[0].start_line == 6

    def test_finding_has_proper_metadata(self) -> None:
        """CandidateFinding should include relevant metadata."""
        match = IdrMatch(
            line_number=10,
            route="/api/v1/orders/{order_id}",
            path_param="order_id",
            handler_file="routes/orders.py",
            handler_symbol="get_order",
        )

        finding = idor_match_to_candidate_finding(
            match,
            scan_id="scan-2",
            workspace_id="test-workspace",
            created_by="idor-scanner",
        )

        assert finding.workspace_id == "test-workspace"
        assert finding.scan_id == "scan-2"
        assert finding.created_by == "idor-scanner"
        assert finding.metadata["path_param"] == "order_id"
        assert finding.metadata["route"] == "/api/v1/orders/{order_id}"
        assert finding.metadata["handler_symbol"] == "get_order"

    def test_finding_id_is_fingerprint_prefix(self) -> None:
        """Finding ID should be derived from fingerprint (first 32 chars)."""
        match = IdrMatch(
            line_number=6,
            route="/users/{user_id}",
            path_param="user_id",
            handler_file="routes/users.py",
            handler_symbol="get_user",
        )

        finding_a = idor_match_to_candidate_finding(match, scan_id="scan-1")
        finding_b = idor_match_to_candidate_finding(match, scan_id="scan-2")

        # Same vulnerability should have same ID regardless of scan_id
        assert finding_a.id == finding_b.id
        assert len(finding_a.id) == 32  # First 32 chars of SHA-256


class TestIdorMatchDataclass:
    """Test the IdrMatch dataclass structure."""

    def test_idor_match_has_required_fields(self) -> None:
        """IdrMatch should have all required fields."""
        match = IdrMatch(
            line_number=5,
            route="/items/{item_id}",
            path_param="item_id",
            handler_file="routes/items.py",
            handler_symbol="get_item",
        )

        assert match.line_number == 5
        assert match.route == "/items/{item_id}"
        assert match.path_param == "item_id"
        assert match.handler_file == "routes/items.py"
        assert match.handler_symbol == "get_item"

    def test_idor_match_is_frozen(self) -> None:
        """IdrMatch should be immutable (frozen dataclass)."""
        match = IdrMatch(
            line_number=5,
            route="/items/{item_id}",
            path_param="item_id",
            handler_file="routes/items.py",
            handler_symbol="get_item",
        )

        # Attempting to modify should raise an error
        from dataclasses import FrozenInstanceError

        def _try_set_attr(obj: object, attr: str, value: object) -> None:
            setattr(obj, attr, value)

        with pytest.raises((AttributeError, TypeError, FrozenInstanceError)):
            _try_set_attr(match, "line_number", 10)
