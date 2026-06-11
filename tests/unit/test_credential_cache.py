"""Tests for CredentialCache (ADR-018 §7).

Written RED first — these fail until credentials.py exists.

Key invariants:
- CredentialCache is per-run only; its constructor takes a scan_id.
- Resolved credentials are stored keyed by profile name.
- TTL expiry causes a cache miss (returns None).
- 401 → re-login once → second 401 yields needs_manual_review.
- Resolved values are NEVER persisted; only in-memory.
"""

from __future__ import annotations

from quarry_activities.credentials import CachedCredential, CredentialCache


class TestCredentialCacheBasics:
    def test_cache_miss_returns_none(self) -> None:
        cache = CredentialCache(scan_id="scan-001")
        assert cache.get("admin-profile") is None

    def test_store_and_retrieve(self) -> None:
        cache = CredentialCache(scan_id="scan-001")
        cred = CachedCredential(
            profile_name="admin-profile",
            header_name="Authorization",
            header_value="Bearer tok123",
        )
        cache.put(cred)
        retrieved = cache.get("admin-profile")
        assert retrieved is not None
        assert retrieved.header_value == "Bearer tok123"

    def test_cache_is_per_scan_id(self) -> None:
        """Two CredentialCache instances with different scan IDs are independent."""
        c1 = CredentialCache(scan_id="scan-A")
        c2 = CredentialCache(scan_id="scan-B")
        cred = CachedCredential(
            profile_name="user-profile",
            header_name="Authorization",
            header_value="Bearer abc",
        )
        c1.put(cred)
        # c2 must not see c1's credential
        assert c2.get("user-profile") is None

    def test_invalidate_removes_credential(self) -> None:
        cache = CredentialCache(scan_id="scan-001")
        cred = CachedCredential(
            profile_name="admin-profile",
            header_name="Authorization",
            header_value="Bearer tok",
        )
        cache.put(cred)
        cache.invalidate("admin-profile")
        assert cache.get("admin-profile") is None


class TestCredentialCacheTTL:
    def test_credential_expired_by_ttl_returns_none(self) -> None:
        cache = CredentialCache(scan_id="scan-ttl")
        cred = CachedCredential(
            profile_name="short-lived",
            header_name="Authorization",
            header_value="Bearer short",
            ttl_seconds=0,  # immediately expired
        )
        cache.put(cred)
        # TTL=0 means already expired
        assert cache.get("short-lived") is None

    def test_credential_within_ttl_is_returned(self) -> None:
        cache = CredentialCache(scan_id="scan-ttl2")
        cred = CachedCredential(
            profile_name="long-lived",
            header_name="Authorization",
            header_value="Bearer long",
            ttl_seconds=3600,  # 1 hour
        )
        cache.put(cred)
        assert cache.get("long-lived") is not None

    def test_no_ttl_credential_never_expires(self) -> None:
        """Credentials without TTL persist for the lifetime of the cache."""
        cache = CredentialCache(scan_id="scan-no-ttl")
        cred = CachedCredential(
            profile_name="static-key",
            header_name="X-Api-Key",
            header_value="key123",
            ttl_seconds=None,
        )
        cache.put(cred)
        assert cache.get("static-key") is not None


class TestCredentialCacheReloginLogic:
    def test_increment_relogin_count(self) -> None:
        """After a 401, increment_relogin tracks how many re-logins have been attempted."""
        cache = CredentialCache(scan_id="scan-relogin")
        assert cache.relogin_count("admin-profile") == 0
        cache.increment_relogin("admin-profile")
        assert cache.relogin_count("admin-profile") == 1

    def test_needs_manual_review_after_second_401(self) -> None:
        """Two re-logins without success triggers needs_manual_review flag."""
        cache = CredentialCache(scan_id="scan-relogin2")
        cache.increment_relogin("admin-profile")
        cache.increment_relogin("admin-profile")
        assert cache.needs_manual_review("admin-profile") is True

    def test_one_relogin_not_yet_manual_review(self) -> None:
        cache = CredentialCache(scan_id="scan-relogin3")
        cache.increment_relogin("admin-profile")
        assert cache.needs_manual_review("admin-profile") is False
