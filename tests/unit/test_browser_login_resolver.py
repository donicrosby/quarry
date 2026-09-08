"""BrowserLoginResolver — TDD for tasks 5.2/5.3 (live-exploitation-loop, ADR-023).

Browser login lets the exploitation loop authenticate to JS/SSO targets an httpx POST
can't reach. It runs worker-side only; the agent never sees the browser, the session,
or any secret — only the profile name. Playwright is an optional extra, imported
lazily, so non-browser scans never require it.

Locked in here:

- With a configured ``browser_login`` profile, the resolver drives the declarative
  flow, evaluates the ``SuccessCheck`` in code, captures the session, caches it, and
  reuses it on the next call (no second browser launch).
- A TOTP-gated step is filled with the code from the TOTP provider (credential path).
- Secrets (password, TOTP, captured session) are registered in the scrubber — no
  credential leaks into artifacts; the credential is referenced by profile name only.
- With Playwright absent, the resolver fails with an actionable error.
"""

from __future__ import annotations

from typing import Any

import pytest

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    BrowserLoginStep,
    SecretRef,
    SuccessCheck,
    TotpConfig,
)
from quarry_activities.browser_login import (
    BrowserLoginResolver,
    BrowserLoginUnavailableError,
)
from quarry_activities.credentials import CredentialCache
from quarry_models.redaction import Scrubber

_PASSWORD_ENV = "QUARRY_SECRET_BROWSER_PW"
_TOTP_SEED_ENV = "QUARRY_SECRET_BROWSER_TOTP"


class _FakeTotp:
    def now(self) -> str:
        return "654321"


class _FakeBrowser:
    """A scripted stand-in for a Playwright session — no real browser."""

    def __init__(self) -> None:
        self.filled: dict[str, str] = {}
        self.clicked: list[str] = []
        self.url = "http://localhost:8000/login"
        self.closed = False

    def navigate(self, url: str) -> None:
        self.url = url

    def fill(self, selector: str, value: str) -> None:
        self.filled[selector] = value

    def click(self, selector: str) -> None:
        self.clicked.append(selector)
        # Submitting the login form lands on the post-login dashboard.
        if selector == "#submit":
            self.url = "http://localhost:8000/dashboard"

    def wait_for(self, selector: str) -> None:  # noqa: ARG002
        return None

    def current_url(self) -> str:
        return self.url

    def has_selector(self, selector: str) -> bool:  # noqa: ARG002
        return True

    def has_text(self, text: str) -> bool:  # noqa: ARG002
        return True

    def storage_state(self) -> dict[str, Any]:
        return {"cookies": [{"name": "session", "value": "sess-token-xyz"}]}

    def close(self) -> None:
        self.closed = True


def _browser_profile() -> AuthProfile:
    return AuthProfile(
        name="app-browser",
        kind=AuthProfileKind.BROWSER_LOGIN,
        username="alice",
        secret_ref=SecretRef(env=_PASSWORD_ENV),
        totp=TotpConfig(seed_ref=SecretRef(env=_TOTP_SEED_ENV)),
        browser_login=BrowserLoginStep(
            start_url="/login",
            username_selector="#user",
            password_selector="#pass",
            submit_selector="#submit",
            otp_selector="#otp",
            success=SuccessCheck(
                kind="url_matches", value="/dashboard", description="lands on dashboard"
            ),
        ),
    )


class TestMissingPlaywright:
    def test_missing_playwright_raises_actionable_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "hunter2")
        monkeypatch.setenv(_TOTP_SEED_ENV, "JBSWY3DPEHPK3PXP")
        resolver = BrowserLoginResolver()  # default factory → real Playwright (absent)
        with pytest.raises(BrowserLoginUnavailableError) as exc:
            resolver.resolve(
                _browser_profile(),
                CredentialCache("s1"),
                Scrubber(),
                allowed_hosts=("localhost",),
                target_host="localhost",
                target_port=8000,
            )
        assert "playwright" in str(exc.value).lower()
        assert "browser" in str(exc.value).lower()  # install-extra hint


class TestBrowserLoginResolution:
    def test_establishes_and_reuses_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "hunter2")
        monkeypatch.setenv(_TOTP_SEED_ENV, "JBSWY3DPEHPK3PXP")
        launches: list[_FakeBrowser] = []

        def factory(**_: Any) -> _FakeBrowser:
            b = _FakeBrowser()
            launches.append(b)
            return b

        cache = CredentialCache("s1")
        scrubber = Scrubber()
        resolver = BrowserLoginResolver(browser_factory=factory, totp_provider=_FakeTotp())

        cred = resolver.resolve(
            _browser_profile(),
            cache,
            scrubber,
            allowed_hosts=("localhost",),
            target_host="localhost",
            target_port=8000,
        )
        assert cred is not None
        # Session captured as a reusable credential referenced by profile NAME only.
        assert cred.profile_name == "app-browser"
        assert cred.header_name == "Cookie"
        assert "sess-token-xyz" in cred.header_value
        assert len(launches) == 1

        # Second resolve is a cache hit — no second browser launch.
        cred2 = resolver.resolve(
            _browser_profile(),
            cache,
            scrubber,
            allowed_hosts=("localhost",),
            target_host="localhost",
            target_port=8000,
        )
        assert cred2 is not None
        assert len(launches) == 1

    def test_totp_step_filled_from_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "hunter2")
        monkeypatch.setenv(_TOTP_SEED_ENV, "JBSWY3DPEHPK3PXP")
        browser = _FakeBrowser()

        def factory(**_: Any) -> _FakeBrowser:
            return browser

        resolver = BrowserLoginResolver(browser_factory=factory, totp_provider=_FakeTotp())
        resolver.resolve(
            _browser_profile(),
            CredentialCache("s1"),
            Scrubber(),
            allowed_hosts=("localhost",),
            target_host="localhost",
            target_port=8000,
        )
        assert browser.filled["#user"] == "alice"
        assert browser.filled["#pass"] == "hunter2"
        assert browser.filled["#otp"] == "654321"

    def test_secrets_registered_in_scrubber(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "hunter2")
        monkeypatch.setenv(_TOTP_SEED_ENV, "JBSWY3DPEHPK3PXP")
        scrubber = Scrubber()

        def factory(**_: Any) -> _FakeBrowser:
            return _FakeBrowser()

        resolver = BrowserLoginResolver(browser_factory=factory, totp_provider=_FakeTotp())
        resolver.resolve(
            _browser_profile(),
            CredentialCache("s1"),
            scrubber,
            allowed_hosts=("localhost",),
            target_host="localhost",
            target_port=8000,
        )
        redacted = scrubber.scrub("pw=hunter2 session=sess-token-xyz").text
        assert "hunter2" not in redacted
        assert "sess-token-xyz" not in redacted

    def test_out_of_scope_host_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "hunter2")
        monkeypatch.setenv(_TOTP_SEED_ENV, "JBSWY3DPEHPK3PXP")

        def factory(**_: Any) -> _FakeBrowser:
            return _FakeBrowser()

        resolver = BrowserLoginResolver(browser_factory=factory, totp_provider=_FakeTotp())
        with pytest.raises(ValueError, match="allowed_hosts"):
            resolver.resolve(
                _browser_profile(),
                CredentialCache("s1"),
                Scrubber(),
                allowed_hosts=("localhost",),
                target_host="evil.example.com",
                target_port=8000,
            )

    def test_failed_success_check_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_PASSWORD_ENV, "hunter2")
        monkeypatch.setenv(_TOTP_SEED_ENV, "JBSWY3DPEHPK3PXP")

        class _StuckBrowser(_FakeBrowser):
            def click(self, selector: str) -> None:
                self.clicked.append(selector)  # never navigates to /dashboard

        def factory(**_: Any) -> _StuckBrowser:
            return _StuckBrowser()

        resolver = BrowserLoginResolver(browser_factory=factory, totp_provider=_FakeTotp())
        cred = resolver.resolve(
            _browser_profile(),
            CredentialCache("s1"),
            Scrubber(),
            allowed_hosts=("localhost",),
            target_host="localhost",
            target_port=8000,
        )
        assert cred is None
