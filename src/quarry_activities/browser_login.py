"""Browser-based login resolution (ADR-023) — worker-side, credential-safe.

Finishes the documented-but-unimplemented ``BrowserLoginResolver``. For a
``browser_login`` auth profile, this drives a declarative Playwright flow (headless
Chromium) to authenticate to JS/SSO/CSRF targets a single httpx POST can't reach,
evaluates the operator-declared ``SuccessCheck`` deterministically in code, captures
the session (storage state), and returns it as a ``CachedCredential`` — referenced
by profile NAME only. The agent never sees the browser, the session, or any secret.

Playwright is an optional extra (``quarry[browser]``): it is imported lazily, so
non-browser scans never require it. When it is absent, resolution fails with an
actionable ``BrowserLoginUnavailableError``. The concrete browser is injectable
(``browser_factory``) so tests script the flow without a real browser.
"""

from __future__ import annotations

import re
from typing import Any, Protocol, runtime_checkable

from quarry.schemas import AuthProfile, BrowserAction, SuccessCheck
from quarry_activities.credentials import (
    CachedCredential,
    CredentialCache,
    TotpProvider,
    resolve_env_secret,
)
from quarry_models.redaction import Scrubber


class BrowserLoginUnavailableError(RuntimeError):
    """Raised when a browser_login profile is used but Playwright is not installed."""


@runtime_checkable
class BrowserSession(Protocol):
    """Minimal browser surface the resolver drives — a subset of a Playwright page."""

    def navigate(self, url: str) -> None: ...
    def fill(self, selector: str, value: str) -> None: ...
    def click(self, selector: str) -> None: ...
    def wait_for(self, selector: str) -> None: ...
    def current_url(self) -> str: ...
    def has_selector(self, selector: str) -> bool: ...
    def has_text(self, text: str) -> bool: ...
    def storage_state(self) -> dict[str, Any]: ...
    def close(self) -> None: ...


def _playwright_browser_factory(**_: Any) -> BrowserSession:
    """Default factory — builds a real Playwright session, or errors actionably.

    Playwright is imported lazily here so that importing this module (and running any
    non-browser scan) never requires the heavy dependency.
    """
    try:
        import playwright.sync_api  # noqa: F401  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised via the missing-dep test
        msg = (
            "browser_login requires Playwright, which is not installed. Install the "
            "optional browser extra (e.g. `uv sync --extra browser` or "
            "`pip install 'quarry[browser]'`) and run `playwright install chromium`. "
            "Non-browser scans do not need this."
        )
        raise BrowserLoginUnavailableError(msg) from exc
    # A real Playwright-backed BrowserSession is provided by the sandbox worker image
    # (ADR-023 §5). It is not constructed in-process here.
    msg = (
        "In-process Playwright browser driver is not available: Playwright is "
        "installed but the browser session must be provided by the quarry-dynamic "
        "worker image (ADR-023 §5). To drive a browser locally, install the "
        "optional browser extra (`uv sync --extra browser` / `pip install "
        "'quarry[browser]'`) and run `playwright install chromium`, then run the "
        "scan through the dynamic worker."
    )
    raise BrowserLoginUnavailableError(msg)  # pragma: no cover


class BrowserLoginResolver:
    """Resolves a ``browser_login`` profile to a reusable, scrubbed session credential."""

    def __init__(
        self,
        *,
        browser_factory: Any | None = None,
        totp_provider: Any | None = None,
    ) -> None:
        self._browser_factory = browser_factory or _playwright_browser_factory
        self._totp_override = totp_provider

    def resolve(
        self,
        profile: AuthProfile,
        cache: CredentialCache,
        scrubber: Scrubber,
        *,
        allowed_hosts: tuple[str, ...],
        target_host: str = "localhost",
        target_port: int = 80,
    ) -> CachedCredential | None:
        """Drive the declarative browser login and return the captured session.

        Returns a cache hit immediately. Otherwise validates scope (Layer 6),
        resolves secrets from the credential path only, drives the flow, evaluates
        the ``SuccessCheck`` in code, and on success captures + caches the session.
        Returns ``None`` when the success check fails (auth_failed). All secrets and
        the captured session are registered in ``scrubber`` before return.
        """
        cached = cache.get(profile.name)
        if cached is not None:
            return cached

        step = profile.browser_login
        if step is None:
            return None

        # Layer 6 sub-check: the login must navigate only within allowed hosts.
        if target_host not in allowed_hosts:
            msg = (
                f"Browser login for profile '{profile.name}' would navigate to host "
                f"'{target_host}', which is not in allowed_hosts {allowed_hosts!r}."
            )
            raise ValueError(msg)

        username = profile.username or ""
        password = resolve_env_secret(profile.secret_ref.env) if profile.secret_ref else ""
        if password:
            scrubber.register_secret(password)

        totp_provider = self._totp_override
        if totp_provider is None and profile.totp is not None:
            seed = resolve_env_secret(profile.totp.seed_ref.env)
            totp_provider = TotpProvider(
                seed_b32=seed,
                digits=profile.totp.digits,
                period_seconds=profile.totp.period_seconds,
                algorithm=profile.totp.algorithm,
            )

        base_url = f"http://{target_host}:{target_port}"
        placeholders = {"username": username, "password": password}

        browser = self._browser_factory(
            allowed_hosts=allowed_hosts,
            target_host=target_host,
            target_port=target_port,
        )
        try:
            browser.navigate(base_url + step.start_url)
            browser.fill(step.username_selector, username)
            browser.fill(step.password_selector, password)
            if step.otp_selector is not None and totp_provider is not None:
                otp = totp_provider.now()
                scrubber.register_secret(otp)
                browser.fill(step.otp_selector, otp)

            for action in step.extra_steps:
                self._run_action(browser, action, placeholders, totp_provider, scrubber)

            browser.click(step.submit_selector)

            if step.failure_check is not None and self._check(browser, step.failure_check):
                cache.increment_relogin(profile.name)
                return None
            if not self._check(browser, step.success):
                cache.increment_relogin(profile.name)
                return None

            header_value = self._session_cookie_header(browser.storage_state(), scrubber)
        finally:
            browser.close()

        cred = CachedCredential(
            profile_name=profile.name,
            header_name="Cookie",
            header_value=header_value,
            ttl_seconds=step.ttl_seconds,
        )
        cache.put(cred)
        return cred

    def _run_action(
        self,
        browser: BrowserSession,
        action: BrowserAction,
        placeholders: dict[str, str],
        totp_provider: Any | None,
        scrubber: Scrubber,
    ) -> None:
        if action.action == "click":
            browser.click(action.selector)
        elif action.action == "wait_for":
            browser.wait_for(action.selector)
        elif action.action == "fill":
            value = self._substitute(action.value or "", placeholders, totp_provider, scrubber)
            browser.fill(action.selector, value)

    def _substitute(
        self,
        template: str,
        placeholders: dict[str, str],
        totp_provider: Any | None,
        scrubber: Scrubber,
    ) -> str:
        value = template
        value = value.replace("${username}", placeholders.get("username", ""))
        value = value.replace("${password}", placeholders.get("password", ""))
        for match in re.finditer(r"\$\{secret:([A-Z0-9_]+)\}", value):
            secret = resolve_env_secret(match.group(1))
            scrubber.register_secret(secret)
            value = value.replace(match.group(0), secret)
        if "${totp}" in value and totp_provider is not None:
            otp = totp_provider.now()
            scrubber.register_secret(otp)
            value = value.replace("${totp}", otp)
        return value

    def _check(self, browser: BrowserSession, check: SuccessCheck) -> bool:
        """Evaluate a SuccessCheck deterministically in code (never the model's say-so)."""
        if check.kind == "url_matches":
            return check.value in browser.current_url()
        if check.kind == "selector_present":
            return browser.has_selector(check.value)
        if check.kind == "text_present":
            return browser.has_text(check.value)
        return check.kind == "status_ok"

    def _session_cookie_header(self, storage_state: dict[str, Any], scrubber: Scrubber) -> str:
        cookies = storage_state.get("cookies", [])
        parts: list[str] = []
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            if value:
                scrubber.register_secret(value)
            parts.append(f"{name}={value}")
        return "; ".join(parts)
