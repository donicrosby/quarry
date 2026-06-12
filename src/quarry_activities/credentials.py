"""Credential resolution for the quarry-control worker (ADR-018 §7).

Credential values are resolved ONLY inside the quarry-control worker at
activity dispatch time.  The agent, workflow code, and ToolRunner see only
the *profile name* string — never a concrete token, password, or cookie.

Key types
---------
CachedCredential  — resolved credential stored in memory for one scan.
CredentialCache   — per-run in-memory store (never persisted).
TotpProvider      — RFC-6238 TOTP generator backed by an in-tree _totp().
CredentialProvider — protocol (for typing / testing).
resolve_credentials — entry point called by http_request_activity.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import httpx

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    CredentialExtract,
)
from quarry_models.redaction import Scrubber

# ---------------------------------------------------------------------------
# _totp: in-tree RFC-6238 implementation (no pyotp dependency)
# ---------------------------------------------------------------------------


def _totp(
    seed_b32: str,
    counter: int,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> str:
    """Compute one TOTP code for *counter* using the given base32 seed.

    Implements RFC 4226 (HOTP) over the time-step counter per RFC 6238.
    Only SHA1/SHA256/SHA512 are supported (same set as RFC 6238 §4).
    """
    key = base64.b32decode(seed_b32.upper())
    msg = struct.pack(">Q", counter)

    digest_map = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }
    digestmod = digest_map.get(algorithm.upper())
    if digestmod is None:
        msg_err = f"Unsupported TOTP algorithm: {algorithm!r}. Must be SHA1, SHA256, or SHA512."
        raise ValueError(msg_err)

    hmac_hash = hmac.new(key, msg, digestmod).digest()
    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack(">I", hmac_hash[offset : offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10**digits)
    return str(code).zfill(digits)


# ---------------------------------------------------------------------------
# TotpProvider
# ---------------------------------------------------------------------------


class TotpProvider:
    """RFC-6238 TOTP generator from a base32 seed.

    Uses the in-tree ``_totp()`` to avoid adding a ``pyotp`` dependency.
    Codes are NEVER cached — each ``now()`` call recomputes from the clock.
    """

    def __init__(
        self,
        seed_b32: str,
        digits: int = 6,
        period_seconds: int = 30,
        algorithm: str = "SHA1",
    ) -> None:
        self._seed_b32 = seed_b32
        self.digits = digits
        self.period_seconds = period_seconds
        self.algorithm = algorithm.upper()

    def now(self) -> str:
        """Return the TOTP code for the current time window."""
        counter = int(time.time()) // self.period_seconds
        return self.at_counter(counter)

    def at_counter(self, counter: int) -> str:
        """Return the TOTP code for a specific counter value (deterministic; for testing)."""
        return _totp(
            self._seed_b32,
            counter,
            digits=self.digits,
            algorithm=self.algorithm,
        )


# ---------------------------------------------------------------------------
# CachedCredential
# ---------------------------------------------------------------------------


@dataclass
class CachedCredential:
    """A resolved credential held in memory for the lifetime of one scan."""

    profile_name: str
    header_name: str  # e.g. "Authorization", "X-Api-Key", "Cookie"
    header_value: str  # e.g. "Bearer tok123"
    ttl_seconds: int | None = None  # None = never expire
    _stored_at: float = field(default_factory=time.time, repr=False, compare=False)

    def is_expired(self) -> bool:
        """Return True if this credential has passed its TTL."""
        if self.ttl_seconds is None:
            return False
        return time.time() >= self._stored_at + self.ttl_seconds


# ---------------------------------------------------------------------------
# CredentialCache
# ---------------------------------------------------------------------------


class CredentialCache:
    """Per-run, in-memory credential store.

    Instances are never shared across scans.  Nothing is persisted to disk or
    passed back through Temporal — the cache lives only for the duration of the
    activity worker process serving a given scan.
    """

    def __init__(self, scan_id: str) -> None:
        self._scan_id = scan_id
        self._store: dict[str, CachedCredential] = {}
        self._relogin_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def get(self, profile_name: str) -> CachedCredential | None:
        """Return the cached credential if it exists and has not expired."""
        cred = self._store.get(profile_name)
        if cred is None:
            return None
        if cred.is_expired():
            del self._store[profile_name]
            return None
        return cred

    def put(self, cred: CachedCredential) -> None:
        """Store a credential.  Immediately discards expired entries."""
        if not cred.is_expired():
            self._store[cred.profile_name] = cred

    def invalidate(self, profile_name: str) -> None:
        """Remove a credential from the cache (e.g. after a 401)."""
        self._store.pop(profile_name, None)

    # ------------------------------------------------------------------
    # Re-login tracking
    # ------------------------------------------------------------------

    def relogin_count(self, profile_name: str) -> int:
        """Number of times a re-login has been attempted for this profile."""
        return self._relogin_counts.get(profile_name, 0)

    def increment_relogin(self, profile_name: str) -> None:
        """Record one more re-login attempt for *profile_name*."""
        self._relogin_counts[profile_name] = self.relogin_count(profile_name) + 1

    def needs_manual_review(self, profile_name: str) -> bool:
        """Return True if two or more re-logins have been attempted without success."""
        return self.relogin_count(profile_name) >= 2


# ---------------------------------------------------------------------------
# CredentialProvider protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class CredentialProvider(Protocol):
    """Protocol for anything that can resolve a named auth profile."""

    def resolve(
        self,
        profile: AuthProfile,
        cache: CredentialCache,
        scrubber: Scrubber,
        *,
        allowed_hosts: tuple[str, ...],
        target_host: str = "localhost",
        target_port: int = 80,
    ) -> CachedCredential | None: ...


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_env_secret(env_name: str) -> str:
    """Read a secret from an environment variable; raise EnvironmentError if missing."""
    value = os.environ.get(env_name)
    if not value:
        msg = (
            f"Required environment variable '{env_name}' is not set. "
            "Set it in .env or the worker environment before running a scan "
            "with authenticated dynamic validation."
        )
        raise OSError(msg)
    return value


def _extract_from_response(response_body: str, extract: CredentialExtract) -> str:
    """Extract a token from a login response using the configured extraction strategy."""
    if extract.from_json is not None:
        # Minimal JSONPath: supports simple $.key patterns only.
        path = extract.from_json
        if path.startswith("$."):
            key = path[2:]
            try:
                data = json.loads(response_body)
                return str(data[key])
            except (json.JSONDecodeError, KeyError) as exc:
                msg = f"Could not extract '{path}' from login response: {exc}"
                raise ValueError(msg) from exc
        msg = f"Unsupported from_json path: {path!r}. Only simple $.key patterns are supported."
        raise ValueError(msg)

    if extract.from_cookie is not None:
        # Parse Set-Cookie style values — not implemented for this phase.
        msg = "from_cookie extraction is not yet implemented."
        raise NotImplementedError(msg)

    if extract.from_header is not None:
        msg = "from_header extraction is not yet implemented."
        raise NotImplementedError(msg)

    msg = "CredentialExtract must specify from_json, from_cookie, or from_header."
    raise ValueError(msg)


def _inject_as_header(
    value: str,
    inject_as: str,
    name_hint: str | None,
) -> tuple[str, str]:
    """Convert an extracted token to (header_name, header_value) based on inject_as."""
    if inject_as == "bearer":
        return "Authorization", f"Bearer {value}"
    if inject_as == "cookie":
        cookie_name = name_hint or "session"
        return "Cookie", f"{cookie_name}={value}"
    if inject_as == "header":
        if not name_hint:
            msg = "inject_as='header' requires name_hint to specify the header name."
            raise ValueError(msg)
        return name_hint, value
    msg = f"Unknown inject_as value: {inject_as!r}"
    raise ValueError(msg)


def _render_field_template(
    field_template: dict[str, str],
    *,
    totp_provider: TotpProvider | None = None,
) -> dict[str, str]:
    """Expand ${secret:ENV} and ${totp} placeholders in a login field_template."""
    rendered: dict[str, str] = {}
    for key, tmpl in field_template.items():
        value = tmpl
        # ${secret:ENV_VAR_NAME} → read env
        if "${secret:" in value:
            import re

            for match in re.finditer(r"\$\{secret:([A-Z0-9_]+)\}", value):
                env_name = match.group(1)
                secret_val = _resolve_env_secret(env_name)
                value = value.replace(match.group(0), secret_val)
        # ${totp} → generate TOTP code
        if "${totp}" in value:
            if totp_provider is None:
                msg = "Field template contains ${totp} but no TotpConfig was provided."
                raise ValueError(msg)
            value = value.replace("${totp}", totp_provider.now())
        rendered[key] = value
    return rendered


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def resolve_credentials(
    profile: AuthProfile,
    cache: CredentialCache,
    scrubber: Scrubber,
    *,
    allowed_hosts: tuple[str, ...],
    target_host: str = "localhost",
    target_port: int = 80,
) -> CachedCredential | None:
    """Resolve a named auth profile to a concrete ``CachedCredential``.

    Layers enforced here:
    - Cache hit: returns immediately without re-reading env or re-logging in.
    - Bearer/basic/static_header/cookie: reads env var; registers value in scrubber.
    - login_flow: validates target host is in allowed_hosts, POSTs credentials,
      extracts token; registers all secrets (input password + extracted token) in scrubber.
    - Returns None if no credentials are needed (e.g. unauthenticated profile).

    The resolved *header_value* is registered in *scrubber* before return so it is
    automatically stripped from any HTTP response body that re-enters a prompt.
    """
    # --- Cache hit ---
    cached = cache.get(profile.name)
    if cached is not None:
        return cached

    # --- Per-kind resolution ---
    if profile.kind == AuthProfileKind.BEARER:
        if profile.secret_ref is None:
            return None
        token = _resolve_env_secret(profile.secret_ref.env)
        scrubber.register_secret(token)
        cred = CachedCredential(
            profile_name=profile.name,
            header_name="Authorization",
            header_value=f"Bearer {token}",
        )
        cache.put(cred)
        return cred

    if profile.kind == AuthProfileKind.BASIC:
        if profile.secret_ref is None:
            return None
        password = _resolve_env_secret(profile.secret_ref.env)
        scrubber.register_secret(password)
        username = profile.username or ""
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        cred = CachedCredential(
            profile_name=profile.name,
            header_name="Authorization",
            header_value=f"Basic {encoded}",
        )
        cache.put(cred)
        return cred

    if profile.kind == AuthProfileKind.STATIC_HEADER:
        if profile.secret_ref is None:
            return None
        token = _resolve_env_secret(profile.secret_ref.env)
        scrubber.register_secret(token)
        header_name = profile.name_hint or "X-Api-Key"
        cred = CachedCredential(
            profile_name=profile.name,
            header_name=header_name,
            header_value=token,
        )
        cache.put(cred)
        return cred

    if profile.kind == AuthProfileKind.COOKIE:
        if profile.secret_ref is None:
            return None
        token = _resolve_env_secret(profile.secret_ref.env)
        scrubber.register_secret(token)
        cookie_name = profile.name_hint or "session"
        cred = CachedCredential(
            profile_name=profile.name,
            header_name="Cookie",
            header_value=f"{cookie_name}={token}",
        )
        cache.put(cred)
        return cred

    if profile.kind == AuthProfileKind.LOGIN_FLOW:
        if profile.login is None:
            return None

        # Layer 6 sub-check: login endpoint must be on an allowed host.
        if target_host not in allowed_hosts:
            msg = (
                f"Login flow for profile '{profile.name}' would POST to host "
                f"'{target_host}', which is not in allowed_hosts {allowed_hosts!r}. "
                "Only hosts in the target's allowed_hosts list may receive credentials."
            )
            raise ValueError(msg)

        # Build TOTP provider if configured.
        totp_provider: TotpProvider | None = None
        if profile.totp is not None:
            totp_seed = _resolve_env_secret(profile.totp.seed_ref.env)
            totp_provider = TotpProvider(
                seed_b32=totp_seed,
                digits=profile.totp.digits,
                period_seconds=profile.totp.period_seconds,
                algorithm=profile.totp.algorithm,
            )

        # Expand field template (resolves ${secret:...} and ${totp}).
        rendered_fields = _render_field_template(
            profile.login.field_template,
            totp_provider=totp_provider,
        )

        # Register all resolved secret values before the POST.
        for val in rendered_fields.values():
            scrubber.register_secret(val)

        # POST to the login endpoint.
        base_url = f"http://{target_host}:{target_port}"
        with httpx.Client() as client:
            response = client.post(
                base_url + profile.login.path,
                json=rendered_fields,
            )

        # Extract the token from the response body.
        token = _extract_from_response(response.text, profile.login.extract)
        scrubber.register_secret(token)

        header_name, header_value = _inject_as_header(
            token,
            profile.login.extract.inject_as,
            profile.name_hint,
        )

        cred = CachedCredential(
            profile_name=profile.name,
            header_name=header_name,
            header_value=header_value,
            ttl_seconds=profile.login.ttl_seconds,
        )
        cache.put(cred)
        return cred

    return None
