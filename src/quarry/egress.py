"""Egress-policy construction, DNS pinning, and per-tier composition.

The sandbox containment primitive is a *destination-set* policy: a set of named
allow-lists (``target-host``, ``canary-listener``, …) with deny-all-else.  This
module owns the pure policy-construction helpers plus the one side-effecting
step — DNS resolution — which resolves every destination domain exactly once
and pins the resulting IPs (DNS-rebinding guard).

Layering: the models live in :mod:`quarry.schemas`; this module is pure-policy
logic plus :func:`system_resolver` (the only I/O).  It is safe to import from
workflow code as long as the resolver is not invoked there — workflows are
I/O-free by ADR-014, so resolution happens in the sandbox activity.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence

from quarry.schemas import (
    DestinationSet,
    EgressPolicy,
    ResolvedDestinationSet,
    ResolvedEgressPolicy,
)

# ---------------------------------------------------------------------------
# Destination-set vocabulary
# ---------------------------------------------------------------------------

#: The authorized scan target (built from ``TargetAuthorization.allowed_hosts``).
TARGET_HOST = "target-host"
#: An SSRF/XXE canary listener the proof scenario reaches.
CANARY_LISTENER = "canary-listener"
#: A browser-automation proof target.
BROWSER_TARGET = "browser-target"
#: The configured model-provider endpoint.
MODEL_PROVIDER = "model-provider"
#: Outbound integration sinks (Jira/Slack/etc).
INTEGRATION_OUTBOUND = "integration-outbound"
#: The artifact store (Redis/S3).
ARTIFACT_STORE = "artifact-store"

# Sets whose traffic originates on the WORKER HOST, not inside a sandbox: model
# calls and integration sinks run in activities, and artifact I/O is the store
# protocol.  Allowing any of these inside a sandbox policy would hand a
# compromised sandbox an allow-listed exfiltration channel, so they are excluded
# from every sandbox-scoped policy.
HOST_SIDE_SET_NAMES: frozenset[str] = frozenset(
    {MODEL_PROVIDER, INTEGRATION_OUTBOUND, ARTIFACT_STORE}
)


class EgressPolicyError(Exception):
    """Raised on an egress-policy violation.

    Covers the DNS-rebinding guard (a re-resolution attempt) and a tier that
    cannot enforce a non-empty policy (Tier 1 ``LocalSubprocessSandbox``).
    """


#: A resolver maps a domain to the IPs it currently resolves to.
Resolver = Callable[[str], Sequence[str]]


def system_resolver(domain: str) -> list[str]:
    """Resolve *domain* to its IPv4 addresses via the system resolver.

    IPv4 only: the sandbox enforcement tiers address destinations by IPv4
    (Docker bridge networks, K8s ``ipBlock``), so pinning IPv6 addresses here
    would produce an allow-list the tiers cannot enforce.
    """
    import socket

    infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        if family != socket.AF_INET:
            continue
        ip = str(sockaddr[0])
        if ip not in ips:
            ips.append(ip)
    if not ips:
        msg = f"no IPv4 address resolved for destination domain '{domain}'"
        raise EgressPolicyError(msg)
    return ips


class FrozenResolver:
    """Resolve each domain at most once, then reject any re-resolution.

    Policy construction resolves every destination domain exactly once and
    pins the resulting IPs.  A second ``resolve`` of the same domain — an
    attacker-triggered re-resolution mid-execution, or the same domain declared
    in two sets — raises :class:`EgressPolicyError`, so traffic cannot be
    redirected to a fresh IP after the pin (DNS-rebinding defence).
    """

    def __init__(self, *, resolver: Resolver | None = None) -> None:
        self._resolver: Resolver = resolver or system_resolver
        self._pinned: dict[str, list[str]] = {}
        self._frozen = False

    def resolve(self, domain: str) -> list[str]:
        """Resolve *domain* once; raise on any subsequent resolution."""
        if self._frozen:
            msg = f"re-resolution of '{domain}' rejected: policy is frozen"
            raise EgressPolicyError(msg)
        if domain in self._pinned:
            msg = f"re-resolution of '{domain}' rejected: domain already pinned"
            raise EgressPolicyError(msg)
        ips = list(self._resolver(domain))
        if not ips:
            msg = f"resolver returned no IPs for '{domain}'"
            raise EgressPolicyError(msg)
        self._pinned[domain] = ips
        return ips

    def freeze(self) -> None:
        """Seal the resolver: every later ``resolve`` raises."""
        self._frozen = True

    @property
    def pinned(self) -> dict[str, list[str]]:
        """A copy of the domain → pinned-IPs map built so far."""
        return {domain: list(ips) for domain, ips in self._pinned.items()}


def resolve_egress_policy(
    policy: EgressPolicy,
    *,
    resolver: Resolver | None = None,
) -> ResolvedEgressPolicy:
    """Resolve every domain in *policy* once and freeze the resulting IPs.

    Domains declared as IPs are passed through; domains are resolved through a
    :class:`FrozenResolver` so each is looked up at most once.  The returned
    policy is the frozen, tier-enforceable form.  Raises
    :class:`EgressPolicyError` on a re-resolution or an empty resolution.
    """
    frozen = FrozenResolver(resolver=resolver)
    resolved_sets: list[ResolvedDestinationSet] = []
    for ds in policy.destination_sets:
        ips = list(ds.allowed_ips)
        for domain in ds.allowed_domains:
            for ip in frozen.resolve(domain):
                if ip not in ips:
                    ips.append(ip)
        resolved_sets.append(ResolvedDestinationSet(name=ds.name, allowed_ips=ips))
    frozen.freeze()
    return ResolvedEgressPolicy(
        destination_sets=resolved_sets,
        deny_all_else=policy.deny_all_else,
        resolution_frozen=True,
    )


def _split_hosts(entries: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split *entries* into (domains, IPs), preserving order and de-duplicating."""
    domains: list[str] = []
    ips: list[str] = []
    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            if entry not in domains:
                domains.append(entry)
        else:
            if entry not in ips:
                ips.append(entry)
    return domains, ips


def build_egress_policy(
    *,
    allowed_hosts: Sequence[str] = (),
    canary_destinations: Sequence[str] = (),
    browser_targets: Sequence[str] = (),
    model_provider_hosts: Sequence[str] = (),
    artifact_store_hosts: Sequence[str] = (),
    integration_hosts: Sequence[str] = (),
) -> EgressPolicy:
    """Construct the scan's destination-set policy at scan start.

    ``allowed_hosts`` (the ``TargetAuthorization`` hosts) becomes the
    ``target-host`` set; the remaining keyword arguments seed the other sets.
    Sets with no entries are omitted.  Deny-all-else is the default.  Pure — no
    DNS resolution happens here.
    """
    sources: tuple[tuple[str, Sequence[str]], ...] = (
        (TARGET_HOST, allowed_hosts),
        (CANARY_LISTENER, canary_destinations),
        (BROWSER_TARGET, browser_targets),
        (MODEL_PROVIDER, model_provider_hosts),
        (ARTIFACT_STORE, artifact_store_hosts),
        (INTEGRATION_OUTBOUND, integration_hosts),
    )
    destination_sets: list[DestinationSet] = []
    for name, entries in sources:
        domains, ips = _split_hosts(entries)
        if domains or ips:
            destination_sets.append(
                DestinationSet(name=name, allowed_domains=domains, allowed_ips=ips)
            )
    return EgressPolicy(destination_sets=destination_sets)


def build_prove_sandbox_policy(
    scan_policy: EgressPolicy,
    *,
    needs_live_target: bool,
    needs_browser: bool = False,
    needs_canary: bool = False,
) -> EgressPolicy:
    """Scope *scan_policy* to the destination sets one proof scenario needs.

    The prove stage runs a sandbox, not the worker host, so only the
    scenario-facing sets are carried over: ``target-host`` when the proof needs
    live target access, plus ``browser-target`` (browser proof) and
    ``canary-listener`` (SSRF canary).  The host-side sets (``model-provider``,
    ``integration-outbound``, ``artifact-store``) are never included — they
    would be an allow-listed exfiltration channel inside the sandbox.  A proof
    that needs none of the requested sets receives an empty policy (no egress).
    """
    wanted: set[str] = set()
    if needs_live_target:
        wanted.add(TARGET_HOST)
    if needs_browser:
        wanted.add(BROWSER_TARGET)
    if needs_canary:
        wanted.add(CANARY_LISTENER)

    scoped = [
        ds
        for ds in scan_policy.destination_sets
        if ds.name in wanted and ds.name not in HOST_SIDE_SET_NAMES
    ]
    return EgressPolicy(destination_sets=scoped, deny_all_else=True)
