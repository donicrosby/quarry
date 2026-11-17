"""Unit tests for the per-destination-set egress policy (D1).

Covers the model shapes, the DNS-pinning guard, policy construction, prove-stage
scoping, and each tier's enforcement contract.  HTTP/network-free — resolution
uses injected fake resolvers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.egress import (
    ARTIFACT_STORE,
    BROWSER_TARGET,
    CANARY_LISTENER,
    INTEGRATION_OUTBOUND,
    MODEL_PROVIDER,
    TARGET_HOST,
    EgressPolicyError,
    FrozenResolver,
    build_egress_policy,
    build_prove_sandbox_policy,
    resolve_egress_policy,
)
from quarry.schemas import (
    DestinationSet,
    EgressPolicy,
    EnvProfile,
    ResolvedDestinationSet,
    ResolvedEgressPolicy,
    SandboxExecSpec,
)
from quarry_activities.sandbox import (
    EGRESS_NETWORK_PREFIX,
    K8sJobSandbox,
    LocalSubprocessSandbox,
    build_network_policy,
    egress_network_name,
)

# ---------------------------------------------------------------------------
# Model shapes
# ---------------------------------------------------------------------------


class TestModels:
    def test_destination_set_defaults(self) -> None:
        ds = DestinationSet(name="target-host")
        assert ds.allowed_domains == []
        assert ds.allowed_ips == []

    def test_destination_set_round_trip(self) -> None:
        ds = DestinationSet(
            name="canary-listener",
            allowed_domains=["canary.local"],
            allowed_ips=["10.0.0.9"],
        )
        reloaded = DestinationSet.model_validate_json(ds.model_dump_json())
        assert reloaded == ds

    def test_egress_policy_defaults_deny_all(self) -> None:
        policy = EgressPolicy()
        assert policy.destination_sets == []
        assert policy.deny_all_else is True
        assert policy.is_empty() is True

    def test_egress_policy_non_empty(self) -> None:
        policy = EgressPolicy(
            destination_sets=[DestinationSet(name=TARGET_HOST, allowed_ips=["10.0.0.1"])]
        )
        assert policy.is_empty() is False

    def test_egress_policy_empty_set_of_sets_is_empty(self) -> None:
        """A set with no entries declares no reachable destination."""
        policy = EgressPolicy(destination_sets=[DestinationSet(name=TARGET_HOST)])
        assert policy.is_empty() is True

    def test_resolved_policy_all_allowed_ips_deduped_sorted(self) -> None:
        policy = ResolvedEgressPolicy(
            destination_sets=[
                ResolvedDestinationSet(name="a", allowed_ips=["10.0.0.2", "10.0.0.1"]),
                ResolvedDestinationSet(name="b", allowed_ips=["10.0.0.2"]),
            ]
        )
        assert policy.all_allowed_ips() == ["10.0.0.1", "10.0.0.2"]

    def test_resolved_policy_empty_when_no_ips(self) -> None:
        policy = ResolvedEgressPolicy(
            destination_sets=[ResolvedDestinationSet(name="a", allowed_ips=[])]
        )
        assert policy.is_empty() is True

    def test_resolved_policy_round_trip(self) -> None:
        policy = ResolvedEgressPolicy(
            destination_sets=[ResolvedDestinationSet(name=TARGET_HOST, allowed_ips=["10.0.0.1"])]
        )
        reloaded = ResolvedEgressPolicy.model_validate_json(policy.model_dump_json())
        assert reloaded == policy
        assert reloaded.resolution_frozen is True

    def test_models_are_frozen(self) -> None:
        from pydantic import ValidationError

        ds = DestinationSet(name="x")
        with pytest.raises(ValidationError):
            ds.name = "y"  # type: ignore[misc]

    def test_unfrozen_resolved_policy_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="resolution_frozen"):
            ResolvedEgressPolicy(resolution_frozen=False)


# ---------------------------------------------------------------------------
# DNS-rebinding guard — FrozenResolver / resolve_egress_policy
# ---------------------------------------------------------------------------


class _CountingResolver:
    def __init__(self, mapping: dict[str, list[str]]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def __call__(self, domain: str) -> list[str]:
        self.calls.append(domain)
        return self.mapping.get(domain, [])


class TestFrozenResolver:
    def test_resolves_once(self) -> None:
        resolver = _CountingResolver({"target.com": ["10.0.0.1"]})
        frozen = FrozenResolver(resolver=resolver)
        assert frozen.resolve("target.com") == ["10.0.0.1"]
        assert frozen.pinned == {"target.com": ["10.0.0.1"]}

    def test_second_resolve_of_same_domain_raises(self) -> None:
        resolver = _CountingResolver({"target.com": ["10.0.0.1"]})
        frozen = FrozenResolver(resolver=resolver)
        frozen.resolve("target.com")
        with pytest.raises(EgressPolicyError, match="re-resolution"):
            frozen.resolve("target.com")
        # The domain was resolved exactly once — the second call never hit the resolver.
        assert resolver.calls == ["target.com"]

    def test_freeze_rejects_every_later_resolve(self) -> None:
        frozen = FrozenResolver(resolver=_CountingResolver({"a": ["10.0.0.1"]}))
        frozen.freeze()
        with pytest.raises(EgressPolicyError, match="frozen"):
            frozen.resolve("a")

    def test_empty_resolution_raises(self) -> None:
        frozen = FrozenResolver(resolver=_CountingResolver({}))
        with pytest.raises(EgressPolicyError, match="no IPs|no IPv4"):
            frozen.resolve("missing.example")


class TestResolveEgressPolicy:
    def test_resolves_each_domain_exactly_once(self) -> None:
        resolver = _CountingResolver({"target.com": ["10.0.0.1"], "canary.local": ["10.0.0.2"]})
        policy = EgressPolicy(
            destination_sets=[
                DestinationSet(name=TARGET_HOST, allowed_domains=["target.com"]),
                DestinationSet(name=CANARY_LISTENER, allowed_domains=["canary.local"]),
            ]
        )
        resolved = resolve_egress_policy(policy, resolver=resolver)
        assert resolver.calls == ["target.com", "canary.local"]
        assert resolved.all_allowed_ips() == ["10.0.0.1", "10.0.0.2"]
        assert resolved.resolution_frozen is True

    def test_declared_ips_pass_through_and_domains_are_pinned(self) -> None:
        resolver = _CountingResolver({"target.com": ["10.0.0.1"]})
        policy = EgressPolicy(
            destination_sets=[
                DestinationSet(
                    name=TARGET_HOST, allowed_domains=["target.com"], allowed_ips=["10.0.0.9"]
                )
            ]
        )
        resolved = resolve_egress_policy(policy, resolver=resolver)
        assert resolved.destination_sets[0].allowed_ips == ["10.0.0.9", "10.0.0.1"]

    def test_same_domain_in_two_sets_is_rejected(self) -> None:
        """A repeated domain would be a second resolution — rejected."""
        resolver = _CountingResolver({"target.com": ["10.0.0.1"]})
        policy = EgressPolicy(
            destination_sets=[
                DestinationSet(name="a", allowed_domains=["target.com"]),
                DestinationSet(name="b", allowed_domains=["target.com"]),
            ]
        )
        with pytest.raises(EgressPolicyError, match="re-resolution"):
            resolve_egress_policy(policy, resolver=resolver)


# ---------------------------------------------------------------------------
# Policy construction (build_egress_policy)
# ---------------------------------------------------------------------------


class TestBuildEgressPolicy:
    def test_allowed_hosts_become_target_host(self) -> None:
        policy = build_egress_policy(allowed_hosts=["app.test", "127.0.0.1"])
        assert len(policy.destination_sets) == 1
        ds = policy.destination_sets[0]
        assert ds.name == TARGET_HOST
        assert ds.allowed_domains == ["app.test"]
        assert ds.allowed_ips == ["127.0.0.1"]

    def test_empty_inputs_produce_empty_policy(self) -> None:
        policy = build_egress_policy()
        assert policy.is_empty() is True
        assert policy.deny_all_else is True

    def test_all_sets_seeded(self) -> None:
        policy = build_egress_policy(
            allowed_hosts=["target.test"],
            canary_destinations=["canary.local"],
            browser_targets=["browser.test"],
            model_provider_hosts=["models.test"],
            artifact_store_hosts=["artifacts.test"],
            integration_hosts=["hooks.test"],
        )
        names = {ds.name for ds in policy.destination_sets}
        assert names == {
            TARGET_HOST,
            CANARY_LISTENER,
            BROWSER_TARGET,
            MODEL_PROVIDER,
            ARTIFACT_STORE,
            INTEGRATION_OUTBOUND,
        }

    def test_entries_deduplicated(self) -> None:
        policy = build_egress_policy(allowed_hosts=["a.test", "a.test", "10.0.0.1", "10.0.0.1"])
        ds = policy.destination_sets[0]
        assert ds.allowed_domains == ["a.test"]
        assert ds.allowed_ips == ["10.0.0.1"]


# ---------------------------------------------------------------------------
# Prove-stage scoping (build_prove_sandbox_policy)
# ---------------------------------------------------------------------------


class TestBuildProveSandboxPolicy:
    def _scan_policy(self) -> EgressPolicy:
        return build_egress_policy(
            allowed_hosts=["target.test"],
            canary_destinations=["canary.local"],
            browser_targets=["browser.test"],
            model_provider_hosts=["models.test"],
            artifact_store_hosts=["artifacts.test"],
            integration_hosts=["hooks.test"],
        )

    def test_live_target_only(self) -> None:
        scoped = build_prove_sandbox_policy(self._scan_policy(), needs_live_target=True)
        assert [ds.name for ds in scoped.destination_sets] == [TARGET_HOST]

    def test_browser_and_canary_sets(self) -> None:
        scoped = build_prove_sandbox_policy(
            self._scan_policy(),
            needs_live_target=False,
            needs_browser=True,
            needs_canary=True,
        )
        assert {ds.name for ds in scoped.destination_sets} == {BROWSER_TARGET, CANARY_LISTENER}

    def test_host_side_sets_never_included(self) -> None:
        """Host-side sets are excluded even if the scenario flags request everything."""
        scoped = build_prove_sandbox_policy(
            self._scan_policy(),
            needs_live_target=True,
            needs_browser=True,
            needs_canary=True,
        )
        names = {ds.name for ds in scoped.destination_sets}
        assert names.isdisjoint({MODEL_PROVIDER, INTEGRATION_OUTBOUND, ARTIFACT_STORE})

    def test_no_needs_yields_empty_policy(self) -> None:
        scoped = build_prove_sandbox_policy(self._scan_policy(), needs_live_target=False)
        assert scoped.is_empty() is True

    def test_missing_set_in_scan_policy_is_omitted(self) -> None:
        scan = build_egress_policy(allowed_hosts=["target.test"])
        scoped = build_prove_sandbox_policy(scan, needs_live_target=False, needs_canary=True)
        assert scoped.is_empty() is True


# ---------------------------------------------------------------------------
# Tier enforcement contracts
# ---------------------------------------------------------------------------


def _resolved(*ips: str, name: str = TARGET_HOST) -> ResolvedEgressPolicy:
    return ResolvedEgressPolicy(
        destination_sets=[ResolvedDestinationSet(name=name, allowed_ips=list(ips))]
    )


class TestTier1Refusal:
    def test_non_empty_policy_is_rejected(self, tmp_path: Path) -> None:
        """Tier 1 has no kernel network NS — a non-empty policy must be refused."""
        sandbox = LocalSubprocessSandbox()
        spec = SandboxExecSpec(command="echo", args=["hi"])
        with pytest.raises(EgressPolicyError):
            sandbox.run(
                spec, work_dir=tmp_path, resolved_env={}, egress_policy=_resolved("10.0.0.1")
            )

    def test_none_policy_runs(self, tmp_path: Path) -> None:
        sandbox = LocalSubprocessSandbox()
        spec = SandboxExecSpec(command="echo", args=["hi"], env_profile=EnvProfile.NONE)
        result = sandbox.run(spec, work_dir=tmp_path, resolved_env={}, egress_policy=None)
        assert result.exit_code == 0

    def test_empty_policy_runs(self, tmp_path: Path) -> None:
        sandbox = LocalSubprocessSandbox()
        spec = SandboxExecSpec(command="echo", args=["hi"], env_profile=EnvProfile.NONE)
        empty = ResolvedEgressPolicy(
            destination_sets=[ResolvedDestinationSet(name=TARGET_HOST, allowed_ips=[])]
        )
        result = sandbox.run(spec, work_dir=tmp_path, resolved_env={}, egress_policy=empty)
        assert result.exit_code == 0


class TestTier2NetworkName:
    def test_deterministic_per_ip_set(self) -> None:
        assert egress_network_name(_resolved("10.0.0.1", "10.0.0.2")) == egress_network_name(
            _resolved("10.0.0.2", "10.0.0.1")
        )

    def test_prefix_and_empty_handling(self) -> None:
        name = egress_network_name(_resolved("10.0.0.1"))
        assert name is not None and name.startswith(EGRESS_NETWORK_PREFIX)
        assert egress_network_name(None) is None
        empty = ResolvedEgressPolicy(
            destination_sets=[ResolvedDestinationSet(name=TARGET_HOST, allowed_ips=[])]
        )
        assert egress_network_name(empty) is None

    def test_distinct_ip_sets_get_distinct_networks(self) -> None:
        assert egress_network_name(_resolved("10.0.0.1")) != egress_network_name(
            _resolved("10.0.0.2")
        )


class TestTier3NetworkPolicy:
    def test_shape_against_resolved_ips(self) -> None:
        policy = ResolvedEgressPolicy(
            destination_sets=[
                ResolvedDestinationSet(name=TARGET_HOST, allowed_ips=["10.0.0.1"]),
                ResolvedDestinationSet(name=CANARY_LISTENER, allowed_ips=["10.0.0.2"]),
            ]
        )
        manifest = build_network_policy(policy, name="quarry-test")
        assert manifest["apiVersion"] == "networking.k8s.io/v1"
        assert manifest["kind"] == "NetworkPolicy"
        assert manifest["metadata"] == {"name": "quarry-test"}
        spec = manifest["spec"]
        assert spec["policyTypes"] == ["Egress"]
        assert len(spec["egress"]) == 2
        blocks = [rule["to"][0]["ipBlock"]["cidr"] for rule in spec["egress"]]
        assert blocks == ["10.0.0.1/32", "10.0.0.2/32"]

    def test_empty_policy_denies_all(self) -> None:
        manifest = build_network_policy(ResolvedEgressPolicy())
        assert manifest["spec"]["egress"] == []

    def test_k8s_job_sandbox_helper_delegates(self) -> None:
        sandbox = K8sJobSandbox()
        manifest = sandbox.build_network_policy(_resolved("10.0.0.1"), name="x")
        assert manifest["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"] == "10.0.0.1/32"
