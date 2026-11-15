# Tasks: egress-policy-destination-sets

## 1. Schema and policy model
- [ ] 1.1 Define `DestinationSet` model in `src/quarry/schemas.py`: name, allowed_domains, allowed_ips (frozen Pydantic BaseModel, per project conventions)
- [ ] 1.2 Define `EgressPolicy` model: ordered list of `DestinationSet` entries, `deny_all_else: bool = True` (default deny-all)
- [ ] 1.3 Define `ResolvedEgressPolicy` model: policy with all domains resolved to IPs, `resolution_frozen: bool = True`
- [ ] 1.4 DNS resolution helper: resolve domains once, pin IPs, raise on re-resolution attempt (RED: test re-resolution rejection)

## 2. Policy construction at scan start
- [ ] 2.1 `build_egress_policy()` factory: construct `EgressPolicy` from `TargetAuthorization.allowed_hosts` (→ `target-host` set), configured model-provider endpoints, artifact-store URIs, and any canary/integration destinations
- [ ] 2.2 `resolve_egress_policy()`: resolve all domains to IPs, freeze, return `ResolvedEgressPolicy` (RED: test that DNS resolution happens exactly once)

## 3. SandboxBackend protocol update
- [ ] 3.1 Replace `target_endpoint: TargetEndpoint | None` parameter with `egress_policy: ResolvedEgressPolicy | None` on `SandboxBackend.run()` (protocol + all three tier classes)
- [ ] 3.2 Update `LocalSubprocessSandbox`: accept `ResolvedEgressPolicy | None`; Tier 1 cannot enforce kernel network NS so it logs a warning and passes through (best-effort, documented caveat)
- [ ] 3.3 Update `ContainerSandbox._build_docker_cmd()`: replace `--network none` with per-destination-set Docker network attachment (create restricted network, attach container, allow only resolved IPs)
- [ ] 3.4 Update `K8sJobSandbox`: construct `NetworkPolicy` egress rules from `ResolvedEgressPolicy` destination sets (RED: test NetworkPolicy shape against resolved IPs)

## 4. Prove stage integration
- [ ] 4.1 `build_prove_sandbox_policy()`: scope the scan's egress policy to the destinations the proof scenario needs (browser → `browser-target`, canary → `canary-listener`, none → empty policy)
- [ ] 4.2 Wire scoped policy into prove stage sandbox invocation; verify empty-policy case produces no egress

## 5. Caller migration
- [ ] 5.1 Update all `SandboxBackend.run()` call sites to pass `ResolvedEgressPolicy` instead of `TargetEndpoint`
- [ ] 5.2 Update `TargetEndpoint` references in activity inputs, workflow code, and CLI to use `EgressPolicy` / `ResolvedEgressPolicy`

## 6. DNS rebinding guard
- [ ] 6.1 `FrozenResolver` helper: wraps resolved IPs, rejects any re-resolution call with a typed error (RED: test that a second resolve raises)
- [ ] 6.2 Integration test: ContainerSandbox with a policy that includes `example.com` → verify container reaches the resolved IP, not a different IP for the same hostname

## 7. Verification
- [ ] 7.1 Unit tests: `DestinationSet`, `EgressPolicy`, `ResolvedEgressPolicy` model validation
- [ ] 7.2 Unit tests: `build_egress_policy()` factory output shape
- [ ] 7.3 Unit tests: `FrozenResolver` re-resolution rejection
- [ ] 7.4 Integration test: ContainerSandbox with multi-destination policy (target + canary) → target reachable, canary reachable, other hosts blocked
- [ ] 7.5 Integration test: empty policy → no egress (regression guard)
- [ ] 7.6 Ruff + pyright + vulture clean; full test suite green

## 8. Landing
- [ ] 8.1 Conventional commit, push, CI green
- [ ] 8.2 `openspec archive egress-policy-destination-sets --yes`