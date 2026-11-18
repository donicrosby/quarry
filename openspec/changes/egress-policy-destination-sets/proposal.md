# Change: egress-policy-destination-sets

## Why

The current sandbox egress model is binary per-sandbox: a single `TargetEndpoint` (host:port, VERIFIED at b284af7:src/quarry/schemas.py:1394-1398) or no network at all. Browser crawling, SSRF canary detection, and multi-destination proof scenarios need the sandbox to reach more than one destination — the target host AND a canary listener, or the target AND an artifact store — while still blocking all other egress. The single-endpoint model cannot express these multi-destination policies, and without per-destination-set egress control the sandbox containment primitive is trivially bypassed by a compromised process that reaches any destination in the allow-set.

## What Changes

- **Destination-set model**: Replace the single `TargetEndpoint` with named destination sets (`target-host`, `canary-listener`, `artifact-store`, `model-provider`, `integration-outbound`, `browser-target`), each carrying its own `allowed_domains` and `allowed_ips`. Deny-all-else is the default.
- **DNS rebinding protection**: Resolve destination domains once at policy construction; pin to the initially-resolved IPs. Re-resolution during sandbox execution is rejected.
- **Per-tier enforcement**: Every sandbox tier enforces destination-set policies. Tier 2 (ContainerSandbox) restricts to resolved IPs; Tier 3 (K8sJobSandbox) enforces via NetworkPolicy.
- **Policy construction**: The policy is built at scan start from the `TargetAuthorization` allowed hosts, configured model-provider endpoints, artifact-store URIs, and any canary/integration destinations.

## Impact

- **Specs**: `sandbox-backends` (MODIFIED "Egress pinning for live proof" + ADDED destination-set, DNS-rebinding, and tier-enforcement requirements), `proof-and-sandbox-execution` (ADDED "Destination-set-aware proof configuration"; no existing requirement modified).
- **Code**: `src/quarry/schemas.py` (new `DestinationSet`, `EgressPolicy` models replacing/coexisting with `TargetEndpoint`), `src/quarry_activities/sandbox.py` (protocol parameter change + Tier 2 enforcement), deployment manifests (K8s NetworkPolicy for Tier 3).
- **Threat model (SECURITY-CRITICAL)**: The per-destination-set egress policy is the sandbox containment primitive. A compromised sandbox that escapes its process boundary can reach ONLY destinations explicitly allowed in the policy's destination sets. The DNS rebinding guard closes the resolution-race vector: an attacker cannot cause a re-resolution mid-execution to redirect traffic. Defense in depth: the destination-set policy is enforced at the sandbox tier (kernel/network namespace), not in application code — a sandbox escape that compromises the Python runtime still cannot reach unallowed destinations. The threat model assumes the sandbox tier's network enforcement is the last line; any destination-set policy gap (missing a set for a new capability, DNS rebinding guard disabled) expands the blast radius of a sandbox escape.
- **Cost**: Adds one DNS resolution pass at scan start (bounded latency). No per-invocation overhead beyond the tier's existing enforcement.
- **Non-goals**: Per-request path-level filtering (the `do_not_test` ceiling already handles path exclusions at the authorization layer); egress logging/tracing (separate observability change); dynamic destination addition mid-scan (policy is fixed at scan start).
- **Blocks**: W1 (browser-automation proof), W10 (SSRF canary detection), W11 (XXE proof).

## Reconcile notes (2026-09-10 original vs b284af7 main)

- **Kept**: Destination-set model, per-set allowlists, DNS rebinding protection, tier integration. Core need unchanged.
- **Dropped**: "Local egress-filter proxy sidecar pattern" as a fixed implementation requirement. The spec defines WHAT (destination sets, per-set policies); the implementation is free to enforce via proxy, iptables, Docker network attachment, or NetworkPolicy as appropriate per tier.
- **Rescoped**: The spec extends the existing `SandboxBackend` protocol rather than introducing a separate sidecar component. This aligns with ADR-024's "every sandbox tier is a backend drop-in" invariant.