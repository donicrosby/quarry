"""Quarry domain schemas."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    PREPARING = "preparing"
    MAPPING = "mapping"
    SCANNING = "scanning"
    VALIDATING = "validating"
    PROVING = "proving"
    REPORTING = "reporting"
    INTEGRATING = "integrating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATING = "validating"
    REJECTED = "rejected"
    VALIDATED = "validated"
    # Retained pending proof: validator returned needs_proof or inconclusive.
    # This is the carry-forward status the future prove stage consumes —
    # filter by status == NEEDS_PROOF to find the candidates prove should run on.
    NEEDS_PROOF = "needs_proof"
    PROVING = "proving"
    PROVED = "proved"
    FINAL = "final"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CredibilityLevel(StrEnum):
    """Ordinal ensemble credibility posterior for a finding (MDASH, design D3).

    Ordinal-first by design — a small, explicit, auditable set rather than a
    numeric score, so the rule stays legible and a finding is never silently
    dropped on credibility alone.

    - ``refuted``: a debater tier argued the candidate away from the code.
    - ``contested``: independent models disagree about the candidate.
    - ``unrefuted``: a debater tried and *failed* to refute it → credibility up.

    Ordered least-to-most credible: refuted < contested < unrefuted.
    """

    REFUTED = "refuted"
    CONTESTED = "contested"
    UNREFUTED = "unrefuted"


class Provider(StrEnum):
    """Model provider identifiers.  Add new vendors as new members."""

    MOCK = "mock"
    LITELLM = "litellm"
    # Bedrock routes through LiteLLM (``bedrock/<model>``) but is a distinct vendor
    # so a panel can span genuinely different vendors and cross-vendor disagreement
    # reflects real independence (MDASH ensemble, design D4). AWS credentials are
    # only needed at call time, not at client construction.
    BEDROCK = "bedrock"


class VulnerabilityClass(StrEnum):
    SECRETS = "secrets"
    IDOR = "idor"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    FILE_UPLOAD = "file_upload"
    # OWASP-aligned + common taint-friendly vulnerability classes.
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    SSTI = "ssti"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    XXE = "xxe"
    LDAP_INJECTION = "ldap_injection"
    MASS_ASSIGNMENT = "mass_assignment"
    AUTH = "auth"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    INSECURE_DESIGN = "insecure_design"
    WEAK_CRYPTO = "weak_crypto"


class TriageLabel(StrEnum):
    TP = "tp"
    FP = "fp"
    DUP = "dup"
    OOS = "oos"


class DeploymentIntent(StrEnum):
    """Deployment-intent judgement for a finding's cited code.

    Fail-safe default is ``PRODUCTION``: intent is non-production only when
    every production-signal check is affirmatively false.
    """

    PRODUCTION = "production"
    SAMPLE = "sample"
    TEST = "test"
    EXAMPLE = "example"


class ReVerificationOutcome(StrEnum):
    """Outcome of a re-verification pass over a finding's cited location.

    Fail-safe default is ``RETAIN``: when re-verification cannot run (missing
    file, out-of-range line) the finding is retained under the conservative
    verdict rather than discarded.
    """

    RAN = "ran"
    RETAIN = "retain"
    DISCARD = "discard"


class VerdictDefaults:
    """Fail-safe verdict defaults (candidate-precision-and-calibration).

    Verdict-producing stages bias toward never silently dropping a finding.
    """

    @staticmethod
    def deployment_intent(
        *,
        serves_traffic: bool | None = None,
        sample_data: bool | None = None,
    ) -> DeploymentIntent:
        """Default ``PRODUCTION`` unless every production signal is false.

        ``None`` (unknown) is not evidence of non-production. A non-production
        intent requires ``serves_traffic`` affirmatively false; ``sample_data``
        true then marks deliberately non-production sample code.
        """
        if serves_traffic is True:
            return DeploymentIntent.PRODUCTION
        if serves_traffic is None or sample_data is None:
            # Any unknown signal: bias to production.
            return DeploymentIntent.PRODUCTION
        # serves_traffic affirmatively False — every production signal failed.
        return DeploymentIntent.SAMPLE if sample_data else DeploymentIntent.EXAMPLE

    @staticmethod
    def reverification_outcome(
        *,
        file_exists: bool,
        line_in_range: bool | None,
    ) -> ReVerificationOutcome:
        """Default ``RETAIN`` when re-verification cannot run.

        A missing cited file or out-of-range cited line must not silently drop
        the finding — the conservative default retains it.
        """
        if not file_exists or line_in_range is not True:
            return ReVerificationOutcome.RETAIN
        return ReVerificationOutcome.RAN


class ArtifactKind(StrEnum):
    REPO_MANIFEST = "repo_manifest"
    CODE_SNIPPET = "code_snippet"
    TOOL_STDOUT = "tool_stdout"
    TOOL_STDERR = "tool_stderr"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    MODEL_PROMPT = "model_prompt"
    MODEL_RESPONSE = "model_response"
    REPORT = "report"
    INTEGRATION_PAYLOAD = "integration_payload"
    COVERAGE_LEDGER = "coverage_ledger"
    # candidate-precision-and-calibration: durable Knowledge Base recon artifact set
    # (component entities, vuln-class notes, dependency graph, root index).
    KNOWLEDGE_BASE = "knowledge_base"
    # ADR-020: scrubbed ActionReasoning artifact for provenance audit trail.
    REASONING = "reasoning"


class RedactionStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    REDACTED = "redacted"
    CONTAINS_SENSITIVE = "contains_sensitive"
    UNKNOWN = "unknown"


class IntegrationStatus(StrEnum):
    PENDING = "pending"
    DRY_RUN = "dry_run"
    DELIVERED = "delivered"
    FAILED = "failed"
    SKIPPED = "skipped"


def _empty_source_refs() -> list[SourceRef]:
    return []


def _empty_artifact_refs() -> list[ArtifactRef]:
    return []


def _empty_strings() -> list[str]:
    return []


def _empty_panel_entries() -> list[ModelPanelEntry]:
    return []


def _empty_vuln_classes() -> list[VulnerabilityClass]:
    return []


def _empty_coverage_gaps() -> list[CoverageGap]:
    return []


def _empty_production_file_accounting() -> list[ProductionFileAccounting]:
    return []


class ChecklistConstraint(StrEnum):
    """The fixed negative-constraint checklist catalogue (cpc slice 5).

    One outcome is recorded per constraint; the order here is the canonical
    catalogue order a recorded checklist follows.
    """

    HYPOTHETICAL_MISUSE = "hypothetical_misuse"
    DEFENSE_IN_DEPTH_ONLY = "defense_in_depth_only"
    PEDANTIC_LINTING = "pedantic_linting"
    MITIGATION_STRETCHING = "mitigation_stretching"
    SOURCE_COHERENCE = "source_coherence"
    TRUST_BOUNDARY = "trust_boundary"


class ChecklistOutcome(StrEnum):
    """The outcome recorded for a single checklist constraint."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


class ChecklistItem(BaseModel):
    """One recorded outcome for a negative-constraint checklist entry."""

    constraint: ChecklistConstraint
    outcome: ChecklistOutcome
    evidence: str = ""


def _empty_checklist() -> list[ChecklistItem]:
    return []


def _empty_entry_points() -> list[EntryPoint]:
    return []


class SourceRef(BaseModel):
    artifact_ref: str | None = None
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    snippet_hash: str | None = None


class EvidencePathElement(BaseModel):
    """One step in a finding's ordered, sink-first evidence path.

    Elements are repo-relative ``path:line`` locators. On a finding,
    ``evidence_path[0]`` is always the sink (the flaw's primary location),
    followed by the steps back toward the source — the ordering is part of
    the contract downstream dedup/correlation rely on.
    """

    path: str
    line: int

    @field_validator("path")
    @classmethod
    def _require_repo_relative(cls, v: str) -> str:
        if v.startswith("/") or v.startswith(".."):
            msg = f"evidence-path element must be repo-relative, got: {v!r}"
            raise ValueError(msg)
        return v

    @property
    def locator(self) -> str:
        return f"{self.path}:{self.line}"


def _empty_evidence_path() -> list[EvidencePathElement]:
    return []


# ---------------------------------------------------------------------------
# Knowledge Base recon records (candidate-precision-and-calibration, D3)
# ---------------------------------------------------------------------------


class KBComponentEntity(BaseModel):
    """One security-relevant component record in the Knowledge Base.

    Frozen: KB records are write-once artifacts. Every assertion in
    ``security_relevance`` / ``constraints`` must be backed by a cited
    ``path:line`` in ``source_locations`` — the harness's grounding pass
    omits or corrects any record whose citations don't resolve to real
    locations in the audited repository (spec: "Entity records cite source").
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    path: str
    line: int
    security_relevance: str = ""
    constraints: list[str] = Field(default_factory=_empty_strings)
    source_locations: list[str] = Field(default_factory=_empty_strings)


class KBVulnClassNote(BaseModel):
    """A note on one vulnerability class's relevance to the audited codebase.

    Same grounding rule as ``KBComponentEntity``: every claim is cited via
    ``source_locations``.
    """

    model_config = ConfigDict(frozen=True)

    vuln_class: VulnerabilityClass
    relevance: str = ""
    relevant_paths: list[str] = Field(default_factory=_empty_strings)
    source_locations: list[str] = Field(default_factory=_empty_strings)


class KBDependencyGraph(BaseModel):
    """Import/dependency graph keyed by repo-relative source paths.

    Derived code-side from the audited source (never model-reported). When no
    import structure parses, ``edges`` is empty — the artifact is present and
    empty, not omitted (spec: "Empty dependency graph is explicit").
    """

    model_config = ConfigDict(frozen=True)

    edges: dict[str, list[str]] = Field(default_factory=dict)


class KBRootIndex(BaseModel):
    """Root index cataloguing every record in the Knowledge Base artifact set."""

    model_config = ConfigDict(frozen=True)

    scan_id: str
    entity_keys: list[str] = Field(default_factory=_empty_strings)
    vuln_class_note_keys: list[str] = Field(default_factory=_empty_strings)
    dependency_graph_key: str | None = None


class KBContextProvenance(BaseModel):
    """Provenance of the KB records resolved into a stage's prompt context.

    Written by the consuming activity (hunt/gapfill/validate) when it resolves
    KB references: which root-index key was resolved, whether any referenced
    record actually rendered, and the artifact keys supplied to the prompt.
    ``resolved=False`` is the explicit fallback signal — the stage kept its
    inline-context behaviour.
    """

    model_config = ConfigDict(frozen=True)

    kb_root_index_key: str
    resolved: bool = False
    records_supplied: int = 0
    record_keys: list[str] = Field(default_factory=_empty_strings)


class ArtifactRef(BaseModel):
    id: str
    uri: str
    kind: ArtifactKind
    content_type: str
    sha256: str
    size_bytes: int
    redaction_status: RedactionStatus = RedactionStatus.UNKNOWN
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class FileManifestEntry(BaseModel):
    path: str
    size_bytes: int
    sha256: str
    language: str | None = None
    ignored: bool = False
    ignore_reason: str | None = None


class FileManifest(BaseModel):
    entries: list[FileManifestEntry]
    total_size_bytes: int


class RepositorySnapshot(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    repo_path: str
    commit_sha: str | None = None
    file_manifest_ref: ArtifactRef
    file_count: int
    total_size_bytes: int
    detected_frameworks: list[str] = Field(default_factory=_empty_strings)
    entry_points: list[str] = Field(default_factory=_empty_strings)
    repo_type: str | None = None
    ignored_paths: list[str] = Field(default_factory=_empty_strings)
    created_at: datetime


class CodeIndex(BaseModel):
    id: str
    scan_id: str
    snapshot_id: str
    symbols_ref: ArtifactRef | None = None
    routes_ref: ArtifactRef | None = None
    imports_ref: ArtifactRef | None = None
    dependencies_ref: ArtifactRef | None = None
    created_at: datetime


class Workspace(BaseModel):
    id: str
    name: str
    created_at: datetime


class Hunter(BaseModel):
    id: str
    email: str | None = None
    display_name: str
    role: str = "local_admin"


class Target(BaseModel):
    id: str
    workspace_id: str
    repo_path: str
    target_url: str | None = None
    target_kind: Literal["local_repo", "local_web_app", "remote_web_app"] = "local_repo"
    allowed_hosts: list[str] = Field(default_factory=list)
    auth_config_ref: str | None = None
    # Git URL the repo was cloned from (audit trail), when scanning a remote repo.
    origin_url: str | None = None
    # Commit SHA the clone was pinned to (deterministic re-clone on resume).
    origin_commit_sha: str | None = None
    created_at: datetime


class TargetAuthorization(BaseModel):
    id: str
    target_id: str
    workspace_id: str
    authorized_by: str
    allowed_hosts: list[str]
    allowed_repo_paths: list[str]
    expires_at: datetime | None = None
    notes: str | None = None
    do_not_test: list[str] = Field(default_factory=_empty_strings)
    created_at: datetime


def _empty_tier_dicts() -> list[dict[str, Any]]:
    return []


class ModelPanelEntry(BaseModel):
    id: str
    scan_id: str
    role: str
    provider: str
    model: str
    rate_limit_rpm: int = 30
    turn_timeout_seconds: int = 120
    # Serialised ModelTier dicts (MDASH ensemble). Stored as plain dicts to keep
    # schemas.py free of a panel_config import (panel_config already imports this
    # module, so the reverse would be circular). Reconstructed into ModelTier by
    # panel_json_for_role when building the per-role RoleConfig for the worker.
    tiers: list[dict[str, Any]] = Field(default_factory=_empty_tier_dicts)


class ScopeExclusion(BaseModel):
    """Identifies a scope element that must not be tested."""

    model_config = {"frozen": True}

    kind: str  # e.g. "route", "vuln_class", "note"
    value: str
    reason: str
    block_dynamic: bool = False


def _empty_scope_exclusions() -> list[ScopeExclusion]:
    return []


def _empty_integration_configs() -> list[IntegrationConfig]:
    return []


class ScanProfile(BaseModel):
    id: str
    name: str
    vuln_classes: list[VulnerabilityClass]
    max_depth: int = 1
    dynamic_validation_enabled: bool = False
    proof_enabled: bool = False
    model_assist_enabled: bool = False
    integrations_enabled: bool = False
    dry_run_integrations: bool = True
    max_runtime_seconds: int = 1800
    plugins_active: list[str] = Field(default_factory=_empty_strings)
    scope_exclusions: list[ScopeExclusion] = Field(default_factory=_empty_scope_exclusions)
    # Per-integration settings (enable/dry-run/severity/secret), sourced from
    # quarry.toml [integrations.<name>] by default. Forward-ref to
    # IntegrationConfig (defined later in this module); resolved via
    # model_rebuild() right after IntegrationConfig is defined.
    integration_configs: list[IntegrationConfig] = Field(default_factory=_empty_integration_configs)


class Scan(BaseModel):
    id: str
    workspace_id: str
    target_id: str
    requested_by: str
    profile: ScanProfile
    status: ScanStatus
    parent_scan_id: str | None = None
    budget_cap_usd: float | None = None
    panel_snapshot: list[ModelPanelEntry] = Field(default_factory=_empty_panel_entries)
    attack_classes: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    plugins_active: list[str] = Field(default_factory=_empty_strings)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # GC exemption: scans marked legal_hold=True are never purged by the retention sweep.
    # Required for evidence-grade audit trails (e.g. proof artifacts, prompt provenance).
    legal_hold: bool = False


class ScanSummary(BaseModel):
    scan_id: str
    repo_path: str
    status: str
    profile_id: str
    event_count: int
    report_path: str | None = None
    created_at: str
    completed_at: str | None = None
    error: str | None = None


class EnsembleJudgement(BaseModel):
    """One model's contribution to a finding's ensemble credibility (design D3).

    Each judgement is a retained credibility *input* — not a discarded boolean —
    and links to the ``ModelInvocation`` that produced it so the report can trace
    the credibility posterior back to provenance-tracked model calls.
    """

    role: str
    tier: str  # TierKind value: "reasoner" / "debater" / "counterpoint"
    provider: str
    model: str
    verdict: str  # e.g. "validated" / "rejected" / "refuted" / "unrefuted"
    refuted: bool | None = None  # set only for debater judgements
    model_invocation_id: str | None = None


def _empty_ensemble_judgements() -> list[EnsembleJudgement]:
    return []


class CandidateFinding(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    vuln_class: VulnerabilityClass
    title: str
    hypothesis: str
    reasoning: str | None = None
    affected_component: str | None = None
    attack_surface_item_id: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    # Ordered sink-first evidence path (sink at index 0). ``source_refs`` is
    # retained for back-compat during the migration.
    evidence_path: list[EvidencePathElement] = Field(default_factory=_empty_evidence_path)
    confidence: Confidence = Confidence.LOW
    severity: Severity = Severity.MEDIUM
    severity_adjusted: Severity | None = None
    # Calibration fields (candidate-precision-and-calibration). ``raw_severity``
    # is the hunter's severity and is never overwritten by calibration;
    # ``calibrated_severity``/``calibrated_priority`` are None until the
    # calibrate stage runs, and ``firing_rule_ids`` records which rules fired.
    raw_severity: Severity | None = None
    calibrated_severity: Severity | None = None
    calibrated_priority: int | None = None
    firing_rule_ids: list[str] = Field(default_factory=_empty_strings)
    status: FindingStatus = FindingStatus.CANDIDATE
    root_cause_key: str | None = None
    cross_vendor_disagreement: bool = False
    # Ensemble credibility posterior (MDASH, design D3). ``None`` when the finding
    # was not reviewed by a debater/counterpoint ensemble. ``ensemble`` retains
    # each contributing judgement (provenance-linked) so the report is auditable.
    credibility: CredibilityLevel | None = None
    ensemble: list[EnsembleJudgement] = Field(default_factory=_empty_ensemble_judgements)
    hunter_provider: str | None = None
    trigger_input: str | None = None
    scrubber_hits: int = 0
    triage_label: TriageLabel | None = None
    triage_notes: str | None = None
    triaged_at: datetime | None = None
    duplicate_of: str | None = None
    created_by: str
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _backfill_raw_severity(self) -> CandidateFinding:
        # Pre-calibration findings only set ``severity``; mirror it into
        # ``raw_severity`` so the raw value is always exposed.
        if self.raw_severity is None:
            self.raw_severity = self.severity
        return self


class FinalFinding(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    fingerprint: str
    vuln_class: VulnerabilityClass
    severity: Severity
    severity_adjusted: Severity | None = None
    raw_severity: Severity | None = None
    calibrated_severity: Severity | None = None
    calibrated_priority: int | None = None
    firing_rule_ids: list[str] = Field(default_factory=_empty_strings)
    title: str
    summary: str
    affected_component: str | None = None
    attack_surface_item_id: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    evidence_path: list[EvidencePathElement] = Field(default_factory=_empty_evidence_path)
    validation_result_id: str
    proof_artifact_ids: list[str] = Field(default_factory=_empty_strings)
    trace_id: str | None = None
    triage_label: TriageLabel | None = None
    remediation: str | None = None
    created_at: datetime

    @model_validator(mode="after")
    def _backfill_raw_severity(self) -> FinalFinding:
        if self.raw_severity is None:
            self.raw_severity = self.severity
        return self


class Report(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    title: str
    summary: str
    finding_ids: list[str]
    formats: list[str]
    artifact_refs: list[ArtifactRef]
    generated_at: datetime


class WorkflowEvent(BaseModel):
    """An observable event emitted during a scan workflow.

    ``event_type`` is a dot-namespaced string. Known types:

    Stage-grained (existing):
      ``scan.started``, ``scan.completed``, ``scan.failed``, ``stage.completed``

    Finding-grained (existing):
      ``finding.candidate``, ``finding.validated``, ``finding.promoted``

    Iteration-grained (ADR-020):
      ``agent.action_proposed`` — emitted per proposed action after the vagueness check.
        Payload: ``agent_kind``, ``iteration``, ``tool_name``, ``reasoning_summary``
        (hypothesis, scrubbed), ``check_result`` (passed/failed), ``reasoning_retries``.
      ``agent.reasoning_rejected`` — emitted when a retry is consumed or the loop halts
        with ``reasoning_rejected``. Payload: ``agent_kind``, ``iteration``, ``tool_name``,
        ``failed_checks``, ``retries_remaining``.

    All ``agent.*`` payloads are scrubbed before emission. Raw ``args`` and full reasoning
    text are never included in the payload; only the scrubbed ``reasoning_summary`` (hypothesis
    only) and structural metadata appear.
    """

    id: str
    scan_id: str
    workspace_id: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class AgentTask(BaseModel):
    id: str
    scan_id: str
    role: str
    task_name: str
    task_prompt: str = ""
    vuln_class: VulnerabilityClass | None = None
    scope: str | None = None
    # Entry points recon mapped for this scope, threaded through so the hunter
    # receives concrete leads instead of "(none identified)". Forward-ref to
    # EntryPoint (defined later in this module); resolved via model_rebuild().
    entry_points: list[EntryPoint] = Field(default_factory=_empty_entry_points)
    # Recon's free-text notes for this scope (per-class sink/source buckets),
    # carried so the hunter can seed backward-taint from recon's leads.
    recon_notes: str = ""
    # Assembled context-injector output for this task (assemble_domain_context),
    # computed once in emit_agent_tasks and carried here so hunt_impl can
    # render it without redoing plugin discovery/assembly per hunt call.
    domain_context: str = ""
    # Names of the context-injector plugins that contributed to domain_context
    # (provenance — empty when no plugin matched, even if plugins_active was
    # non-empty).
    domain_context_sources: list[str] = Field(default_factory=_empty_strings)
    # Knowledge Base consumption by reference (cpc slice 3): the KB root-index
    # artifact key recorded on the scan metadata by the kb-recon stage. The
    # consuming activity resolves it via the kb_context injector at execution
    # time — the task itself carries only the reference, never the content.
    kb_root_index_key: str | None = None
    source: Literal["recon", "gapfill", "feedback"] = "recon"
    gapfill_pass: int = 0
    # The iterative-coverage-loop round (0-based) in which this task is hunted
    # (ADR-022). round_index=0 for recon-derived tasks; gapfill/feedback tasks
    # emitted at the end of round N are stamped round_index=N+1.
    round_index: int = 0
    input_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    output_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    error: str | None = None


class ValidationResult(BaseModel):
    id: str
    candidate_finding_id: str
    scan_id: str
    verdict: Literal["validated", "rejected", "needs_proof", "inconclusive"]
    reasons: list[str] = Field(default_factory=_empty_strings)
    checks_run: list[str] = Field(default_factory=_empty_strings)
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    model_invocation_id: str | None = None
    cross_vendor: bool = False  # deprecated alias; use cross_vendor_disagreement
    cross_vendor_disagreement: bool = False
    # Ensemble credibility posterior + its contributing judgements (MDASH, D3).
    # ``credibility`` is None when no debater tier reviewed the candidate.
    credibility: CredibilityLevel | None = None
    ensemble: list[EnsembleJudgement] = Field(default_factory=_empty_ensemble_judgements)
    # The recorded negative-constraint checklist (cpc slice 5). Populated when the
    # debater runs the checklist refute regime; empty for the legacy binary refuter.
    checklist: list[ChecklistItem] = Field(default_factory=_empty_checklist)
    safe_payload: str | None = None  # benign exploit payload used to prove the finding
    created_at: datetime


class ProofArtifact(BaseModel):
    id: str
    scan_id: str
    candidate_finding_id: str
    final_finding_id: str | None = None
    proof_type: str
    description: str
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    safe_payload: str | None = None
    redaction_status: RedactionStatus
    created_at: datetime


class GapfillTask(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    vuln_class: VulnerabilityClass
    scope: str
    reason: str
    nudge_prompt_hint: str | None = None
    gapfill_pass: int = 1
    parent_task_id: str | None = None
    status: str = "pending"
    created_at: datetime


class CoverageGap(BaseModel):
    id: str
    scan_id: str
    scope_unit_id: str | None = None
    vuln_class: VulnerabilityClass | None = None
    reason: str
    recommended_next_task: str | None = None
    severity_hint: str | None = None


class ProductionFileStatus(StrEnum):
    """Coverage status of one first-party file in the snapshot manifest."""

    COVERED = "covered"
    INTENTIONALLY_EXCLUDED = "intentionally_excluded"
    GAP = "gap"


class ProductionFileAccounting(BaseModel):
    """The ledger's accounting for one first-party file.

    Every manifest file appears exactly once: ``covered`` (an investigation
    covers it), ``intentionally_excluded`` (out by scope, focus, or the
    production-code boundary — ``reason`` is required), or ``gap`` (neither —
    surfaced for gapfill). Excluded files are recorded, never silently
    omitted; gap files never carry a reason.
    """

    path: str
    status: ProductionFileStatus
    reason: str | None = None


class HunterGap(BaseModel):
    """A coverage gap a hunter self-reports at the end of its pass.

    It names an area (a path, directory, file, or input vector) the hunter did
    NOT fully investigate or deliberately skipped, plus why. Gapfill turns these
    into a fresh round of targeted re-hunt tasks. Fields are lenient (all have
    defaults) so a flaky open-model response can't fail validation on this field.
    ``vuln_class`` is filled in by the hunt activity from the task's class; the
    model only needs to emit ``area`` and ``reason``.
    """

    area: str = ""
    reason: str = ""
    vuln_class: VulnerabilityClass | None = None


class CoverageLedger(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    agent_tasks_total: int
    agent_tasks_scanned: int
    vuln_classes_requested: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    vuln_classes_completed: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    skipped_items: list[CoverageGap] = Field(default_factory=_empty_coverage_gaps)
    # Proactive production-file accounting (candidate-precision-and-calibration).
    # Every first-party file in the snapshot manifest is accounted for exactly
    # once: covered by an investigation, intentionally excluded (with reason),
    # or surfaced as a gap for gapfill to pick up. Empty for ledgers built
    # without a manifest (pre-guarantee behaviour).
    file_coverage: list[ProductionFileAccounting] = Field(
        default_factory=_empty_production_file_accounting
    )
    created_at: datetime

    def file_gap_paths(self) -> list[str]:
        """Paths of production files neither covered nor excluded (sorted)."""
        return [item.path for item in self.file_coverage if item.status is ProductionFileStatus.GAP]

    def file_excluded_paths(self) -> list[str]:
        """Paths of files recorded as intentionally excluded (sorted)."""
        return [
            item.path
            for item in self.file_coverage
            if item.status is ProductionFileStatus.INTENTIONALLY_EXCLUDED
        ]

    def file_covered_paths(self) -> list[str]:
        """Paths of production files covered by an investigation (sorted)."""
        return [
            item.path for item in self.file_coverage if item.status is ProductionFileStatus.COVERED
        ]


class GroundTruthFinding(BaseModel):
    id: str
    vuln_class: VulnerabilityClass
    file_path: str
    route: str | None = None
    severity: Severity
    expected_fingerprint_hint: str | None = None


class BenchmarkCase(BaseModel):
    id: str
    name: str
    repo_path: str
    target_url: str | None = None
    ground_truth_ref: ArtifactRef
    scan_profile_id: str


class ModelInvocation(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    task_name: str
    role: str
    provider: str
    model: str
    # Template provenance fields (ADR-019).
    # Legacy flat fields (prompt_version, prompt_hash) removed — old DB records
    # that contain them deserialize fine because Pydantic ignores extra fields.
    prompt_template_id: str = ""
    prompt_template_version: str = ""
    template_sha256: str = ""
    system_prompt_hash: str = ""
    developer_prompt_hash: str | None = None
    user_prompt_hash: str = ""
    evidence_hashes: list[str] = Field(default_factory=list)
    temperature: float = 0.0
    prompt_ref: ArtifactRef | None = None
    response_ref: ArtifactRef | None = None
    token_input: int | None = None
    token_output: int | None = None
    cached_tokens: int | None = None
    estimated_cost: float | None = None
    scrubber_hits: int = 0
    redaction_status: RedactionStatus = RedactionStatus.UNKNOWN
    created_at: datetime


class BudgetPolicy(BaseModel):
    id: str
    workspace_id: str
    max_cost_per_scan: float | None = None
    max_tokens_per_scan: int | None = None
    max_model_calls_per_stage: int | None = None
    max_concurrent_scans: int = 1
    max_runtime_seconds: int = 1800


class IntegrationEvent(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    event_type: str
    finding_id: str | None = None
    payload_ref: ArtifactRef | None = None
    created_at: datetime


class IntegrationRun(BaseModel):
    id: str
    scan_id: str
    integration_config_id: str
    integration_event_id: str
    idempotency_key: str
    status: IntegrationStatus
    dry_run: bool
    sink: str
    finding_fingerprint: str | None = None
    external_ref_id: str | None = None
    output_ref: ArtifactRef | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class NotificationMessage(BaseModel):
    title: str
    body: str
    severity: Severity | None = None
    scan_id: str
    finding_fingerprint: str | None = None
    links: list[str] = Field(default_factory=_empty_strings)


class TicketCreationRequest(BaseModel):
    idempotency_key: str
    title: str
    body: str
    severity: Severity
    labels: list[str] = Field(default_factory=_empty_strings)
    finding_fingerprint: str
    report_ref: ArtifactRef | None = None


class TicketCreationResult(BaseModel):
    idempotency_key: str
    dry_run: bool
    created: bool
    external_id: str | None = None
    url: str | None = None
    payload_ref: ArtifactRef | None = None


class ExternalFindingReference(BaseModel):
    id: str
    workspace_id: str
    finding_fingerprint: str
    system: str
    external_id: str
    url: str | None = None
    created_at: datetime


class ScanManifest(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    quarry_version: str
    profile_id: str
    panel_snapshot: list[ModelPanelEntry] = Field(default_factory=_empty_panel_entries)
    plugins_active: list[str] = Field(default_factory=_empty_strings)
    repo_commit_sha: str | None = None
    prompt_bundle_hash: str | None = None
    policy_bundle_hash: str | None = None
    created_at: datetime


class ToolInvocation(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    tool_name: str
    tool_version: str | None = None
    args_hash: str
    allowed: bool = True
    denied_reason: str | None = None
    exit_code: int | None = None
    stdout_ref: ArtifactRef | None = None
    stderr_ref: ArtifactRef | None = None
    started_at: datetime
    completed_at: datetime | None = None
    # ADR-020: accepted action reasoning (scrubbed hypothesis inlined for fast display;
    # full ActionReasoning stored as an artifact via reasoning_ref).
    reasoning_summary: str | None = None
    reasoning_ref: ArtifactRef | None = None


class FindingProvenance(BaseModel):
    finding_fingerprint: str
    scan_id: str
    manifest_id: str
    validation_result_id: str | None = None
    proof_artifact_ids: list[str] = Field(default_factory=_empty_strings)
    model_invocation_ids: list[str] = Field(default_factory=_empty_strings)
    tool_invocation_ids: list[str] = Field(default_factory=_empty_strings)
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)


class ReportProvenance(BaseModel):
    report_id: str
    scan_id: str
    manifest_id: str
    finding_fingerprints: list[str] = Field(default_factory=_empty_strings)
    inputs_hash: str
    generated_at: datetime


class DiffLabel(StrEnum):
    INTRODUCED_BY_DIFF = "introduced_by_diff"
    TOUCHED_BY_DIFF = "touched_by_diff"
    POSSIBLY_EXPOSED_BY_DIFF = "possibly_exposed_by_diff"
    UNCHANGED = "unchanged"


class ReachabilityVerdict(StrEnum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    INDETERMINATE = "indeterminate"


class RepoRole(StrEnum):
    PRIMARY = "primary"
    DEPENDENCY = "dependency"
    SIBLING = "sibling"


class ChangedFile(BaseModel):
    path: str
    status: str
    additions: int = 0
    deletions: int = 0
    hunks: list[str] = Field(default_factory=list)


class ImpactedCodeRegion(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    label: DiffLabel
    scope_name: str | None = None
    scope_type: str | None = None


def _empty_changed_files() -> list[ChangedFile]:
    return []


def _empty_impacted_regions() -> list[ImpactedCodeRegion]:
    return []


def _empty_call_edges() -> list[CallEdge]:
    return []


def _empty_run_repos() -> list[RunRepo]:
    return []


class EntryPoint(BaseModel):
    repo: str
    file: str
    function: str
    kind: Literal[
        "http_handler",
        "cli_arg",
        "library_export",
        "fuzz_harness",
        "main",
        "message_handler",
        "unknown",
    ]
    # ADR-024 §C.2: how a CLI/binary entry point is invoked, so the prove stage
    # runs the target without guessing. Empty/absent for non-CLI kinds.
    invocation: list[str] = []
    attacker_controlled_input: Literal["args", "stdin", "env", "config_file", "none"] = "none"


# AgentTask references EntryPoint in a forward annotation but is defined above
# it; rebuild now that EntryPoint exists so the field type resolves.
AgentTask.model_rebuild()


class CallEdge(BaseModel):
    caller_repo: str
    caller_file: str
    caller_function: str
    callee_repo: str
    callee_file: str
    callee_function: str


class RunRepo(BaseModel):
    id: str
    scan_id: str
    name: str
    url: str
    sha: str
    role: RepoRole
    clone_depth: int = 1
    clone_filter: str | None = None
    subtree_scope: str | None = None
    vendor_allowlist: list[str] = Field(default_factory=_empty_strings)


class Trace(BaseModel):
    id: str
    scan_id: str
    finding_id: str
    reachable: ReachabilityVerdict
    entry_points: list[EntryPoint] = Field(default_factory=_empty_entry_points)
    cross_repo: bool = False
    trace_notes: str | None = None
    model_invocation_id: str | None = None


class CallGraph(BaseModel):
    scan_id: str
    repos: list[RunRepo] = Field(default_factory=_empty_run_repos)
    entry_points: list[EntryPoint] = Field(default_factory=_empty_entry_points)
    edges: list[CallEdge] = Field(default_factory=_empty_call_edges)
    index_kind: str = "static"


class GitDiff(BaseModel):
    base_commit: str
    head_commit: str
    changed_files: list[ChangedFile] = Field(default_factory=_empty_changed_files)
    total_additions: int = 0
    total_deletions: int = 0


class DiffScanInput(BaseModel):
    repo_path: str
    base_commit: str
    head_commit: str
    db_path: str
    target_url: str | None = None


class DiffScanResult(BaseModel):
    scan_id: str
    git_diff: GitDiff
    impacted_regions: list[ImpactedCodeRegion] = Field(default_factory=_empty_impacted_regions)
    candidate_finding_count: int = 0
    final_finding_count: int = 0


# ---------------------------------------------------------------------------
# Agentic harness schemas
# ---------------------------------------------------------------------------


class TrustBoundary(BaseModel):
    """A boundary in the target system that crosses a trust domain."""

    name: str
    description: str
    crosses: list[str] = Field(default_factory=_empty_strings)
    auth_model: str


class BuildCommand(BaseModel):
    """A command needed to build, test, run, fuzz, or install the target."""

    purpose: Literal["build", "test", "run", "fuzz", "install"]
    command: str
    working_dir: str


def _empty_trust_boundaries() -> list[TrustBoundary]:
    return []


def _empty_build_commands() -> list[BuildCommand]:
    return []


class SubsystemAssignment(BaseModel):
    """Assignment returned by the recon orchestrator activity."""

    model_config = {"frozen": True}

    name: str
    root_paths: list[str]
    languages: list[str]
    responsibility: str


class Subsystem(BaseModel):
    """A coherent sub-section of the target repository."""

    name: str
    root_paths: list[str]
    languages: list[str]
    responsibility: str
    entry_points: list[EntryPoint] = Field(default_factory=_empty_entry_points)
    notes: str = ""


def _empty_subsystems() -> list[Subsystem]:
    return []


class ArchitectureDoc(BaseModel):
    """Language-agnostic structural analysis produced by the recon agent."""

    repo_languages: list[str]
    primary_language: str
    repo_type: str  # "web_service" | "cli" | "fuzzing" | "mixed"
    subsystems: list[Subsystem] = Field(default_factory=_empty_subsystems)
    entry_points: list[EntryPoint] = Field(default_factory=_empty_entry_points)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=_empty_trust_boundaries)
    build_commands: list[BuildCommand] = Field(default_factory=_empty_build_commands)
    attack_surface_summary: str = ""
    transcript_refs: list[str] = Field(default_factory=_empty_strings)


class AgentStep(BaseModel):
    """One iteration recorded inside an agent loop."""

    agent_kind: Literal[
        "orchestrator",
        "subsystem",
        "synthesis",
        "hunt",
        "validate",
        "calibrate",
        "prove",
        "trace",
        "gapfill",
        "dynamic_validate",
        "live_recon",
        "exploit",
    ]
    iteration: int
    tool_calls: list[str] = Field(default_factory=_empty_strings)
    model_invocation_id: str
    estimated_cost: float = 0.0
    # ADR-020: artifact IDs of ActionReasoning objects that were rejected this iteration.
    # Enables audit of "what did the agent try to justify before getting it right?"
    rejected_reasoning_refs: list[str] = Field(default_factory=_empty_strings)
    # ADR-020: scrubbed hypothesis of the first *accepted* ProposedAction in this iteration.
    # None when the iteration had no proposed_actions (e.g. a pure tool-execution turn or
    # when the iteration ended in reasoning_rejected before any action was accepted).
    reasoning_summary: str | None = None


def _empty_agent_steps() -> list[AgentStep]:
    return []


class AgentLoopResult(BaseModel):
    """Result returned by run_agent_loop."""

    final_answer: Any | None = None
    steps: list[AgentStep] = Field(default_factory=_empty_agent_steps)
    iterations_used: int
    total_cost: float = 0.0
    stop_reason: Literal[
        "final_answer",
        "max_iterations",
        "budget_exceeded",
        "guard_triggered",
        # ADR-020: all reasoning_max_retries for an action consumed; loop halted.
        "reasoning_rejected",
        # All max_parse_retries for a turn consumed (schema/parse failure); loop halted.
        "schema_rejected",
        # Per-tier tool_call_cap reached; loop stopped issuing tool calls (mdash D1).
        "tool_call_cap",
    ]


# ---------------------------------------------------------------------------
# Action reasoning and vagueness-guard schemas (ADR-020)
# ---------------------------------------------------------------------------


class ActionReasoning(BaseModel):
    """Structured intent the agent must provide for every proposed tool call.

    Four non-optional slots force specificity by construction: a model that cannot
    fill ``target_ref`` with a concrete locator has no concrete locator to report.
    All fields are scrubbed before persistence, logging, and TUI display.

    Note: this describes *tool-call intent*, not *finding justification*.
    ``CandidateFinding.reasoning`` (finding justification) is validator-blind;
    ``ActionReasoning`` is operator-visible but never sent to any model role.
    """

    hypothesis: str
    """What the agent believes and is testing RIGHT NOW (e.g. 'reflected XSS via `q`)."""

    target_ref: str
    """Concrete locator: URL path, param name, or file:line (e.g. 'GET /search?q=')."""

    expected_evidence: str
    """The specific observable signal that confirms or denies the hypothesis."""

    why_this_tool: str
    """Why this particular tool + args advances the hypothesis over other options."""


class ProposedAction(BaseModel):
    """An action the agent loop proposes to execute, with mandatory structured reasoning.

    ``reasoning`` is required on every proposal. The loop's vagueness guard
    (``check_vague_reasoning`` in ``guards.py``) inspects it deterministically
    before any tool is executed.

    This class lives in ``quarry.schemas`` and is re-exported from
    ``quarry_models.validation`` for back-compat with code that imported it there.
    """

    kind: str
    """Checked against ROLE_ALLOWED_ACTION_KINDS[role] before execution."""

    tool_name: str
    """The tool to call (matches a registered tool in the ToolRunner registry)."""

    args: dict[str, Any] = Field(default_factory=dict)
    """Tool-specific arguments (raw, before scrubbing)."""

    reasoning: ActionReasoning
    """MANDATORY structured reasoning — missing or partial reasoning is rejected."""


class ReasoningCheckResult(BaseModel):
    """Result of the deterministic vagueness guard over a ProposedAction's reasoning.

    ``passed=True`` means the action may proceed to execution.
    ``passed=False`` triggers a re-prompt (up to ``reasoning_max_retries`` times)
    before the loop halts with ``stop_reason='reasoning_rejected'``.
    """

    passed: bool
    failed_checks: list[str] = Field(default_factory=list)
    """Names of failed sub-checks: 'presence', 'context_reference', 'lexicon', 'args_coherence'."""

    detail: str = ""
    """Human-readable feedback rendered into the re-prompt (via the vague_reasoning.j2 template)."""


# ---------------------------------------------------------------------------
# Validator-independence boundary (ADR-021)
# ---------------------------------------------------------------------------


class ValidatorClaim(BaseModel):
    """The subset of a CandidateFinding the validator is allowed to receive.

    Contains only claim fields: file location, vuln_class, and the finding
    description. Hunter reasoning, provider, tool trace, and model name are
    intentionally excluded to preserve the adversarial-review design.
    """

    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    vuln_class: VulnerabilityClass
    description: str
    affected_code_snippet: str | None = None


# ---------------------------------------------------------------------------
# Live-dynamic validation schemas (ADR-017)
# ---------------------------------------------------------------------------

# Patterns that look like inline credentials; auth_profile must never carry them.
_CREDENTIAL_RE = re.compile(
    r"^(sk-[A-Za-z0-9\-_]{8,}|ghp_[A-Za-z0-9]{10,}|Bearer\s+[A-Za-z0-9._\-]{10,})$"
)


class TargetEndpoint(BaseModel):
    """The single host:port the egress policy permits for live dynamic validation."""

    host: str
    port: int
    scheme: Literal["http", "https"] = "http"
    base_path: str = "/"


class HttpRequestSpec(BaseModel):
    """The HTTP request a dynamic_validate or prove agent proposes.

    Carries no inline secrets; auth_profile references a named credential from
    Target.auth_config_ref, never an inline token.
    """

    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    auth_profile: str | None = None  # named cred only; never an inline token

    @field_validator("auth_profile")
    @classmethod
    def _reject_inline_credential(cls, v: str | None) -> str | None:
        if v is not None and _CREDENTIAL_RE.match(v):
            msg = (
                f"auth_profile looks like an inline credential: '{v[:12]}…'. "
                "Use a named credential reference, never an inline token."
            )
            raise ValueError(msg)
        return v


class HttpResponseCapture(BaseModel):
    """Captured HTTP response; body stored as an artifact, not inline."""

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_artifact_ref: str  # ArtifactRef id for the scrubbed, size-limited body
    elapsed_ms: int
    scrubber_hits: int = 0
    redaction_status: RedactionStatus
    # ArtifactRef id for the captured request (set by http_request_activity).
    request_artifact_ref: str | None = None
    # Store KEY the response artifact was written under (set by
    # http_request_activity). body_artifact_ref is a uuid id; the artifact
    # store is key-addressed, so per-class body evaluators resolve the body
    # through this key via the read-artifact-text activity. Optional — legacy
    # captures construct without it and evaluators treat a missing body as
    # non-corroboration, never an error.
    body_artifact_key: str | None = None


class DynamicEvidenceLink(BaseModel):
    """Source-to-dynamic provenance chain: white-box anchor → HTTP round-trip → finding."""

    source_ref: SourceRef
    attack_surface_item_id: str | None = None
    request_artifact_id: str
    response_artifact_id: str
    candidate_finding_id: str


# ---------------------------------------------------------------------------
# Live exploitation schemas (Shannon pillar — the app-centric track)
# ---------------------------------------------------------------------------


class LiveSessionContext(BaseModel):
    """Redacted live-session state carried across exploitation turns (design D2).

    Distinct from the LLM message history: holds the session cookies, CSRF/auth
    tokens, and IDs discovered mid-chain that later requests depend on. Values are
    redacted references (never raw secrets) — the dispatch/egress path is
    responsible for scrubbing before anything re-enters a prompt.
    """

    cookies: dict[str, str] = Field(default_factory=dict)
    tokens: dict[str, str] = Field(default_factory=dict)
    discovered_ids: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=_empty_strings)


class ExploitStep(BaseModel):
    """One request/response round in an exploit chain — an ordered proof unit (D3)."""

    order: int
    intent: str  # "login" | "enumerate" | "exploit" | ...
    request_spec: HttpRequestSpec
    request_artifact_id: str | None = None
    response_artifact_id: str | None = None
    status_code: int | None = None
    dispatched: bool = True  # False when refused by rules-of-engagement before egress
    confirmed: bool = False  # this step demonstrated the exploit
    notes: str = ""


def _empty_exploit_steps() -> list[ExploitStep]:
    return []


class ExploitChain(BaseModel):
    """Ordered request/response chain that demonstrates an exploit — the proof (D3).

    The app-centric analogue of Glasswing's compile-and-run PoC: a finding is emitted
    only when a chain is ``proven`` (at least one confirmed exploit step). The chain
    is also the persisted provenance artifact for a live-proven finding.
    """

    scan_id: str
    workspace_id: str
    vuln_class: VulnerabilityClass
    steps: list[ExploitStep] = Field(default_factory=_empty_exploit_steps)
    proven: bool = False
    summary: str = ""


# ---------------------------------------------------------------------------
# Sandbox execution schemas (ADR-017 §5 — transport-agnostic prove subsystem)
# ---------------------------------------------------------------------------


class EnvProfile(StrEnum):
    """Named, vetted environment profiles for sandbox execution.

    The prove agent picks a NAME, never raw env-var values.  Credential injection
    (QUARRY_INJECTED_CRED_*) is the sole exception and is resolved worker-side (ADR-018).
    """

    NONE = "none"  # empty env — default; tightest containment
    REPO_READONLY = "repo_readonly"  # minimal PATH + repo root only, no credentials


class SandboxExecSpec(BaseModel):
    """A CLI/binary invocation the prove agent proposes.  No live I/O in agent context.

    Parallels HttpRequestSpec: carries no inline secrets; auth_profile and env_profile
    are NAMES resolved worker-side at dispatch (ADR-018).  input_files are crafted
    attacker-controlled files staged into the sandbox working dir before execution.
    """

    command: str
    args: list[str] = Field(default_factory=list)
    stdin: str | None = None
    env_profile: EnvProfile = EnvProfile.NONE
    cwd: str = "."  # relative to sandbox working dir; restricted worker-side
    input_files: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = 30  # hard-capped worker-side (max 60 s)
    auth_profile: str | None = None  # named cred only; never an inline token

    @field_validator("auth_profile")
    @classmethod
    def _reject_inline_credential(cls, v: str | None) -> str | None:
        if v is not None and _CREDENTIAL_RE.match(v):
            msg = (
                f"auth_profile looks like an inline credential: '{v[:12]}…'. "
                "Use a named credential reference, never an inline token."
            )
            raise ValueError(msg)
        return v


class SandboxExecCapture(BaseModel):
    """Captured result of a sandbox execution.  Parallels HttpResponseCapture.

    stdout/stderr stored as artifacts (TOOL_STDOUT/TOOL_STDERR), never inline.
    Both streams pass through Scrubber.scrub() + <target_content> wrap before
    any prompt re-entry (same policy as HTTP response bodies).
    """

    exit_code: int
    stdout_artifact_ref: str  # ArtifactRef id — scrubbed, size-capped TOOL_STDOUT
    stderr_artifact_ref: str  # ArtifactRef id — scrubbed, size-capped TOOL_STDERR
    elapsed_ms: int
    scrubber_hits: int = 0
    redaction_status: RedactionStatus
    timed_out: bool = False


class ProveCorpus(BaseModel):
    """A dataset the prove sandbox materializes as the CLI's working input.

    The CLI target cannot be proven in isolation — it needs a corpus to operate on
    (e.g. a dbt project for dbt Core, a sample repo for a linter).  This is staged
    into the sandbox working dir alongside any crafted input_files.
    """

    source: str  # local path or git URL
    materialize_as: str = "project"  # subdir created inside the sandbox working dir
    setup_commands: list[BuildCommand] = Field(default_factory=_empty_build_commands)

    @field_validator("materialize_as")
    @classmethod
    def _reject_non_relative(cls, v: str) -> str:
        from pathlib import PurePosixPath

        p = PurePosixPath(v)
        if p.is_absolute() or ".." in p.parts:
            msg = (
                f"materialize_as must be a simple relative path, got '{v}'. "
                "Absolute paths and path traversal (..) are rejected."
            )
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Target authentication schemas (ADR-018)
# ---------------------------------------------------------------------------

# Extend the inline-credential pattern to cover common token formats.
_SECRET_REF_ENV_CREDENTIAL_RE = re.compile(
    r"^(sk-[A-Za-z0-9\-_]{8,}|ghp_[A-Za-z0-9]{10,}|Bearer\s+[A-Za-z0-9._\-]{10,}"
    r"|cpk_[A-Za-z0-9]{8,}|eyJ[A-Za-z0-9._\-]{20,})$"
)

# Env var prefixes whose values are always treated as secrets by the scrubber.
SENSITIVE_ENV_KEYS: frozenset[str] = frozenset(
    {
        "QUARRY_SECRET_",  # prefix convention (ADR-018)
        "CHUTES_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "GIT_CLONE_TOKEN",
    }
)


class SecretRef(BaseModel):
    """Pointer to a secret value held in an environment variable.

    The value is never stored here — only the env-var name.
    """

    env: str  # e.g. "QUARRY_SECRET_ADMIN_TOKEN"

    @field_validator("env")
    @classmethod
    def _env_nonempty(cls, v: str) -> str:
        if not v:
            msg = "SecretRef.env must be a non-empty environment variable name."
            raise ValueError(msg)
        return v


# Full-string ``${secret:ENV_VAR_NAME}`` template syntax for referencing an
# environment variable in TOML-sourced string config (e.g. quarry.toml
# [integrations.<name>] tables). Distinct from credentials.py's embedded
# find-all usage of the same syntax inside field_template strings — this one
# requires the *entire* value to be the template, since it parses into a
# SecretRef pointer rather than substituting a value into a larger string.
SECRET_TEMPLATE_RE = re.compile(r"^\$\{secret:([A-Z0-9_]+)\}$")


def parse_secret_ref_template(value: str) -> SecretRef:
    """Parse a ``${secret:ENV_VAR_NAME}`` string into a SecretRef.

    Raises ValueError if *value* is not exactly in that form — secret-shaped
    config fields must reference an environment variable, never carry a
    literal value inline.
    """
    match = SECRET_TEMPLATE_RE.match(value)
    if not match:
        msg = (
            "Expected a secret reference in the form '${secret:ENV_VAR_NAME}', "
            f"got: {value!r}. Never place a literal secret value in config."
        )
        raise ValueError(msg)
    return SecretRef(env=match.group(1))


class TotpConfig(BaseModel):
    """TOTP configuration for OTP-gated login flows (RFC 6238)."""

    seed_ref: SecretRef  # base32 TOTP seed in env
    digits: int = 6
    period_seconds: int = 30
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"


class CredentialExtract(BaseModel):
    """Where to find the credential in the login response."""

    from_json: str | None = None  # JSONPath expression, e.g. "$.access_token"
    from_cookie: str | None = None  # cookie name
    from_header: str | None = None  # response header name
    inject_as: Literal["bearer", "cookie", "header"]  # how to attach to subsequent requests


class LoginStep(BaseModel):
    """A single login flow (POST credentials, receive token/cookie)."""

    path: str  # login endpoint path, relative to target base_path
    field_template: dict[str, str]  # placeholders: ${secret:ENV}, ${totp}, ${username}
    extract: CredentialExtract
    ttl_seconds: int | None = None  # cache TTL; re-login on expiry or 401


class SuccessCheck(BaseModel):
    """Operator-defined, code-evaluated signal that a login or call succeeded (ADR-023 §3).

    The verdict is decided deterministically in code — never by the model. ``description``
    is surfaced to the agent for reasoning only.
    """

    kind: Literal["url_matches", "selector_present", "text_present", "status_ok"]
    value: str = ""  # url substring | CSS selector | expected text | (status: unused)
    description: str = ""


class BrowserAction(BaseModel):
    """One step in a browser login's closed action vocabulary (ADR-023 §2 — never raw JS)."""

    action: Literal["click", "fill", "wait_for"]
    selector: str
    value: str | None = None  # for fill; supports ${username}/${secret:ENV}/${totp}


def _empty_browser_actions() -> list[BrowserAction]:
    return []


class BrowserLoginStep(BaseModel):
    """Declarative browser-login flow — no secrets, no arbitrary code (ADR-023 §2)."""

    start_url: str  # login page path (host must be in allowed_hosts)
    username_selector: str
    password_selector: str
    submit_selector: str
    otp_selector: str | None = None  # OTP field selector (when TOTP-gated)
    extra_steps: list[BrowserAction] = Field(default_factory=_empty_browser_actions)
    success: SuccessCheck
    failure_check: SuccessCheck | None = None
    ttl_seconds: int | None = None


class AuthProfileKind(StrEnum):
    BEARER = "bearer"
    BASIC = "basic"
    STATIC_HEADER = "static_header"
    COOKIE = "cookie"
    LOGIN_FLOW = "login_flow"
    BROWSER_LOGIN = "browser_login"


class AuthProfile(BaseModel):
    """Declares how to authenticate to a target.  No inline secrets ever.

    Secret values live in env vars under QUARRY_SECRET_*.  The profile name
    is what HttpRequestSpec.auth_profile carries; the concrete credential is
    resolved worker-side at dispatch time and never returned to the agent.
    """

    name: str
    kind: AuthProfileKind
    secret_ref: SecretRef | None = None  # bearer / basic / static_header / cookie
    username: str | None = None  # non-secret (basic auth / login template)
    name_hint: str | None = None  # custom header or cookie name
    login: LoginStep | None = None  # required when kind == login_flow
    browser_login: BrowserLoginStep | None = None  # required when kind == browser_login
    totp: TotpConfig | None = None  # TOTP when login is OTP-gated

    @field_validator("secret_ref")
    @classmethod
    def _reject_inline_secret_env(cls, v: SecretRef | None) -> SecretRef | None:
        if v is not None and _SECRET_REF_ENV_CREDENTIAL_RE.match(v.env):
            msg = (
                f"SecretRef.env looks like an inline credential: '{v.env[:12]}…'. "
                "Use an environment variable name (e.g. QUARRY_SECRET_TOKEN), "
                "never an inline token value."
            )
            raise ValueError(msg)
        return v


class AuthProfileSet(BaseModel):
    """The complete set of auth profiles for a scan, loaded from auth-profiles.toml."""

    profiles: list[AuthProfile] = Field(default_factory=lambda: [])

    @field_validator("profiles")
    @classmethod
    def _reject_duplicate_names(cls, v: list[AuthProfile]) -> list[AuthProfile]:
        names = [p.name for p in v]
        seen: set[str] = set()
        for name in names:
            if name in seen:
                msg = f"AuthProfileSet contains duplicate profile name: '{name}'."
                raise ValueError(msg)
            seen.add(name)
        return v

    def get(self, name: str) -> AuthProfile | None:
        """Return the profile with the given name, or None."""
        for p in self.profiles:
            if p.name == name:
                return p
        return None


class IntegrationConfig(BaseModel):
    """Per-integration settings: enable/dry-run/severity gate/secret.

    Sourced from quarry.toml [integrations.<name>] tables by default (see
    panel_config.resolve_integration_configs) and carried on ScanProfile.
    """

    integration_type: str
    enabled: bool = False
    dry_run: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secret_ref: SecretRef | None = None
    severity_threshold: Severity = Severity.CRITICAL

    @field_validator("secret_ref")
    @classmethod
    def _reject_inline_secret_env(cls, v: SecretRef | None) -> SecretRef | None:
        if v is not None and _SECRET_REF_ENV_CREDENTIAL_RE.match(v.env):
            msg = (
                f"SecretRef.env looks like an inline credential: '{v.env[:12]}…'. "
                "Use an environment variable name (e.g. QUARRY_SECRET_TOKEN), "
                "never an inline token value."
            )
            raise ValueError(msg)
        return v


# ScanProfile references IntegrationConfig in a forward annotation but is
# defined above it; rebuild now that IntegrationConfig exists so the field
# type resolves (mirrors AgentTask/EntryPoint below).
ScanProfile.model_rebuild()


def local_scan_profile(
    target_url: str | None = None,
    vuln_classes: list[VulnerabilityClass] | None = None,
    dynamic_validation_enabled: bool = False,
    integration_configs: list[IntegrationConfig] | None = None,
    integrations_enabled: bool = True,
    plugins_active: list[str] | None = None,
) -> ScanProfile:
    """Build a local fast-scan profile.

    dynamic_validation_enabled is explicitly controlled by the caller
    (e.g. the CLI's --dynamic-validation flag).  A bare target_url does NOT
    flip the live-HTTP gate — that was an explicitly-rejected alternative in
    ADR-017, section "Alternatives considered".

    integration_configs defaults to quarry.toml's resolved [integrations.*]
    tables (see panel_config.resolve_integration_configs); pass an explicit
    list (e.g. []) to override.

    integrations_enabled defaults to True (dry-run by default via
    dry_run_integrations); the caller passes False to force no integration
    delivery of any kind — e.g. benchmark runs, where scoring accuracy must
    never trigger an external side effect.

    plugins_active defaults to [] (context-injector plugins disabled unless
    explicitly named — see panel_config.ScanDefaultsConfig.plugins_active).
    """
    return ScanProfile(
        id="local-fast",
        name="Local Fast",
        vuln_classes=vuln_classes
        or [
            VulnerabilityClass.SECRETS,
            VulnerabilityClass.IDOR,
            VulnerabilityClass.COMMAND_INJECTION,
        ],
        dynamic_validation_enabled=dynamic_validation_enabled,
        integrations_enabled=integrations_enabled,
        integration_configs=integration_configs or [],
        plugins_active=plugins_active or [],
    )
