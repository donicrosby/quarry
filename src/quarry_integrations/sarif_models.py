"""SARIF v2.1.0 models (OASIS Standard) for the SARIF finding sink.

Only the subset of the SARIF schema Quarry emits is modelled: a single run, the
tool driver that produced it, and one result per finding. Field names keep
SARIF's camelCase so ``model_dump_json`` emits spec-conformant JSON without a
per-field alias layer; ``schema_url`` carries an alias because ``$schema`` is
not a valid Python identifier.

``result.properties.quarry`` carries Quarry's own namespace:

* ``severity`` — the *original* severity, unmapped, because the severity-to-level
  mapping collapses ``low`` and ``info`` onto ``note`` and a CI-side
  ``severity_threshold`` filter must act on the pre-mapping value.
* ``severity_rationale_state`` — how the finding's severity rationale was
  produced (``model`` / ``legacy`` / ``model_omitted``). The rationale's prose
  slots are model-authored and are never exported; only this closed-set state
  is, so a consumer can tell a real rationale from a backfilled one without
  trusting (or gating on) the prose.
"""

from __future__ import annotations

import importlib.metadata
from collections.abc import Iterable, Sequence
from enum import StrEnum
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from quarry.schemas import FinalFinding, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_TOOL_NAME = "quarry"
QUARRY_FINGERPRINT_KEY = "quarryFingerprint"


class SarifLevel(StrEnum):
    """SARIF ``result.level`` (``none`` is not produced by Quarry)."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


class SeverityRationaleState(StrEnum):
    """How a finding's ``severity_rationale`` was produced (finding-contract).

    A closed set, so the export surfaces the honesty markers (``legacy`` for a
    pre-contract finding, ``model_omitted`` for slots the model did not supply)
    as data rather than embedding the untrusted prose slots.
    """

    MODEL = "model"
    LEGACY = "legacy"
    MODEL_OMITTED = "model_omitted"


# Quarry severity -> SARIF result level (constant lookup table). ``low`` and
# ``info`` both collapse onto ``note``; the original severity travels in
# ``ResultProperties.quarry`` so threshold filtering stays lossless.
SEVERITY_TO_LEVEL: dict[Severity, SarifLevel] = {
    Severity.CRITICAL: SarifLevel.ERROR,
    Severity.HIGH: SarifLevel.ERROR,
    Severity.MEDIUM: SarifLevel.WARNING,
    Severity.LOW: SarifLevel.NOTE,
    Severity.INFO: SarifLevel.NOTE,
}


def _empty_rules() -> list[ReportingDescriptor]:
    return []


def _empty_locations() -> list[Location]:
    return []


def _empty_fingerprints() -> dict[str, str]:
    return {}


def _empty_results() -> list[Result]:
    return []


def _empty_runs() -> list[Run]:
    return []


class Message(BaseModel):
    text: str


class ArtifactLocation(BaseModel):
    uri: str


class Region(BaseModel):
    startLine: int
    endLine: int | None = None


class PhysicalLocation(BaseModel):
    artifactLocation: ArtifactLocation
    region: Region | None = None


class Location(BaseModel):
    physicalLocation: PhysicalLocation


class ReportingDescriptor(BaseModel):
    id: str
    name: str
    shortDescription: Message


class Driver(BaseModel):
    name: str
    version: str
    rules: list[ReportingDescriptor] = Field(default_factory=_empty_rules)


class Tool(BaseModel):
    driver: Driver


class QuarryResultProperties(BaseModel):
    """``result.properties.quarry`` — Quarry's own namespace on a result."""

    severity: Severity
    severity_rationale_state: SeverityRationaleState


class ResultProperties(BaseModel):
    quarry: QuarryResultProperties


class Result(BaseModel):
    ruleId: str
    level: SarifLevel
    message: Message
    locations: list[Location] = Field(default_factory=_empty_locations)
    partialFingerprints: dict[str, str] = Field(default_factory=_empty_fingerprints)
    properties: ResultProperties


class Run(BaseModel):
    tool: Tool
    results: list[Result] = Field(default_factory=_empty_results)


class SarifLog(BaseModel):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    version: str = SARIF_VERSION
    schema_url: str = Field(default=SARIF_SCHEMA_URI, alias="$schema")
    runs: list[Run] = Field(default_factory=_empty_runs)


def quarry_tool_version() -> str:
    """Installed Quarry distribution version, or ``0.0.0`` outside an install."""
    try:
        return importlib.metadata.version("quarry")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def _tool() -> Tool:
    return Tool(driver=Driver(name=SARIF_TOOL_NAME, version=quarry_tool_version()))


def _message_text(finding: FinalFinding) -> str:
    return f"{finding.title}\n\n{finding.summary}"


def _artifact_uri(path: str) -> str:
    """A finding's path as a SARIF ``artifactLocation.uri``.

    SARIF locations are URIs, and the path originates in model/target output:
    reserved characters (space, ``#``, ``?``) must be escaped so a path cannot
    change the URI's structure for the consuming code-scanning dashboard.
    """
    return quote(path)


def _primary_location(finding: FinalFinding) -> PhysicalLocation | None:
    """The finding's primary source location, or ``None`` when it has none.

    Resolution mirrors the report's evidence links: the ordered, sink-first
    ``evidence_path`` wins (index 0 is the flaw's primary site) and a
    ``source_ref`` is the fallback, so both surfaces point at the same place.
    """
    if finding.evidence_path:
        element = finding.evidence_path[0]
        return PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=_artifact_uri(element.path)),
            region=Region(startLine=element.line),
        )
    if finding.source_refs:
        ref = finding.source_refs[0]
        region = None
        if ref.start_line is not None:
            region = Region(startLine=ref.start_line, endLine=ref.end_line)
        return PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=_artifact_uri(ref.file_path)), region=region
        )
    return None


def severity_rationale_state(finding: FinalFinding) -> SeverityRationaleState:
    """Classify a finding's severity rationale by its honesty markers only."""
    rationale = finding.severity_rationale
    if rationale.legacy:
        return SeverityRationaleState.LEGACY
    if rationale.model_omitted:
        return SeverityRationaleState.MODEL_OMITTED
    return SeverityRationaleState.MODEL


def finding_to_sarif_result(finding: FinalFinding) -> Result:
    """Convert one ``FinalFinding`` into a SARIF ``Result``.

    Only explicitly mapped finding fields are copied — the result is a
    whitelist, never ``model_dump`` of the finding, so fields Quarry does not
    intend to publish (``proof_artifact_ids``, ``trace_id``, raw evidence
    references, and the rationale's model-authored prose) cannot leak into the
    log. The rationale appears as its ``severity_rationale_state`` marker alone.
    """
    location = _primary_location(finding)
    return Result(
        ruleId=finding.vuln_class.value,
        level=SEVERITY_TO_LEVEL[finding.severity],
        message=Message(text=_message_text(finding)),
        locations=[Location(physicalLocation=location)] if location is not None else [],
        partialFingerprints={QUARRY_FINGERPRINT_KEY: finding.fingerprint},
        properties=ResultProperties(
            quarry=QuarryResultProperties(
                severity=finding.severity,
                severity_rationale_state=severity_rationale_state(finding),
            )
        ),
    )


def rules_for(results: Sequence[Result]) -> list[ReportingDescriptor]:
    """One driver rule per distinct ``ruleId`` present, sorted for determinism."""
    rule_ids = sorted({result.ruleId for result in results})
    return [
        ReportingDescriptor(
            id=rule_id,
            name=rule_id,
            shortDescription=Message(text=f"Quarry vulnerability class: {rule_id}"),
        )
        for rule_id in rule_ids
    ]


def merge_result(log: SarifLog, result: Result) -> SarifLog:
    """Append ``result`` to the log, replacing any result with the same fingerprint."""
    run = log.runs[0] if log.runs else Run(tool=_tool(), results=[])
    fingerprint = result.partialFingerprints.get(QUARRY_FINGERPRINT_KEY)
    kept = [
        existing
        for existing in run.results
        if existing.partialFingerprints.get(QUARRY_FINGERPRINT_KEY) != fingerprint
    ]
    results = [*kept, result]
    driver = run.tool.driver.model_copy(update={"rules": rules_for(results)})
    tool = run.tool.model_copy(update={"driver": driver})
    merged_run = run.model_copy(update={"tool": tool, "results": results})
    return log.model_copy(update={"runs": [merged_run]})


def new_sarif_log() -> SarifLog:
    """An empty, valid SARIF log carrying the tool driver metadata."""
    return SarifLog(runs=[Run(tool=_tool(), results=[])])


def build_sarif_log(findings: Iterable[FinalFinding]) -> SarifLog:
    """Build a complete SARIF log from findings; zero findings is valid (empty ``results``)."""
    log = new_sarif_log()
    for finding in findings:
        log = merge_result(log, finding_to_sarif_result(finding))
    return log
