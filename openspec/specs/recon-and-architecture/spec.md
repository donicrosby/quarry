# recon-and-architecture Specification

## Purpose

Before hunting, Quarry builds an understanding of the target: a recon orchestrator reads
layout and manifests, subsystem agents explore in parallel, and a synthesis step produces
an `ArchitectureDoc` describing languages, subsystems, entry points, trust boundaries, and
build commands. That document drives task emission: one hunt task per (vulnerability class,
scope). Recon is agent-driven and language-agnostic - no per-language detector code.

## Requirements

### Requirement: Agentic architecture mapping

Recon SHALL produce an `ArchitectureDoc` from a deterministic orchestrator pass plus
parallel subsystem agents and a synthesis step. It SHALL be language-agnostic, deriving
languages, subsystems, entry points, and trust boundaries without per-language detector
code.

#### Scenario: Architecture document is produced

- **WHEN** recon completes on a repository
- **THEN** an `ArchitectureDoc` with detected languages, subsystems, entry points, and
  trust boundaries is produced

#### Scenario: One subsystem failure does not fail the scan

- **WHEN** a single subsystem recon agent errors
- **THEN** recon continues and synthesizes from the successful subsystems

### Requirement: Non-executing mapping

Recon SHALL map the target by reading source and manifests; it SHALL NOT execute the
target application to discover its structure.

#### Scenario: Target app is not run during recon

- **WHEN** attack surface is derived
- **THEN** it comes from static reading, not from running the target

### Requirement: Task emission per class and scope

From the `ArchitectureDoc`, recon SHALL emit hunt tasks - one `AgentTask` per
(vulnerability class, scope) - carrying entry points, recon notes, and any domain context,
tagged with `source="recon"`.

#### Scenario: Tasks cover class and scope

- **WHEN** task emission runs over the architecture
- **THEN** one recon-sourced `AgentTask` is emitted per (vulnerability class, scope) pair
  in scope
