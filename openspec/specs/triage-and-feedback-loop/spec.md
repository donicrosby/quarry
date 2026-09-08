# triage-and-feedback-loop Specification

## Purpose

An operator triages findings with a small fixed label set, and that feedback tunes future
scans - but only by adjusting priority, never by silencing a vulnerability class. Feedback
is only trusted once enough findings have been triaged, and it is kept distinct from the
intra-scan coverage loop.

## Requirements

### Requirement: Fixed triage label set

Findings SHALL be triaged with exactly one of `tp`, `fp`, `dup`, or `oos`, stored on the
finding and logged as a workflow event.

#### Scenario: Triage label is recorded

- **WHEN** an operator labels a finding
- **THEN** the label is stored on the finding and emitted as an event

### Requirement: Feedback modulates priority, never eliminates a class

Cross-run feedback SHALL adjust recon task priority and scope hints only. It SHALL NOT
eliminate a vulnerability class; a code-enforced floor SHALL keep at least a minimum
number of tasks per class per run.

#### Scenario: A class is never zeroed out

- **WHEN** feedback would drive a class's task count to zero
- **THEN** the per-class floor still emits tasks for that class

### Requirement: Feedback is trusted only above a triage threshold

Feedback SHALL be used only from runs with a sufficient number of triaged findings, so a
thinly triaged run does not skew future scans.

#### Scenario: Under-triaged run is not used as feedback

- **WHEN** a run has fewer than the minimum triaged findings
- **THEN** its feedback is not applied to future scans

### Requirement: Distinct from the intra-scan loop

Cross-run triage feedback SHALL be distinct from the intra-scan reachability/gapfill loop;
feedback derived from human triage SHALL be treated as untrusted context into recon.

#### Scenario: Triage feedback enters recon as context

- **WHEN** prior-run feedback is available
- **THEN** it is supplied to recon as untrusted context, not as a pipeline control
