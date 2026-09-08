## ADDED Requirements

### Requirement: Lifecycle-hook plugin protocol
The system SHALL define a `LifecycleHookPlugin` protocol extending `Plugin` with an `events`
attribute (a set of subscribed lifecycle event-type strings) and a `handle(event, ctx)` method
that returns an `IntegrationRun` or `None`.

#### Scenario: Object satisfies the LifecycleHookPlugin protocol
- **WHEN** an object defines `plugin_type=lifecycle_hook`, `events`, and `handle(event, ctx)`
- **THEN** `isinstance(object, LifecycleHookPlugin)` returns `True`

### Requirement: Event-type subscription filtering
The dispatch mechanism SHALL invoke only those lifecycle hooks whose `events` set contains the
dispatched event's type. Hooks not subscribed to an event type SHALL NOT be invoked for it.

#### Scenario: Subscribed hook is invoked
- **WHEN** a `finding.validated` event is dispatched and a hook subscribes to `{"finding.validated"}`
- **THEN** that hook's `handle()` is called with the event

#### Scenario: Unsubscribed hook is not invoked
- **WHEN** a `finding.validated` event is dispatched and a hook subscribes only to
  `{"scan.completed"}`
- **THEN** that hook's `handle()` is not called

### Requirement: Severity-threshold filtering
Each configured integration SHALL specify a `severity_threshold`. The dispatch mechanism SHALL
invoke a subscribed hook for a finding-carrying event only when the finding's severity meets or
exceeds that hook's configured threshold.

#### Scenario: Finding below threshold is not delivered
- **WHEN** a hook's `severity_threshold` is `critical` and a `finding.validated` event carries a
  `high`-severity finding
- **THEN** the hook is not invoked for that event

#### Scenario: Finding at or above threshold is delivered
- **WHEN** a hook's `severity_threshold` is `critical` and a `finding.validated` event carries a
  `critical`-severity finding
- **THEN** the hook is invoked for that event

### Requirement: Idempotent delivery
Each hook delivery SHALL be keyed by a stable idempotency key derived from the scan ID, the
hook/sink name, and the finding fingerprint. The dispatch mechanism SHALL NOT re-invoke delivery
for a key already recorded as delivered within the scan.

#### Scenario: Repeated dispatch for the same finding does not duplicate delivery
- **WHEN** dispatch runs twice for the same scan, hook, and finding fingerprint, and the first
  run's idempotency key is already recorded as delivered
- **THEN** the second run skips delivery for that key and does not invoke the hook's external
  side effect again

### Requirement: Workflow dispatch at finding validation
The scan workflow SHALL dispatch the lifecycle-hook mechanism when a finding transitions to
`finding.validated`, passing the finding and its severity, but only when the scan profile has
integrations enabled.

#### Scenario: Dispatch occurs when integrations are enabled
- **WHEN** a finding is validated during a scan with `integrations_enabled=True`
- **THEN** the workflow schedules lifecycle-hook dispatch for the `finding.validated` event and
  persists any resulting `IntegrationRun` records

#### Scenario: No dispatch when integrations are disabled
- **WHEN** a finding is validated during a scan with `integrations_enabled=False`
- **THEN** the workflow does not schedule lifecycle-hook dispatch

### Requirement: Integration configuration schema
The system SHALL support an `IntegrationConfig` per integration, specifying whether it is
enabled, whether it runs in dry-run mode, its severity threshold, and an optional secret
reference. `IntegrationConfig` SHALL reject a `secret_ref` that appears to contain an inline
credential rather than an environment-variable name.

#### Scenario: Config with inline-looking secret is rejected
- **WHEN** an `IntegrationConfig.secret_ref.env` value looks like an inline credential (e.g.
  contains a token-like literal rather than an environment variable name)
- **THEN** constructing the `IntegrationConfig` raises a validation error

### Requirement: Integration configuration authored in quarry.toml
The system SHALL support defining `IntegrationConfig` entries in `quarry.toml` under
`[integrations.<name>]` tables, loaded into `ScanProfile.integration_configs` at scan-profile
construction time. Secret-shaped fields in these tables SHALL be specified using the
`${secret:ENV_VAR_NAME}` template syntax, which resolves to a `SecretRef` referencing that
environment variable. A secret-shaped field containing a literal value instead of this template
syntax SHALL be rejected at load time.

#### Scenario: quarry.toml secret template resolves to a SecretRef
- **WHEN** a `quarry.toml` `[integrations.slack_notify]` table sets a secret-shaped field to
  `"${secret:QUARRY_SECRET_SLACK_WEBHOOK}"`
- **THEN** the loaded `IntegrationConfig.secret_ref` is `SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK")`

#### Scenario: Literal secret value in quarry.toml is rejected
- **WHEN** a `quarry.toml` `[integrations.<name>]` table sets a secret-shaped field to a literal
  string that is not in `${secret:ENV_VAR_NAME}` form
- **THEN** loading `quarry.toml` raises a configuration error naming the expected
  `${secret:ENV_VAR_NAME}` syntax

### Requirement: Dry-run delivery by default
A lifecycle hook that delivers to an external system SHALL default to dry-run behavior: it
SHALL record what would have been sent (e.g. as an artifact) and SHALL NOT make a real network
call, unless its `IntegrationConfig` is explicitly enabled with `dry_run=False` and a resolvable
secret reference.

#### Scenario: Dry-run produces no network call
- **WHEN** a hook's `IntegrationConfig` has `dry_run=True` (or is unset)
- **THEN** `handle()` returns an `IntegrationRun` with dry-run status and makes no outbound
  network request

#### Scenario: Real delivery requires explicit enablement and a resolvable secret
- **WHEN** a hook's `IntegrationConfig` has `enabled=True`, `dry_run=False`, and a `secret_ref`
  that resolves successfully
- **THEN** `handle()` performs the real external delivery

### Requirement: Redaction before external egress
Any finding-derived text included in a lifecycle-hook delivery SHALL be passed through the
system's redaction/scrubbing mechanism before being sent to an external system.

#### Scenario: Sensitive content is scrubbed before delivery
- **WHEN** a finding's associated evidence contains a value matching a redaction pattern
- **THEN** the outbound delivery payload does not contain that value in unredacted form

### Requirement: Slack notification reference hook
The system SHALL provide a reference lifecycle-hook plugin (`slack_notify`) that subscribes to
`finding.validated` and, when enabled for real delivery, posts a notification to a configured
Slack webhook URL resolved from a secret reference.

#### Scenario: Real Slack delivery on a qualifying critical finding
- **WHEN** a `finding.validated` event carries a `critical`-severity finding and `slack_notify`
  is configured with `enabled=True`, `dry_run=False`, a resolvable webhook secret, and a
  `severity_threshold` of `critical` or below
- **THEN** the plugin posts the scrubbed notification to the webhook URL and returns an
  `IntegrationRun` recording successful delivery

#### Scenario: Delivery failure is recorded, not raised
- **WHEN** the outbound webhook request fails (network error or non-success response)
- **THEN** `handle()` returns an `IntegrationRun` recording the failure and does not raise an
  exception out of the dispatch mechanism

### Requirement: No external side effects during benchmark runs
A benchmark-configured scan SHALL run with integrations disabled, enforced by the system, such
that no lifecycle hook delivers externally during a benchmark run regardless of any
otherwise-active integration configuration.

#### Scenario: Benchmark scan delivers no notifications
- **WHEN** a scan is constructed via the benchmark profile path
- **THEN** the resulting `ScanProfile.integrations_enabled` is `False` and no lifecycle-hook
  dispatch occurs during that scan
