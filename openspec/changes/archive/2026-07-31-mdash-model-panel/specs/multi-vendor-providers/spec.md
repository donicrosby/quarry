## ADDED Requirements

### Requirement: Bedrock provider is supported

The model factory SHALL support AWS Bedrock as a provider so a panel can run models
across at least two vendors. Selecting a Bedrock model SHALL route through the provider
adapter with AWS authentication, without changes to calling code beyond panel config.

#### Scenario: A Bedrock-configured role runs

- **WHEN** a role/tier is configured with a Bedrock model
- **THEN** its calls dispatch to Bedrock and record `provider = "bedrock"` (or the
  canonical Bedrock provider id) on the `ModelInvocation`

### Requirement: Cross-vendor panels actually run across vendors

A panel that assigns different vendors to different roles/tiers SHALL execute each on
its configured vendor, so `cross_vendor_disagreement` reflects genuinely different
vendors rather than two models from one provider.

#### Scenario: Two vendors in one scan

- **WHEN** a panel assigns vendor A to the reasoner tier and vendor B to the debater
  tier
- **THEN** each tier's invocations record its respective vendor

### Requirement: vendor_allowlist is enforced fail-fast

When a scan configures a `vendor_allowlist`, the system SHALL validate every panel
model against it before any model call, and SHALL fail the scan up front if any
configured model uses a vendor outside the allowlist — activating the field that is
currently declared but never read.

#### Scenario: Disallowed vendor is rejected before any call

- **WHEN** a panel includes a model whose vendor is not in `vendor_allowlist`
- **THEN** the scan fails at launch, before any model call, naming the offending vendor

#### Scenario: Empty allowlist means unrestricted

- **WHEN** `vendor_allowlist` is empty
- **THEN** no vendor restriction is applied (backward compatible)
