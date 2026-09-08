# release-and-oss-governance Specification

## Purpose

A public release must be safe, honest, and free of organization-specific baggage. This
capability defines the release gates: a one-command demo that needs no secrets, safe
defaults, honest claims, required governance files, no hardcoded secrets, and - explicitly
- no organization-specific names, URLs, policies, or private-repo assumptions in the public
tree.

## Requirements

### Requirement: One-command demo without secrets

A public release SHALL provide a demo runnable with one command that requires no real API
keys, hosted models, external services, or hidden setup.

#### Scenario: Demo runs offline

- **WHEN** the demo command runs on a clean checkout
- **THEN** it completes without real credentials or external services

### Requirement: Safe defaults and honest claims

The released defaults SHALL be safe (no live traffic, integrations off, no source upload),
and documentation SHALL NOT claim capabilities the code does not have.

#### Scenario: Docs match behavior

- **WHEN** the README describes a capability
- **THEN** the shipped code actually provides it

### Requirement: No secrets and no organization-specific content

The public tree SHALL contain no hardcoded secrets and no organization-specific names,
URLs, internal endpoints, private-repo layouts, or internal policies. Reference designs
SHALL be cited only generically.

#### Scenario: Organization-specific reference blocks release

- **WHEN** the public tree contains an organization-specific name, endpoint, or private-repo assumption
- **THEN** the release is blocked until it is removed

#### Scenario: No live-key-shaped literals

- **WHEN** an example value resembles a live credential
- **THEN** it is replaced with an obviously fake, labeled placeholder

### Requirement: Governance files present

A public release SHALL include the required governance files (license, security policy,
contributing guide, responsible-use and data-handling docs).

#### Scenario: Missing governance file blocks release

- **WHEN** a required governance file is absent
- **THEN** the release is blocked

### Requirement: Extensible without forking core

Internal or organization-specific use SHALL be supported through configuration, profiles,
and plugins, without forking or modifying the public core; running Quarry locally SHALL NOT
require any private companion repository.

#### Scenario: Local run needs no private repo

- **WHEN** an operator runs Quarry from the public tree
- **THEN** no private companion repository is required
