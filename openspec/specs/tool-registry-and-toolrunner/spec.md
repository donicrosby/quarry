# tool-registry-and-toolrunner Specification

## Purpose

Agents act on the world only through a registry of typed tools, and every call passes
through `ToolRunner`, the single enforcement point for path, role, host, and scope
guards. This is the boundary that keeps a compromised or confused agent inside the
sandbox: the tool declares what it needs, the runner decides whether it is allowed, and
refused calls are recorded rather than silently dropped.

## Requirements

### Requirement: Typed tool registry with role allowlists

Tools SHALL be registered as `ToolSpec` entries declaring name, description, input schema,
and the roles permitted to call them. The registry SHALL comprise built-in tools plus
tools contributed by plugins.

#### Scenario: Tool declares its permitted roles

- **WHEN** a tool is registered
- **THEN** it declares an input schema and the set of roles allowed to invoke it

### Requirement: Role authorization is enforced

`ToolRunner` SHALL refuse a call whose invoking role is not in the tool's allowlist,
raising an unauthorized-tool error. Dynamic/network tools SHALL be callable only by the
roles authorized for live actions.

#### Scenario: Unauthorized role is refused

- **WHEN** a role not on a tool's allowlist attempts to call it
- **THEN** the runner refuses the call

### Requirement: Filesystem access is confined to the repository root

`ToolRunner` SHALL resolve tool paths against the repository root and SHALL refuse any
path that escapes it. Tools SHALL NOT write outside the repository root.

#### Scenario: Path escape is refused

- **WHEN** a tool input resolves to a path outside the repository root
- **THEN** the runner raises a tool-security error

### Requirement: Network egress is host- and scope-guarded

For network tools the runner SHALL enforce the allowed-hosts guard fail-closed (an empty
allowlist blocks all requests) and the scope-exclusion guard, refusing out-of-scope
requests before egress.

#### Scenario: Empty allowlist blocks all requests

- **WHEN** allowed hosts is configured but empty
- **THEN** every network request is refused

#### Scenario: Excluded target is refused

- **WHEN** a network request targets a scope-excluded host or path
- **THEN** the request is refused before egress

### Requirement: Refused calls are recorded

Every tool invocation, including refused ones, SHALL be recorded as a tool-call record;
refusals SHALL NOT be silently dropped. Timeouts SHALL be owned by the runner, not the
tool.

#### Scenario: Refusal is auditable

- **WHEN** the runner refuses a call
- **THEN** a record of the refused invocation and its reason is retained
