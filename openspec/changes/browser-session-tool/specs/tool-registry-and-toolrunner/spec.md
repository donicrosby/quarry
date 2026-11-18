## MODIFIED Requirements

### Requirement: Network egress is host- and scope-guarded

For network tools (http_request and browser_session) the runner SHALL enforce
the allowed-hosts guard fail-closed (an empty allowlist blocks all requests) and
the scope-exclusion guard, refusing out-of-scope requests before egress.
`browser_session` SHALL join `_DYNAMIC_TOOLS` so scope-exclusion checks apply.

#### Scenario: Empty allowlist blocks all requests

- **WHEN** allowed hosts is configured but empty
- **THEN** every network request is refused

#### Scenario: Excluded target is refused

- **WHEN** a network request targets a scope-excluded host or path
- **THEN** the request is refused before egress

#### Scenario: browser-session-is-gated-by-allowed-hosts

- **WHEN** `browser_session` is dispatched with a URL outside `allowed_hosts`
- **THEN** `_check_allowed_hosts` returns a denial reason and the call is
  refused

#### Scenario: browser-session-is-gated-by-scope-exclusions

- **WHEN** `browser_session` targets a scope-excluded host
- **THEN** the scope-exclusion guard refuses the call with a `denied_reason`