# Change: http-forging-breadth

## Why

`HttpRequestSpec` (`src/quarry/schemas.py:1403`) currently supports only raw-string body requests — no multipart/form-data, no redirect-following control, and no per-request cookie injection. This blocks the `file_upload` vulnerability class (already enumerated at `src/quarry/schemas.py:99`) from performing live dynamic validation: file upload probes require multipart encoding, and the agent cannot currently forge one.

The original ticket t_5e0509d8 (2026-09-10) scoped three additions. Reconcile against main @ b284af7: none of the three features have arrived in the intervening ~45 merges. `VulnerabilityClass.FILE_UPLOAD` was added anticipatorily, but the request-spec surface that would exercise it is still limited to `method, path, headers, body, auth_profile`.

## What Changes

- **HttpRequestSpec** gains three optional fields:
  - `multipart_fields`: list of `{name, value, filename, content_type}` for multipart/form-data requests. When non-empty, the activity sends multipart and ignores the raw `body` field.
  - `follow_redirects`: bool, default false. When true, the activity follows redirects up to a hard maximum of 10 hops.
  - `cookies`: dict[str, str] for per-request `Cookie` header injection.
- The `http_request` tool input_schema (`src/quarry_tools/http_tool.py:33-71`) exposes all three fields so every authorized role (`dynamic_validate`, `prove`, `live_recon`, `exploit`) can use them.
- The `http_request_activity` (`src/quarry_activities/dynamic_http.py:80`) handles multipart body construction, redirect-following, and cookie injection.

## Dropped from original ticket t_5e0509d8

- **General `content_type` field**: the original ticket notes "no content-type variants beyond a raw string." Multipart fields inherently set content-type to `multipart/form-data`, which is the only variant the `file_upload` class needs. A raw-body content-type override introduces content-type spoofing surface that needs its own threat model — deferred to a follow-up change.
- **Scope narrowed from five roles to the current four**: the ticket says "dynamic_validate and exploit roles," but the current tool allows `dynamic_validate, prove, live_recon, exploit` (`src/quarry_tools/http_tool.py:31`). We expand to the current four-role set.

## Impact

- **Specs**: `dynamic-validation-live-http` (3 ADDED requirements), `tool-registry-and-toolrunner` (1 ADDED requirement).
- **Code**: `src/quarry/schemas.py` (HttpRequestSpec fields), `src/quarry_tools/http_tool.py` (input_schema), `src/quarry_activities/dynamic_http.py` (multipart/redirect/cookie handling), `src/quarry_artifacts/http_utils.py` (_redact_headers Cookie redaction).
- **Tests**: new unit tests for multipart construction, redirect limits, cookie injection; golden tests for `file_upload` probe on `vulnerable-fastapi`.
- **Non-goals**: file upload evaluator logic (owned by per-class verdict evaluators, ADR-017); GraphQL body variants (W6); request sequencing primitives outside the exploit loop.