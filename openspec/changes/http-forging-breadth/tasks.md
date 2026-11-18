# Tasks: http-forging-breadth

## 1. Model changes
- [ ] 1.1 Add `multipart_fields` field to `HttpRequestSpec` (`src/quarry/schemas.py:1403`): `list[MultipartFieldSpec] | None`, where `MultipartFieldSpec` is a new Pydantic model with `name: str`, `value: str`, `filename: str | None`, `content_type: str | None`
- [ ] 1.2 Add `follow_redirects` field to `HttpRequestSpec`: `bool` defaulting to `False`
- [ ] 1.3 Add `cookies` field to `HttpRequestSpec`: `dict[str, str]` defaulting to empty
- [ ] 1.4 Schema-level validation: warn (not error) when both `multipart_fields` (non-empty) and `body` (non-None) are supplied

## 2. Tool schema
- [ ] 2.1 Update `_HttpRequestTool.input_schema` (`src/quarry_tools/http_tool.py:33`) to expose `multipart_fields`, `follow_redirects`, `cookies`
- [ ] 2.2 Update `_HttpRequestTool.run()` dispatch payload to pass through the new fields

## 3. Activity changes
- [ ] 3.1 In `http_request_activity` (`src/quarry_activities/dynamic_http.py:80`): when `multipart_fields` is non-empty, construct an `httpx` multipart request via `client.build_request(files=...)` or equivalent, ignoring `body`
- [ ] 3.2 Implement redirect-following with per-hop host re-validation against `allowed_hosts`: use an httpx event-hook or manual redirect loop so every hop's resolved host is checked before the hop is issued; a non-allowlisted host aborts the chain (capture the 3xx as the final response or raise a typed scope error). Strip Authorization and Cookie headers when the redirect target is a different host.
- [ ] 3.3 Inject `cookies` dict as `Cookie` header entries on the outbound request
- [ ] 3.4 Extend `_redact_headers` (`src/quarry_artifacts/http_utils.py:35`) to redact Cookie header values in stored request artifacts. Also register cookie values with the per-run `Scrubber` for response-body and prompt-context redaction.

## 4. Tests
- [ ] 4.1 Unit: `test_multipart_fields_produces_form_data` — verify multipart construction
- [ ] 4.2 Unit: `test_multipart_ignores_body_when_populated` — mutual exclusion
- [ ] 4.3 Unit: `test_follow_redirects_false_captures_3xx` — no redirect
- [ ] 4.4 Unit: `test_follow_redirects_true_follows` — follows one redirect to an allowlisted host
- [ ] 4.5 Unit: `test_follow_redirects_max_hops_raises` — exceeds hard limit
- [ ] 4.6 Unit: `test_redirect_to_non_allowlisted_host_refused` — redirect to non-allowlisted host captures 3xx
- [ ] 4.7 Unit: `test_cross_host_redirect_strips_sensitive_headers` — Authorization and Cookie headers stripped on cross-host redirect
- [ ] 4.8 Unit: `test_cookies_injected` — cookies appear on request
- [ ] 4.9 Unit: `test_cookies_redacted_from_capture` — cookie values not in artifact
- [ ] 4.10 Unit: `test_tool_schema_exposes_new_fields` — verify input_schema shape
- [ ] 4.11 Golden: file upload probe on `vulnerable-fastapi` end-to-end (multipart POST, fetch result)
- [ ] 4.12 Regression: all existing `HttpRequestSpec` consumers (dynamic validate, prove, exploit) pass unchanged
- [ ] 4.13 Unit: `test_cookies_empty_no_header_added` — empty/absent cookies adds no Cookie header beyond what the credential resolver injects

## 5. Gates
- [ ] 5.1 `openspec validate http-forging-breadth --strict` clean
- [ ] 5.2 Ruff / pyright strict clean
- [ ] 5.3 Full unit + integration + golden test suite green
- [ ] 5.4 Conventional commit, push branch, CI green