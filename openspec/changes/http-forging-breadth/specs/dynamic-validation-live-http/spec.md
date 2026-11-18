## ADDED Requirements

### Requirement: Multipart request body support

HttpRequestSpec SHALL accept an optional multipart_fields list whose entries carry name, value, filename, and content_type. When multipart_fields is non-empty, the http_request_activity SHALL send a multipart/form-data request and SHALL ignore the raw body field.

#### Scenario: multipart-fields-populated-sends-form-data

- **WHEN** HttpRequestSpec carries one or more multipart_fields entries
- **THEN** the http_request_activity constructs a multipart/form-data request with each field as a part, using the part's filename and content_type when present

#### Scenario: multipart-fields-empty-sends-raw-body

- **WHEN** HttpRequestSpec carries an empty or absent multipart_fields list
- **THEN** the activity falls back to the raw body field for non-multipart requests with no change to existing behavior

#### Scenario: multipart-and-body-mutually-exclusive

- **WHEN** both multipart_fields (non-empty) and body are supplied
- **THEN** the activity sends only the multipart payload and ignores body; validation at the schema boundary SHALL warn when both are populated

### Requirement: Redirect-following control

HttpRequestSpec SHALL accept an optional follow_redirects boolean defaulting to false. When true, the activity SHALL follow redirects up to 10 hops with per-hop host re-validation against allowed_hosts fail-closed; a hop to a non-allowlisted host SHALL NOT be followed. When false, the activity SHALL NOT follow redirects. Authorization and Cookie headers SHALL NOT be forwarded to a different host on a followed hop.

#### Scenario: follow-redirects-false-does-not-follow

- **WHEN** follow_redirects is false or absent and the target responds with a 3xx status
- **THEN** the activity captures the redirect response as-is without following it

#### Scenario: follow-redirects-true-follows-redirect

- **WHEN** follow_redirects is true and the target responds with a redirect
- **THEN** the activity follows the redirect and captures the final response

#### Scenario: follow-redirects-max-hops-limited

- **WHEN** follow_redirects is true and a redirect chain exceeds 10 hops
- **THEN** the activity stops following and raises a TooManyRedirects error

#### Scenario: redirect-to-non-allowlisted-host-refused

- **WHEN** follow_redirects is true and a redirect target host is not in the allowed_hosts list
- **THEN** the redirect is not followed and the 3xx response is captured as the final response

#### Scenario: cross-host-redirect-strips-sensitive-headers

- **WHEN** follow_redirects is true and a redirect target is a different host than the origin
- **THEN** Authorization and Cookie headers are stripped from the followed request

### Requirement: Per-request cookie injection

HttpRequestSpec SHALL accept an optional cookies dict[str, str]. When non-empty, the http_request_activity SHALL inject each entry as a Cookie header on the outbound request. Cookie values SHALL be redacted from stored request artifacts and SHALL NOT re-enter any prompt.

#### Scenario: cookies-injected-into-request

- **WHEN** HttpRequestSpec carries a non-empty cookies dict
- **THEN** each entry is sent as part of the Cookie header on the outbound request

#### Scenario: cookies-empty-no-header-added

- **WHEN** cookies is empty or absent
- **THEN** no Cookie header is added beyond what the credential resolver injects

#### Scenario: cookie-values-redacted-from-capture

- **WHEN** a request with cookies is captured as an artifact
- **THEN** cookie values are redacted from the stored request artifact and never appear in prompt context