## ADDED Requirements

### Requirement: Http request tool exposes forging fields

The http_request tool input_schema SHALL expose multipart_fields, follow_redirects, and cookies fields so that every authorized role (dynamic_validate, prove, live_recon, exploit) can forge multipart requests, control redirect-following, and inject per-request cookies through the guarded network path.

#### Scenario: schema-exposes-multipart-fields

- **WHEN** an agent in an authorized role reads the http_request tool description
- **THEN** the input_schema includes multipart_fields as an optional array of objects with name, value, filename, and content_type properties

#### Scenario: schema-exposes-follow-redirects

- **WHEN** an agent in an authorized role reads the http_request tool description
- **THEN** the input_schema includes follow_redirects as an optional boolean defaulting to false

#### Scenario: schema-exposes-cookies

- **WHEN** an agent in an authorized role reads the http_request tool description
- **THEN** the input_schema includes cookies as an optional string-to-string mapping