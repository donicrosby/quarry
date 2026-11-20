## ADDED Requirements

### Requirement: Crawl activity builds a crawl-derived live attack map

A `crawl` activity SHALL fetch the authorized target's pages with `httpx` (no
JavaScript execution) and build a crawl-derived attack map of links, forms, and
script-bundle URLs. Traversal SHALL be breadth-first over same-host links,
starting from the configured seed paths and bounded by a maximum page count;
every discovered entry SHALL carry `source="crawl"`.

#### Scenario: crawl discovers links and forms

- **WHEN** the crawl activity runs against an authorized target whose seed page
  links to a second page and embeds a form
- **THEN** the returned attack map contains a `GET` entry for each discovered
  link and an entry for the form's method and action
- **AND** every crawl-derived entry carries `source="crawl"`

#### Scenario: same-host traversal is bounded

- **WHEN** the target links to more same-host pages than the configured maximum
- **THEN** the crawl stops at the maximum page count and records a truncation
  reason rather than continuing unboundedly

### Requirement: Crawl egress is host-guarded and scrubbed

Every crawl request SHALL be checked against `allowed_hosts` before any socket
is opened. An empty allowlist SHALL refuse all requests, and a host outside the
list SHALL be skipped without egress. Response bodies SHALL be size-capped and
passed through the run `Scrubber` before any extracted value is emitted, and
redirects to an off-scope host SHALL NOT be followed.

#### Scenario: off-scope host is never fetched

- **WHEN** a crawled page links to a host outside `allowed_hosts`
- **THEN** that link is not fetched and the refusal is recorded

#### Scenario: empty allowlist refuses all crawl egress

- **WHEN** the crawl activity runs with an empty `allowed_hosts`
- **THEN** no request is sent and the returned map is empty

#### Scenario: redactable tokens never reach the result raw

- **WHEN** a same-host redirect URL, a rendered DOM, a dedupe-appended
  parameter, a form input, or a recorded error string carries a value the run
  `Scrubber` redacts
- **THEN** every emitted field (fetched page URLs, form inputs, entry params,
  refusal records) carries the redacted placeholder, never the raw value

### Requirement: Form extraction records method, action, and inputs

The crawler SHALL extract every HTML form's method (defaulting to `GET` when
absent), action (resolved against the page URL), and the names of its `input`,
`select`, and `textarea` controls. The crawler SHALL NOT submit any form.

#### Scenario: form method, action, and inputs are extracted

- **WHEN** a crawled page contains `<form method="post" action="/login">` with
  `username` and `password` inputs
- **THEN** the crawl result records a form with method `POST`, action `/login`,
  and inputs `["username", "password"]`

### Requirement: Client-side routes are extracted from script bundles

The crawler SHALL fetch same-host script bundles referenced by crawled pages and
extract client-side route paths by recognizing React Router and Vue Router route
declarations and generic quoted absolute route literals. Extracted routes SHALL
be added to the attack map as `GET` entries with `source="crawl"`.

#### Scenario: SPA routes invisible in server source are found

- **WHEN** an example SPA serves a script bundle that declares routes absent
  from the target's server source
- **THEN** the crawler discovers those routes and adds them to the attack map

### Requirement: Optional browser-rendered DOM input for SPAs

The crawl activity SHALL accept caller-supplied rendered DOM keyed by URL so a
JavaScript-rendered SPA can be crawled when the server HTML exposes no links.
When a rendered page is supplied for a URL, the crawler SHALL extract from the
rendered DOM instead of the raw response body.

#### Scenario: rendered DOM is preferred when supplied

- **WHEN** the crawl activity is given a rendered DOM for a seed URL whose
  server HTML contains no links
- **THEN** the crawler extracts the links and routes from the rendered DOM
  rather than from the server response

### Requirement: A per-fetch transport failure does not fail the crawl

A transport failure on any single URL — connection refused, connection
aborted mid-response, read timeout, TLS mismatch — SHALL be caught per fetch,
recorded (an error string naming the failure class, and an attack-map entry
for the failed endpoint carrying it in its notes), and traversal SHALL
continue. Such a failure SHALL NOT fail the crawl activity.

#### Scenario: one dead link does not kill the crawl

- **WHEN** a crawled page links to an endpoint whose connection is refused or
  whose response is aborted mid-body
- **THEN** the crawl completes, the remaining pages are fetched and mapped,
  and the failed endpoint is recorded with its error class

### Requirement: Pathological bodies are refused before scrubbing

A fetched body — on the `httpx` path or the rendered-DOM path — whose longest
unbroken `[A-Za-z0-9_]` run exceeds the configured run limit, or whose summed
squared run lengths exceed the configured work budget, SHALL be refused with a
recorded reason and SHALL NOT be scrubbed, parsed, or emitted. (The shared
`Scrubber`'s assignment pattern is quadratic on separator-less runs —
pre-existing redaction-lane debt; this guard contains it crawl-side.)

#### Scenario: separator-less body is refused, not parsed

- **WHEN** an in-scope page serves a body dominated by unbroken alphanumeric
  runs (a separator-less blob, or many legal-length runs packed together)
- **THEN** the page is refused with a recorded reason, no value from it is
  parsed or emitted, and the crawl continues without wedging
