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
