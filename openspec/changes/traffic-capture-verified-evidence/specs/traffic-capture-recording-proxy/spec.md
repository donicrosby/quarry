## ADDED Requirements

### Requirement: Single MITM proxy funnel for all agent HTTP

"Agent HTTP" SHALL mean HTTP requests initiated by quarry tools under proxy env
injection. The only real surface today is `http_request` (`src/quarry_tools/http_tool.py`);
the browser worker (in-flight `spec/browser-worker-playwright`; "Status: planned") SHALL
also route through the proxy when landed. All agent HTTP SHALL be routed through a single
recording MITM proxy with no bypass. Infrastructure HTTP (model-provider, Temporal,
login-flow, NO_PROXY destinations) SHALL be excluded.

#### Scenario: http-request-is-proxied

- **WHEN** a hunter or recon agent dispatches an `http_request` to the target
- **THEN** the request and response transit the recording proxy and are captured

#### Scenario: browser-worker-is-proxied

- **WHEN** the browser worker (Status: planned; gated on `spec/browser-worker-playwright`)
  navigates or fetches a URL
- **THEN** the request and response transit the recording proxy and are captured

#### Scenario: no-proxy-excludes-infrastructure-traffic

- **WHEN** a worker container makes an HTTP request to a host listed in NO_PROXY
- **THEN** the request bypasses the proxy entirely and is not captured
- **THEN** excluded destinations include: model-provider hosts (LiteLLM endpoints),
  Temporal server, and login/auth endpoints

#### Scenario: direct-http-circumvents-proxy-is-blocked

- **WHEN** agent code attempts an HTTP request that bypasses the proxy without matching
  a NO_PROXY exclusion
- **THEN** the connection is refused at the network-policy layer (the network-policy
  refusal mechanism is owned by `openspec/changes/egress-policy-destination-sets`;
  note: that spec's authored scope is sandbox-tier only — ContainerSandbox IP
  pinning, K8sJobSandbox NetworkPolicy — and its destination sets do not include
  a worker-container agent-HTTP policy. This gap is deferred: task 10 records the
  reconciliation note and defers enforcement until the egress spec covers agent-HTTP)

### Requirement: Recording proxy runs as internal sidecar

The proxy SHALL run as an embedded sidecar container in the compose stack, listening on an
internal-network port only; the proxy port SHALL NOT be published to the host.

#### Scenario: proxy-not-published-to-host

- **WHEN** the compose stack starts
- **THEN** the proxy port is bound to an internal network address only, not published on the host

#### Scenario: proxy-env-injected-into-worker

- **WHEN** a worker container starts (quarry-control Temporal activity workers executing
  `http_request` dispatches, and browser workers when landed)
- **THEN** HTTP_PROXY and HTTPS_PROXY env vars point to the proxy's internal address;
  NO_PROXY excludes model-provider, Temporal server, and auth hosts

### Requirement: mitmproxy as the recording engine

The recording proxy SHALL use mitmproxy with a custom addon, chosen over a thin custom
recorder because mitmproxy provides mature TLS interception, HTTP/1.1 and HTTP/2 support,
and a Python-native addon API that avoids reimplementing CONNECT tunnelling and certificate
generation. (DESIGN DECISION: mitmproxy — ASSUMED that its addon API can drive
content-addressed storage and SQLite indexing without forking mitmproxy itself.)

#### Scenario: mitmproxy-addon-writes-content-addressed-blobs

- **WHEN** the addon's response hook fires for an exchange
- **THEN** the full request and response are serialized and written to a content-addressed file

#### Scenario: proxy-forwards-transparently

- **WHEN** an agent sends a request through the proxy
- **THEN** the proxy forwards it to the target and returns the unmodified response

### Requirement: Content-addressed capture with dedup normalization

Each captured exchange SHALL be stored as a blob whose filename is its SHA-256 digest;
exchanges SHALL be indexed by a normalized URL template where path segments matching
parameter patterns are replaced with placeholders so repeated pagination or
parameter-varying requests are recognized as the same template.

#### Scenario: url-template-normalization-artex-verified

- **WHEN** URL template normalization is applied to captured exchange URLs
- **THEN** path segments matching UUID, integer, base64-token, and ISO-date patterns
  are replaced with typed placeholders (`{uuid}`, `{id}`, `{token}`, `{date}`)
  and the normalized template is stored in the capture index `url_template` column
  (provenance: ARTEX traffic/traffic.go content-addressed capture design —
  VERIFIED against its SQLite index schema; ASSUMED pattern set is sufficient)

#### Scenario: url-template-normalized-for-dedup

- **WHEN** two requests differ only in a path segment that matches a parameter pattern
- **THEN** both are recorded under the same URL template

#### Scenario: identical-content-not-duplicated

- **WHEN** a captured exchange has the same SHA-256 as a previously stored blob
- **THEN** the blob file is not duplicated; the index adds a new row referencing the existing blob

#### Scenario: capture-index-is-queryable

- **WHEN** an operator or activity queries the capture index by URL template, status code, or
  time range
- **THEN** matching exchanges are returned with their blob references

### Requirement: Disposable capture store with host-scoped export

The raw capture store SHALL be disposable (safe to delete whole) and support host-scoped
export so a scan's traffic can be extracted for archival before the capture volume is
reclaimed. (VERIFIED: ARTEX traffic/archive.go ExportHosts — host-scoped snapshot export
with deduplicated blobs.)

#### Scenario: host-scoped-export-produces-portable-archive

- **WHEN** an export is requested for one target host
- **THEN** a portable archive is produced containing the host's exchanges and their blobs

#### Scenario: capture-store-can-be-reclaimed

- **WHEN** the capture store's disk usage exceeds a configured threshold
- **THEN** unreferenced capture blobs are deleted and the index rows are removed