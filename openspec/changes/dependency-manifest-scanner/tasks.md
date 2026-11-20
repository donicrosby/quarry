# Tasks: dependency-manifest-scanner

## 1. Spec delta
- [x] 1.1 Add spec delta under `specs/dependency-manifest-scanning/spec.md` with 8 requirements and 16 scenarios
- [x] 1.2 `npx openspec validate dependency-manifest-scanner --strict` passes

## 2. Schema
- [ ] 2.1 Add `SUPPLY_CHAIN = "supply_chain"` to `VulnerabilityClass` enum in `src/quarry/schemas.py` (RED: test that `VulnerabilityClass("supply_chain")` succeeds)
- [ ] 2.2 Add `typosquat_patterns: list[str]` config key with default empty list to `quarry.config` (RED: test that default is empty)

## 3. Manifest parsers (no model calls)
- [ ] 3.1 `parse_requirements_txt(path) -> list[Dependency]` — parse pip-style version specifiers, detect unpinned and git/URL sources (RED: test with `requests>=2.0` and `git+https://...`)
- [ ] 3.2 `parse_pyproject_toml(path) -> list[Dependency]` — parse `[project] dependencies` and `[tool.poetry.dependencies]`, detect unpinned and git/URL sources (RED: test with `flask = "*"` and git dep)
- [ ] 3.3 `parse_package_json(path) -> list[Dependency]` — parse `dependencies`/`devDependencies`, detect git/URL sources, extract `scripts` block (RED: test with `"dep": "git+..."` and postinstall script)
- [ ] 3.4 `parse_cargo_toml(path) -> list[Dependency]` — parse `[dependencies]` table, detect git sources and unpinned versions (RED: test with `dep = { git = "..." }` and `dep = "*"`)
- [ ] 3.5 `parse_go_mod(path) -> list[Dependency]` — parse `require` block, resolve `replace` directives so replaced sources keep their source kind, and detect unpinned versions and git/URL sources (RED: test with unpinned version and a git replace)

## 4. Risk checks (deterministic, per-dependency)
- [ ] 4.1 `check_unpinned_version(dep) -> CandidateFinding | None` — flag lower-bound-only (`>=`, `>`), wildcard, `latest`, absent version with severity HIGH (RED→GREEN)
- [ ] 4.2 `check_git_url_dep(dep) -> CandidateFinding | None` — flag git+https, git+ssh, direct URL sources with severity HIGH (RED→GREEN)
- [ ] 4.3 `check_typosquat(dep, patterns) -> CandidateFinding | None` — match dep name against configurable pattern list, severity MEDIUM; no-op when patterns is empty (RED→GREEN)
- [ ] 4.4 `check_npm_install_scripts(dep, scripts) -> CandidateFinding | None` — flag preinstall/postinstall presence in npm scripts with severity MEDIUM (RED→GREEN)
- [ ] 4.5 `check_curl_pipe_sh(scripts) -> CandidateFinding | None` — detect `curl|sh` and `wget|sh` patterns in script values with severity CRITICAL (RED→GREEN)

## 5. Activity wiring
- [ ] 5.1 Create `src/quarry_activities/dependency_risk.py` with `@activity.defn(name="dependency-risk-scanner")` entry point (auto-discovered via `discover_activities()`)
- [ ] 5.2 Activity accepts `repo_root: Path | str` and `config_json: str | None` (for typosquat patterns), returns `list[CandidateFinding]`
- [ ] 5.3 Wire activity into the workflow as a pre-recon activity dispatched within the existing stage sequence (after clone/snapshot, before `recon-orchestrator`); no new canonical stage — `COMPLETED_STAGE_ORDER` stays as pinned by scan-orchestration

## 6. Verification
- [ ] 6.1 Unit tests green for all 5 parsers, all 5 risk checks, and activity wiring (ruff/pyright/pytest)
- [ ] 6.2 Golden-file test: fixture repo with `requests>=2.0` (unpinned → HIGH), a git+https dep with no version specifier (unpinned HIGH + git/URL HIGH), and a package.json postinstall script (MEDIUM) produces exactly 4 CandidateFindings with correct severities
- [ ] 6.3 Empty-repo test: scanner on a repo with no manifest files returns empty list (not an error)
- [ ] 6.4 Determinism test: two consecutive runs on identical manifests produce identical findings
- [ ] 6.5 Guard test: with model-client construction and network calls patched to raise, the scanner still completes and returns findings (covers the no-model and no-network SHALLs)

## 7. Landing
- [ ] 7.1 Conventional commit, push, CI green
- [ ] 7.2 `openspec archive dependency-manifest-scanner --yes`