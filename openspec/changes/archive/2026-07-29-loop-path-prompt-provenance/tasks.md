## 1. PromptProvenance carrier (TDD: red → green)

- [x] 1.1 Write `tests/unit/test_prompt_provenance.py` for a `PromptProvenance.from_rendered(rendered)` constructor: it copies `template_sha256`, `part_hashes`, `evidence_hashes`, and template id/version from a `RenderedPrompt`.
- [x] 1.2 Add an immutable `PromptProvenance` (dataclass or frozen pydantic model) to `src/quarry_models/types.py` with `template_id`, `template_version`, `template_sha256`, `part_hashes: dict[str, str]`, `evidence_hashes: list[str]`, plus a `from_rendered` classmethod that accepts a `RenderedPrompt`-shaped object (typed structurally to avoid importing `quarry_prompts`).
- [x] 1.3 Run 1.1 to green; `ruff format`/`ruff check`.

## 2. Loop stamps provenance + real scan_id (TDD)

- [x] 2.1 Write a loop test: `run_agent_loop(..., prompt_provenance=<bundle>, scan_id="scan-x")` produces invocations whose `template_sha256`/`system_prompt_hash`/`evidence_hashes` match the bundle, `user_prompt_hash == sha256(initial_user_message)`, and `scan_id == "scan-x"`; and that omitting `prompt_provenance` leaves per-part hashes empty (backward compat) and `scan_id` defaults to `"loop"`.
- [x] 2.2 Add `prompt_provenance: PromptProvenance | None = None` to `run_agent_loop` (`src/quarry_models/loop.py`).
- [x] 2.3 In the per-turn request construction (`loop.py:314-323`), set `scan_id` from the `scan_id` param (fallback `"loop"`), and when `prompt_provenance` is present set `template_sha256`, `system_prompt_hash` (`part_hashes["system"]`), `developer_prompt_hash` (`part_hashes.get("developer")`), `user_prompt_hash` (`sha256(initial_user_message)`), and `evidence_hashes` on the request. Also set `prompt_template_id`/`prompt_template_version` provenance so the invocation records the template identity.
- [x] 2.4 Run 2.1 to green.

## 3. Wire the seven activities (TDD per representative activity)

- [x] 3.1 Write a hunt-activity test asserting the persisted invocations carry non-empty `template_sha256`/`system_prompt_hash` and the real `task.scan_id` (mock client, in-scope `RenderedPrompt`).
- [x] 3.2 In each of the seven model activities (`hunt`, `validate`, `gapfill`, `dedup`, `prove`, `tracer`, `recon_subsystem`), build `PromptProvenance.from_rendered(rendered)` and pass it plus the real `scan_id` into `run_agent_loop`.
- [x] 3.3 Run 3.1 to green.

## 4. Verification and full-suite gate

- [x] 4.1 Add/extend a test that `verify_invocation` passes for a loop-sourced invocation using the rendered prompt's expected system hash and template sha (proves real-scan verifiability).
- [x] 4.2 Confirm no existing loop/activity test regresses (empty-hash callers still pass).
- [x] 4.3 Run the full suite (`task test`) and `task prompt-lint`; both must pass.
