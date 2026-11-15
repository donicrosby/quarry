# Tasks: attacker-env-injection

- [ ] 1. Add conformance test verifying no `env`/`environment`/`env_vars` field exists in `run_in_sandbox` tool schema `properties`
- [ ] 2. Add conformance test verifying `additionalProperties: false` rejects unknown top-level keys for `run_in_sandbox`
- [ ] 3. Gate `env_profile` values other than `"none"` in `sandbox_tool.py` `run()` method until a resolution implementation is registered; return refused ToolCallRecord
- [ ] 4. Add unit test for step 3: `env_profile: "repo_readonly"` is refused; `env_profile: "none"` proceeds
- [ ] 5. Define `_REJECTED_ARG_PATTERNS` in `sandbox.py` — regex set covering `KEY=value` prefix, `-e`/`--env` flags, bare `env`/`printenv` args when command is `sh` or `python3`
- [ ] 6. Wire arg-pattern rejection into `LocalSubprocessSandbox._validate_command` (or a new `_validate_args` method) raising `ToolSecurityError`
- [ ] 7. Add unit tests for arg rejection: VAR=value, -e flag, --env flag, bare env, bare printenv rejected; plain -c, --help, positional args allowed
- [ ] 8. Add integration test: `sh -c "echo hello"` passes; `sh -c "MAL=1 echo hello"` is rejected
- [ ] 9. Implement `_redact_env_output(raw_stdout: str) -> str` in `sandbox.py` — when command is `"env"`, replace stdout with `"<N> environment variables present (redacted)"` where N is the line count
- [ ] 10. Wire `_redact_env_output` into `LocalSubprocessSandbox.run()` and `ContainerSandbox.run()` post-capture, pre-return
- [ ] 11. Add unit test for env-output redaction: `env` output with 3 lines → redacted count line; non-`env` command output passes through unchanged
- [ ] 12. Add integration test: running `env` in sandbox returns exit code 0 but stdout contains only the redaction line
- [ ] 13. Update `EnvProfile` docstring (schemas.py:1517-1525) to note that `REPO_READONLY` is deferred until resolution is implemented
- [ ] 14. Run full sandbox test suite (`pytest tests/unit/test_sandbox* tests/integration/test_local_sandbox* -v`), verify all pass
- [ ] 15. Run `npx openspec validate attacker-env-injection --strict`, verify clean
- [ ] 16. Commit on branch `spec/attacker-env-injection`; push if remote is available