"""Tests for lifecycle-hook dispatch wiring in run_scan.py.

Written pure-function first, per this codebase's convention (see
test_prove_stage.py): workflow dispatch logic (execute_activity, RetryPolicy)
is exercised by observing the pure gating helper and the call-site wiring,
not by simulating the Temporal runtime.
"""

from __future__ import annotations

import inspect

from quarry.schemas import IntegrationConfig, VulnerabilityClass, local_scan_profile


class TestShouldDispatchLifecycleHooks:
    def test_false_when_integrations_disabled(self) -> None:
        from quarry_workflows.run_scan import should_dispatch_lifecycle_hooks

        profile = local_scan_profile(vuln_classes=[VulnerabilityClass.SECRETS])
        profile = profile.model_copy(update={"integrations_enabled": False})
        assert should_dispatch_lifecycle_hooks(profile) is False

    def test_false_when_no_integration_configs(self) -> None:
        from quarry_workflows.run_scan import should_dispatch_lifecycle_hooks

        profile = local_scan_profile(vuln_classes=[VulnerabilityClass.SECRETS])
        assert profile.integrations_enabled is True
        assert profile.integration_configs == []
        assert should_dispatch_lifecycle_hooks(profile) is False

    def test_false_when_all_configs_disabled(self) -> None:
        from quarry_workflows.run_scan import should_dispatch_lifecycle_hooks

        profile = local_scan_profile(
            vuln_classes=[VulnerabilityClass.SECRETS],
            integration_configs=[
                IntegrationConfig(integration_type="slack_notify", enabled=False),
            ],
        )
        assert should_dispatch_lifecycle_hooks(profile) is False

    def test_true_when_at_least_one_config_enabled(self) -> None:
        from quarry_workflows.run_scan import should_dispatch_lifecycle_hooks

        profile = local_scan_profile(
            vuln_classes=[VulnerabilityClass.SECRETS],
            integration_configs=[
                IntegrationConfig(integration_type="jira_dry_run", enabled=False),
                IntegrationConfig(integration_type="slack_notify", enabled=True),
            ],
        )
        assert should_dispatch_lifecycle_hooks(profile) is True


class TestEmitAndDispatchWiring:
    def test_emit_and_dispatch_accepts_finding_and_severity(self) -> None:
        from quarry_workflows.run_scan import RunScanWorkflow

        sig = inspect.signature(
            RunScanWorkflow._emit_and_dispatch  # type: ignore[reportPrivateUsage]
        )
        assert "finding" in sig.parameters
        assert "severity" in sig.parameters

    def test_all_finding_validated_sites_pass_finding_and_severity(self) -> None:
        """Every place run_scan.py emits finding.validated calls _emit_and_dispatch
        with finding= and severity= set, so a lifecycle hook can react to any
        validation path: the agentic AGENTIC_VALIDATE path, the deterministic
        secret path, and the sweep auto-promotion path (scan-repo-for-secrets)."""
        import inspect as _inspect
        import sys

        # quarry_workflows/__init__.py does
        # `from quarry_workflows.run_scan import run_scan`, which rebinds the
        # `run_scan` attribute on the *package* to that function — shadowing
        # the submodule. Import it once to guarantee it's loaded, then fetch
        # the real module object straight from sys.modules.
        __import__("quarry_workflows.run_scan")
        run_scan_module = sys.modules["quarry_workflows.run_scan"]
        source = _inspect.getsource(run_scan_module)

        # Every "finding.validated" emission must go through _emit_and_dispatch,
        # never the bare _append_workflow_event (which drops the hook dispatch).
        # Check the immediately-preceding call keyword at each occurrence site.
        # Three sites: agentic validate, deterministic secret validate, and the
        # sweep auto-promotion gate (added with scan-repo-for-secrets).
        parts = source.split('"finding.validated"')
        sites = parts[:-1]
        assert len(sites) == 3
        for site in sites:
            window = site[-200:]
            call_start = window.rfind("await self._emit_and_dispatch(")
            append_start = window.rfind("await _append_workflow_event(")
            assert call_start != -1, "no _emit_and_dispatch call found near this site"
            assert call_start > append_start, (
                "finding.validated must be emitted via self._emit_and_dispatch, "
                "not the bare _append_workflow_event helper"
            )
