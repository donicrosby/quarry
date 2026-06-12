"""Command-line interface for Quarry."""

import asyncio
import signal
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import typer

from quarry.benchmark import compare, load_ground_truth
from quarry.config import QuarrySettings
from quarry.panel_config import resolve_auth, resolve_focus
from quarry.schemas import FinalFinding, ScanSummary, Target, VulnerabilityClass
from quarry_activities.clone import is_git_url
from quarry_activities.target import start_local_target, terminate_local_target
from quarry_client.client import QuarryClient

app = typer.Typer(help="Quarry local vulnerability research harness.")
scan_app = typer.Typer(help="Run scans.")
target_app = typer.Typer(help="Manage local targets.")
report_app = typer.Typer(help="Inspect reports.")
benchmark_app = typer.Typer(help="Run local benchmarks.")
provenance_app = typer.Typer(help="Prompt-provenance verification and GC retention.")
POLL_INTERVAL_SECONDS = 1.0
TERMINAL_SCAN_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED", "CANCELED"})

app.add_typer(scan_app, name="scan")
app.add_typer(target_app, name="target")
app.add_typer(report_app, name="report")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(provenance_app, name="provenance")


@scan_app.command("run")
def run_scan(
    repo: Annotated[str, typer.Option("--repo", help="Path to repository")],
    target: Annotated[str | None, typer.Option("--target", help="Target URL")] = None,
    focus: Annotated[
        str | None,
        typer.Option(
            "--focus",
            help="Comma-separated vulnerability classes to scan (e.g. ssrf,xss). "
            "Omit to scan all classes.",
        ),
    ] = None,
    async_mode: Annotated[
        bool,
        typer.Option("--async", help="Return immediately"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Stream agent events to stdout as the scan runs."),
    ] = False,
    dynamic_validation: Annotated[
        bool,
        typer.Option(
            "--dynamic-validation",
            help=(
                "Enable live HTTP validation against the target URL (ADR-017). "
                "Requires --target. CLI flag is the sole authority — "
                "--target alone does not enable live traffic."
            ),
        ),
    ] = False,
    live_prove: Annotated[
        bool,
        typer.Option(
            "--live-prove",
            help=(
                "Enable live HTTP proof-of-concept requests for NEEDS_PROOF findings (ADR-017). "
                "Requires --target and --dynamic-validation."
            ),
        ),
    ] = False,
    auth_config: Annotated[
        Path | None,
        typer.Option(
            "--auth-config",
            help="Path to an auth-profiles TOML file (ADR-018).",
        ),
    ] = None,
) -> None:
    if (dynamic_validation or live_prove) and target is None:
        typer.echo(
            "Error: --target is required when --dynamic-validation or --live-prove is set.",
            err=True,
        )
        raise typer.Exit(1)

    focus_classes: list[VulnerabilityClass] | None = None
    if focus is not None:
        tokens = [t.strip() for t in focus.split(",") if t.strip()]
        try:
            focus_classes = resolve_focus(cli_focus=tokens, config_focus=[])
        except ValueError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(1) from exc

    auth_profiles_json: str | None = None
    if auth_config is not None:
        _cli_target = _build_cli_target(target, repo)
        try:
            _profile_set = resolve_auth(auth_config, _cli_target)
        except (FileNotFoundError, OSError) as exc:
            typer.echo(f"Error: --auth-config: {exc}", err=True)
            raise typer.Exit(1) from exc
        except ValueError as exc:
            typer.echo(f"Error: --auth-config: {exc}", err=True)
            raise typer.Exit(1) from exc
        auth_profiles_json = _profile_set.model_dump_json()

    settings = QuarrySettings()
    try:
        lines = asyncio.run(
            _run_scan_command(
                settings,
                repo,
                target,
                async_mode,
                focus_classes,
                verbose,
                dynamic_validation_enabled=dynamic_validation,
                live_prove_enabled=live_prove,
                auth_profiles_json=auth_profiles_json,
            )
        )
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    _echo_lines(lines)


@scan_app.command("cancel")
def cancel_scan(scan_id: Annotated[str, typer.Argument(help="Scan ID to cancel")]) -> None:
    settings = QuarrySettings()
    try:
        result = asyncio.run(_cancel_scan_command(settings, scan_id))
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    _echo_key_values(result)


@scan_app.command("resume")
def scan_resume(scan_id: Annotated[str, typer.Argument(help="Scan ID to resume")]) -> None:
    """Resume a scan from its last checkpoint."""
    settings = QuarrySettings()
    try:
        result = asyncio.run(_resume_scan_command(settings, scan_id))
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    _echo_key_values(result)


@scan_app.command("rerun")
def scan_rerun(
    scan_id: Annotated[str, typer.Argument(help="Scan ID to rerun")],
    mode: Annotated[str, typer.Option(help="Rerun mode. Only 'replay' is supported.")] = "replay",
) -> None:
    """Re-render a scan's report from stored state (no scan or model calls)."""
    if mode != "replay":
        typer.echo(f"Unsupported rerun mode: {mode!r} (only 'replay' is supported)", err=True)
        raise typer.Exit(code=2)
    settings = QuarrySettings()
    try:
        result = asyncio.run(_replay_scan_command(settings, scan_id))
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    _echo_key_values(result)


@scan_app.command("list")
def list_scans() -> None:
    settings = QuarrySettings()
    try:
        scans = asyncio.run(_list_scans_command(settings))
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)

    if not scans:
        typer.echo("No scans found.")
        return

    typer.echo("scan_id\tstatus\trepo_path\treport")
    for scan in scans:
        report_path = scan.report_path or "-"
        typer.echo(f"{scan.scan_id}\t{scan.status}\t{scan.repo_path}\t{report_path}")


@scan_app.command("status")
def scan_status(scan_id: Annotated[str, typer.Argument(help="Scan ID to inspect")]) -> None:
    settings = QuarrySettings()
    try:
        result = asyncio.run(_scan_status_command(settings, scan_id))
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    _echo_key_values(result)


@scan_app.command("diff")
def scan_diff(
    repo: Annotated[str, typer.Option("--repo", help="Path to repository")],
    base: Annotated[str, typer.Option("--base", help="Base commit")],
    head: Annotated[str, typer.Option("--head", help="Head commit")],
) -> None:
    """Scan only the changes between two commits."""
    settings = QuarrySettings()
    try:
        result = asyncio.run(_scan_diff_command(settings, repo, base, head))
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    _echo_key_values(result)


async def _run_scan_command(
    settings: QuarrySettings,
    repo: str,
    target: str | None,
    async_mode: bool,
    focus_classes: list[VulnerabilityClass] | None = None,
    verbose: bool = False,
    dynamic_validation_enabled: bool = False,
    live_prove_enabled: bool = False,
    auth_profiles_json: str | None = None,
) -> list[str]:
    # A git URL (--repo https://… / git@… / ssh://…) is cloned by the workflow;
    # a local path is scanned in place.
    repo_url = repo if is_git_url(repo) else None
    async with QuarryClient(base_url=settings.server_url) as client:
        result = await client.start_scan(
            repo_path=repo,
            target_url=target,
            vuln_classes=focus_classes,
            repo_url=repo_url,
            dynamic_validation_enabled=dynamic_validation_enabled,
            live_prove_enabled=live_prove_enabled,
            auth_profiles_json=auth_profiles_json,
        )
        scan_id = result["scan_id"]
        if async_mode:
            return [scan_id]

        lines = [f"Scan {scan_id} started..."]
        last_event_id: str | None = None
        while True:
            if verbose:
                # Poll for new agent.* events and print them as structured log lines.
                events = await client.poll_events(
                    scan_id,
                    event_types=["agent.action_proposed", "agent.reasoning_rejected"],
                    after_id=last_event_id,
                )
                for event in events:
                    import json as _json

                    typer.echo(
                        _json.dumps(
                            {
                                "event": event.event_type,
                                "scan_id": event.scan_id,
                                "payload": event.payload,
                            },
                            sort_keys=True,
                        )
                    )
                    last_event_id = event.id

            status = await client.get_scan_status(scan_id)
            lines.extend(_format_key_values(status))
            if _is_terminal_status(status):
                lines.append(f"Scan {scan_id} completed.")
                return lines
            await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def _cancel_scan_command(settings: QuarrySettings, scan_id: str) -> dict[str, str]:
    async with QuarryClient(base_url=settings.server_url) as client:
        return await client.cancel_scan(scan_id)


async def _resume_scan_command(settings: QuarrySettings, scan_id: str) -> dict[str, str]:
    async with QuarryClient(base_url=settings.server_url) as client:
        return await client.resume_scan(scan_id)


async def _replay_scan_command(settings: QuarrySettings, scan_id: str) -> dict[str, str]:
    async with QuarryClient(base_url=settings.server_url) as client:
        return await client.replay_scan(scan_id)


async def _list_scans_command(settings: QuarrySettings) -> list[ScanSummary]:
    async with QuarryClient(base_url=settings.server_url) as client:
        return await client.list_scans()


async def _scan_status_command(settings: QuarrySettings, scan_id: str) -> dict[str, Any]:
    async with QuarryClient(base_url=settings.server_url) as client:
        return await client.get_scan_status(scan_id)


async def _scan_diff_command(
    settings: QuarrySettings,
    repo: str,
    base: str,
    head: str,
) -> dict[str, str]:
    async with QuarryClient(base_url=settings.server_url) as client:
        return await client.start_diff_scan(repo_path=repo, base_commit=base, head_commit=head)


def _is_terminal_status(status: Mapping[str, Any]) -> bool:
    status_value = status.get("stage") or status.get("status")
    if status_value is None:
        return False
    return str(status_value).upper() in TERMINAL_SCAN_STATES


def _format_key_values(values: Mapping[str, object]) -> list[str]:
    return [f"{key}={value}" for key, value in values.items()]


def _echo_key_values(values: Mapping[str, object]) -> None:
    _echo_lines(_format_key_values(values))


def _echo_lines(lines: list[str]) -> None:
    for line in lines:
        typer.echo(line)


def _exit_server_not_reachable(settings: QuarrySettings) -> NoReturn:
    typer.echo(f"Error: Quarry server not reachable at {settings.server_url}", err=True)
    raise typer.Exit(1)


def _build_cli_target(target_url: str | None, repo_path: str) -> Target:
    """Build a minimal Target for resolve_auth host validation."""
    allowed_hosts: list[str] = []
    if target_url:
        _parsed = urlparse(target_url)
        _host = _parsed.hostname or ""
        if _host:
            allowed_hosts = [_host, "127.0.0.1"] if _host != "127.0.0.1" else ["127.0.0.1"]
    return Target(
        id=str(uuid4()),
        workspace_id="cli",
        repo_path=repo_path,
        target_url=target_url,
        allowed_hosts=allowed_hosts,
        created_at=datetime.now(UTC),
    )


@app.command("worker")
def worker() -> None:
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-30s %(levelname)s %(message)s",
        force=True,
    )
    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("LiteLLM").setLevel(logging.WARNING)
    logging.getLogger("temporalio").setLevel(logging.WARNING)

    from quarry_worker.main import main

    main()


@app.command()
def server(
    host: Annotated[str | None, typer.Option("--host", help="Host to bind")] = None,
    port: Annotated[int | None, typer.Option("--port", help="Port to bind")] = None,
    no_worker: Annotated[
        bool, typer.Option("--no-worker", help="Run server without Temporal worker")
    ] = False,
) -> None:
    """Start the Quarry API server with Temporal worker."""
    import logging
    import os

    import uvicorn

    from quarry.config import QuarrySettings

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-30s %(levelname)s %(message)s",
        force=True,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("LiteLLM").setLevel(logging.WARNING)
    logging.getLogger("temporalio").setLevel(logging.WARNING)

    settings = QuarrySettings()
    os.environ["QUARRY_SERVER_NO_WORKER"] = "1" if no_worker else "0"
    uvicorn.run(
        "quarry_server.app:create_app",
        factory=True,
        host=host or settings.server_host,
        port=port or settings.server_port,
    )


@app.command("tui")
def tui(
    api_url: Annotated[str, typer.Option("--api-url")] = "http://localhost:8000",
) -> None:
    from quarry_tui.app import QuarryTuiApp

    QuarryTuiApp(api_url=api_url).run()


@target_app.command("start")
def target_start(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, dir_okay=True)],
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8000,
) -> None:
    try:
        process = start_local_target(path, host=host, port=port)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    typer.echo(f"target=http://{host}:{port}")
    typer.echo("health=ok")

    def _raise_interrupt(*_args: object) -> None:
        raise KeyboardInterrupt

    # Treat SIGTERM like Ctrl-C so the target's whole process group is torn down
    # instead of being orphaned when the launcher is killed.
    signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        process.wait()
    except KeyboardInterrupt:
        pass
    finally:
        terminate_local_target(process)


@report_app.callback(invoke_without_command=True)
def report_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo("Reports are written to .quarry/reports by scan runs.")


@benchmark_app.command("local")
def benchmark_local(
    repo: Annotated[
        str, typer.Option("--repo", help="Path to repository")
    ] = "examples/vulnerable-fastapi",
    ground_truth: Annotated[
        str, typer.Option("--ground-truth", help="Path to ground truth JSON")
    ] = "tests/golden/ground_truth/vulnerable-fastapi.json",
    target: Annotated[str | None, typer.Option("--target", help="Target URL")] = None,
    dynamic_validation: Annotated[
        bool,
        typer.Option(
            "--dynamic-validation/--no-dynamic-validation", help="Enable live dynamic validation"
        ),
    ] = False,
    live_prove: Annotated[
        bool,
        typer.Option(
            "--live-prove/--no-live-prove",
            help="Probe confirmed findings to collect proof artifacts",
        ),
    ] = False,
) -> None:
    """Scan the demo app via the server and compare findings to ground truth."""
    settings = QuarrySettings()
    try:
        lines = asyncio.run(
            _benchmark_local_command(
                settings, repo, ground_truth, target, dynamic_validation, live_prove
            )
        )
    except httpx.ConnectError:
        _exit_server_not_reachable(settings)
    except FileNotFoundError:
        typer.echo(f"Error: ground truth file not found at {ground_truth}", err=True)
        raise typer.Exit(1) from None
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1) from None
    _echo_lines(lines)


def ground_truth_is_inside_repo(repo: str, ground_truth: str) -> bool:
    """True if the ground-truth file lives inside the scanned repo tree.

    An answer key inside the scanned repo lets recon/hunters read it and "cheat",
    invalidating the benchmark. The fix is to keep ground-truth files outside the
    repo; this guard makes a regression fail loudly instead of silently inflating
    recall.
    """
    repo_root = Path(repo).resolve()
    gt = Path(ground_truth).resolve()
    return repo_root == gt or repo_root in gt.parents


async def _benchmark_local_command(
    settings: QuarrySettings,
    repo: str,
    ground_truth: str,
    target: str | None,
    dynamic_validation: bool = False,
    live_prove: bool = False,
) -> list[str]:
    if ground_truth_is_inside_repo(repo, ground_truth):
        raise ValueError(
            f"Ground-truth file {ground_truth!r} is inside the scanned repo {repo!r}; "
            "the agents could read the answer key. Move it outside the repo tree."
        )
    truth = load_ground_truth(ground_truth)
    # Scan exactly the vuln classes present in the ground truth, so recall is
    # measured against what we actually hunt for (the default profile omits
    # ssrf/xss/sql_injection, which would otherwise always read as "missed").
    truth_classes = sorted({item.vuln_class for item in truth}, key=lambda c: c.value)
    async with QuarryClient(base_url=settings.server_url) as client:
        started = time.monotonic()
        result = await client.start_scan(
            repo_path=repo,
            target_url=target,
            vuln_classes=truth_classes,
            dynamic_validation_enabled=dynamic_validation,
            live_prove_enabled=live_prove,
        )
        scan_id = result["scan_id"]
        while True:
            status = await client.get_scan_status(scan_id)
            if _is_terminal_status(status):
                break
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
        runtime_seconds = time.monotonic() - started
        findings = await client.get_findings(scan_id)

    final_findings = [
        finding for finding in findings["final_findings"] if isinstance(finding, FinalFinding)
    ]
    benchmark = compare(final_findings, truth, runtime_seconds=runtime_seconds)
    return [f"scan_id={scan_id}", *benchmark.summary_lines()]


# ---------------------------------------------------------------------------
# quarry provenance sub-commands (ADR-019)
# ---------------------------------------------------------------------------


@provenance_app.command("verify")
def provenance_verify(
    invocation_file: Annotated[
        Path,
        typer.Argument(help="Path to a ModelInvocation JSON file."),
    ],
    system_hash: Annotated[
        str | None,
        typer.Option("--system-hash", help="Expected SHA-256 of the system prompt."),
    ] = None,
    template_sha: Annotated[
        str | None,
        typer.Option("--template-sha", help="Expected SHA-256 of the prompt template."),
    ] = None,
    user_hash: Annotated[
        str | None,
        typer.Option("--user-hash", help="Expected SHA-256 of the user prompt."),
    ] = None,
) -> None:
    """Verify prompt-provenance hashes for a stored ModelInvocation.

    Reads the invocation from INVOCATION_FILE (a JSON file produced by a scan),
    then checks that the stored per-part hashes match the provided expected
    values.  Exits 0 on success, 1 on mismatch or missing file.
    """
    from quarry.schemas import ModelInvocation
    from quarry_cli.provenance import verify_invocation

    if not invocation_file.exists():
        typer.echo(f"Error: file not found: {invocation_file}", err=True)
        raise typer.Exit(code=1)

    try:
        inv = ModelInvocation.model_validate_json(invocation_file.read_text())
    except Exception as exc:
        typer.echo(f"Error: could not parse invocation file: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    ok = verify_invocation(
        inv,
        expected_system_hash=system_hash,
        expected_template_sha256=template_sha,
        expected_user_prompt_hash=user_hash,
    )
    if ok:
        typer.echo(f"OK  {inv.id}  hashes match")
    else:
        typer.echo(f"FAIL  {inv.id}  hash mismatch", err=True)
        raise typer.Exit(code=1)


@provenance_app.command("gc-check")
def provenance_gc_check(
    scans_file: Annotated[
        Path,
        typer.Argument(
            help="Path to a JSON file containing a list of Scan objects. "
            "Outputs scan IDs that are eligible for GC (legal_hold=False)."
        ),
    ],
) -> None:
    """List scans eligible for GC retention sweep (legal_hold=False).

    Reads a JSON array of Scan objects from SCANS_FILE and prints the IDs
    of scans that may be purged.  Scans with ``legal_hold=True`` are omitted.
    """
    import json

    from quarry.schemas import Scan
    from quarry_cli.provenance import should_gc_scan

    if not scans_file.exists():
        typer.echo(f"Error: file not found: {scans_file}", err=True)
        raise typer.Exit(code=1)

    try:
        raw = json.loads(scans_file.read_text())
        scans = [Scan.model_validate(item) for item in raw]
    except Exception as exc:
        typer.echo(f"Error: could not parse scans file: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    eligible = [s for s in scans if should_gc_scan(s)]
    if not eligible:
        typer.echo("No scans eligible for GC.")
        return
    for scan in eligible:
        typer.echo(scan.id)
