"""Command-line interface for Quarry."""

from pathlib import Path
from typing import Annotated

import typer

from quarry_activities.target import start_local_target
from quarry_workflows import RunScanInput, run_fake_scan

app = typer.Typer(help="Quarry local vulnerability research harness.")
scan_app = typer.Typer(help="Run scans.")
target_app = typer.Typer(help="Manage local targets.")
report_app = typer.Typer(help="Inspect reports.")
benchmark_app = typer.Typer(help="Run local benchmarks.")

app.add_typer(scan_app, name="scan")
app.add_typer(target_app, name="target")
app.add_typer(report_app, name="report")
app.add_typer(benchmark_app, name="benchmark")


@scan_app.command("run")
def run_scan(
    repo: Annotated[Path, typer.Option("--repo", exists=True, file_okay=False, dir_okay=True)],
    db: Annotated[Path, typer.Option("--db")] = Path(".quarry/quarry.db"),
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path(".quarry"),
    target: Annotated[str | None, typer.Option("--target")] = None,
) -> None:
    result = run_fake_scan(
        RunScanInput(
            repo_path=str(repo),
            db_path=str(db),
            output_dir=str(output_dir),
            target_url=target,
        )
    )
    typer.echo(f"scan_id={result.scan_id}")
    typer.echo(f"candidate_findings={result.candidate_finding_count}")
    typer.echo(f"report={result.report_path}")


@app.command("worker")
def worker() -> None:
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
    import os

    import uvicorn

    from quarry.config import QuarrySettings

    settings = QuarrySettings()
    os.environ["QUARRY_SERVER_NO_WORKER"] = "1" if no_worker else "0"
    uvicorn.run(
        "quarry_server.app:create_app",
        factory=True,
        host=host or settings.server_host,
        port=port or settings.server_port,
    )


@app.command("tui")
def tui(db: Annotated[Path, typer.Option("--db")] = Path(".quarry/quarry.db")) -> None:
    from quarry_tui.app import QuarryTuiApp

    QuarryTuiApp(db_path=db).run()


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
    try:
        process.wait()
    except KeyboardInterrupt:
        process.terminate()
        process.wait(timeout=5)


@report_app.callback(invoke_without_command=True)
def report_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo("Reports are written to .quarry/reports by scan runs.")


@benchmark_app.command("local")
def benchmark_local() -> None:
    typer.echo("Local benchmark is not implemented yet.")
