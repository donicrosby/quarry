"""Command-line interface for Quarry."""

from pathlib import Path
from typing import Annotated

import typer

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


@app.command("tui")
def tui(db: Annotated[Path, typer.Option("--db")] = Path(".quarry/quarry.db")) -> None:
    from quarry_tui.app import QuarryTuiApp

    QuarryTuiApp(db_path=db).run()


@target_app.command("start")
def target_start(path: Path) -> None:
    typer.echo(f"Target launching is not implemented yet: {path}")


@report_app.callback(invoke_without_command=True)
def report_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo("Reports are written to .quarry/reports by scan runs.")


@benchmark_app.command("local")
def benchmark_local() -> None:
    typer.echo("Local benchmark is not implemented yet.")
