"""Ariadne CLI - Command line interface for attack path synthesis."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from ariadne import __version__

app = typer.Typer(
    name="ariadne",
    help="AI-powered attack path synthesizer - trace threads through the labyrinth",
    no_args_is_help=True,
)
console = Console()

parsers_app = typer.Typer(help="Parser management commands")
app.add_typer(parsers_app, name="parsers")


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]Ariadne[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", callback=version_callback, is_eager=True),
    ] = None,
) -> None:
    """Ariadne - AI-powered attack path synthesizer."""
    pass


@app.command()
def analyze(
    input_path: Annotated[Path, typer.Argument(help="Path to recon data directory or file")],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output file path")
    ] = None,
    target: Annotated[
        Optional[list[str]], typer.Option("--target", "-t", help="Crown jewel targets")
    ] = None,
    llm: Annotated[
        Optional[str], typer.Option("--llm", help="LLM provider/model (e.g., ollama/llama3)")
    ] = None,
    config: Annotated[
        Optional[Path], typer.Option("--config", "-c", help="Config file path")
    ] = None,
    playbook: Annotated[
        bool, typer.Option("--playbook", "-p", help="Generate operator playbooks for attack paths")
    ] = False,
    sprawl: Annotated[
        bool, typer.Option("--sprawl", "-s", help="Enable credential sprawl analysis")
    ] = False,
    privesc: Annotated[
        bool, typer.Option("--privesc", help="Enable privilege escalation chaining")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Validate inputs without full analysis")
    ] = False,
    format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: json, html")
    ] = "html",
) -> None:
    """Analyze recon data and synthesize attack paths."""
    from ariadne.config import load_config
    from ariadne.engine.synthesizer import Synthesizer

    console.print(f"[bold cyan]Ariadne[/] - Analyzing {input_path}")

    if not input_path.exists():
        console.print(f"[red]Error:[/] Path does not exist: {input_path}")
        raise typer.Exit(1)

    cfg = load_config(config)
    if llm:
        cfg.llm.model = llm
    if playbook:
        cfg.playbook.enabled = True
    if sprawl:
        cfg.sprawl.enabled = True
        cfg.scoring.weights.credential_sprawl = cfg.sprawl.sprawl_score_weight
    if privesc:
        cfg.privesc.enabled = True

    synthesizer = Synthesizer(cfg)

    if dry_run:
        console.print("[yellow]Dry run mode - validating inputs only[/]")
        results = synthesizer.validate(input_path)
        if results.valid:
            console.print("[green]Validation passed[/]")
            console.print(f"  Files found: {results.file_count}")
            console.print(f"  Parsers matched: {', '.join(results.parsers)}")
        else:
            console.print("[red]Validation failed[/]")
            for error in results.errors:
                console.print(f"  [red]•[/] {error}")
            raise typer.Exit(1)
        return

    with console.status("[bold green]Synthesizing attack paths..."):
        attack_paths = synthesizer.analyze(
            input_path,
            targets=target or [],
        )

    console.print(f"\n[bold green]Found {len(attack_paths)} attack paths[/]\n")

    for i, path in enumerate(attack_paths[:5], 1):
        console.print(f"[bold]{i}. {path.name}[/] (Score: {path.probability:.1%})")
        for step in path.steps:
            console.print(f"   → {step.description}")
        console.print()

    playbooks = None
    if cfg.playbook.enabled and attack_paths:
        with console.status("[bold yellow]Generating operator playbooks..."):
            playbooks = synthesizer.generate_playbooks(attack_paths)
        console.print(f"[bold yellow]Generated {len(playbooks)} playbooks[/]\n")

    if output:
        synthesizer.export(
            attack_paths,
            output,
            format=format,
            playbooks=playbooks,
            sprawl_report=synthesizer._sprawl_report,
            privesc_report=synthesizer._privesc_report,
        )
        console.print(f"[green]Report saved to:[/] {output}")


@app.command()
def web(
    host: Annotated[str, typer.Option("--host", "-h", help="Host to bind")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to bind")] = 8443,
    reload: Annotated[bool, typer.Option("--reload", help="Enable auto-reload")] = False,
    config: Annotated[
        Optional[Path], typer.Option("--config", "-c", help="Config file path")
    ] = None,
) -> None:
    """Start the Ariadne web dashboard."""
    import uvicorn

    console.print("[bold cyan]Ariadne[/] Web Dashboard")
    console.print(f"[green]Starting server at[/] http://{host}:{port}")

    uvicorn.run(
        "ariadne.web.app:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def export(
    input_path: Annotated[Path, typer.Argument(help="Path to recon data")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file")] = Path(
        "graph_export"
    ),
    format: Annotated[
        str, typer.Option("--format", "-f", help="Export format: json, neo4j-cypher, graphml")
    ] = "json",
) -> None:
    """Export the knowledge graph to various formats."""
    from ariadne.graph.store import GraphStore
    from ariadne.parsers.registry import ParserRegistry

    console.print(f"[bold cyan]Ariadne[/] - Exporting graph from {input_path}")

    registry = ParserRegistry()
    store = GraphStore()

    entities = registry.parse_path(input_path)
    store.build_from_entities(entities)

    output_file = store.export(output, format=format)
    console.print(f"[green]Graph exported to:[/] {output_file}")


@parsers_app.command("list")
def parsers_list() -> None:
    """List all available parsers."""
    from ariadne.parsers.registry import ParserRegistry

    registry = ParserRegistry()
    parsers = registry.list_parsers()

    table = Table(title="Available Parsers")
    table.add_column("Name", style="cyan")
    table.add_column("File Patterns", style="green")
    table.add_column("Description")

    for parser in parsers:
        table.add_row(
            parser.name,
            ", ".join(parser.file_patterns),
            parser.description,
        )

    console.print(table)


@parsers_app.command("info")
def parsers_info(name: Annotated[str, typer.Argument(help="Parser name")]) -> None:
    """Show detailed information about a parser."""
    from ariadne.parsers.registry import ParserRegistry

    registry = ParserRegistry()
    parser = registry.get_parser(name)

    if not parser:
        console.print(f"[red]Parser not found:[/] {name}")
        raise typer.Exit(1)

    console.print(f"[bold cyan]{parser.name}[/]")
    console.print(f"[dim]Description:[/] {parser.description}")
    console.print(f"[dim]File patterns:[/] {', '.join(parser.file_patterns)}")
    console.print(f"[dim]Entity types:[/] {', '.join(parser.entity_types)}")


if __name__ == "__main__":
    app()
