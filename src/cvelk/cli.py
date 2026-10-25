"""CVElk CLI - Command Line Interface.

A modern CLI built with Typer for managing CVE data in Elasticsearch.
"""

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

if TYPE_CHECKING:
    from cvelk.config import Settings
    from cvelk.models.cve import CVE

from cvelk import __version__
from cvelk.config import get_settings
from cvelk.services import (
    CVEListV5Service,
    ElasticsearchService,
    EPSSService,
    KEVService,
    KibanaService,
    NVDService,
)
from cvelk.sync import Reporter, SyncPipeline, SyncResult

# Create Typer app
app = typer.Typer(
    name="cvelk",
    help="CVElk - Vulnerability Intelligence Platform",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold blue]CVElk[/] version [green]{__version__}[/]")
        raise typer.Exit()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity."""
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    log_format = (
        "<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    )
    logger.add(sys.stderr, level=level, format=log_format)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output.",
        ),
    ] = False,
) -> None:
    """CVElk - Import NVD, EPSS, and KEV data into Elasticsearch."""
    setup_logging(verbose)


def _progress() -> Progress:
    """Create the spinner progress display used by the sync commands."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )


def _connect_elasticsearch(settings: "Settings", report: Reporter) -> ElasticsearchService:
    """Connect to Elasticsearch and ensure the CVE index exists, or exit."""
    es_service = ElasticsearchService(settings)
    report("Connecting to Elasticsearch...")
    if not es_service.ping():
        console.print("[red]✗[/] Failed to connect to Elasticsearch")
        es_service.close()
        raise typer.Exit(1)
    report("[green]✓[/] Connected to Elasticsearch")
    es_service.ensure_index()
    return es_service


async def _load_enrichment(
    settings: "Settings",
    skip_epss: bool,
    skip_kev: bool,
    report: Reporter,
) -> tuple[EPSSService | None, KEVService | None]:
    """Fetch the EPSS and KEV feeds unless skipped."""
    epss_service = None
    if not skip_epss:
        epss_service = EPSSService(settings)
        report("Fetching EPSS scores...")
        await epss_service.fetch()
        epss_count = epss_service.data.total_count if epss_service.data else 0
        report(f"[green]✓[/] Loaded {epss_count:,} EPSS scores")

    kev_service = None
    if not skip_kev:
        kev_service = KEVService(settings)
        report("Fetching KEV catalog...")
        await kev_service.fetch()
        kev_count = kev_service.catalog.total_count if kev_service.catalog else 0
        report(f"[green]✓[/] Loaded {kev_count:,} KEV entries")

    return epss_service, kev_service


async def _load_nvd_cache(settings: "Settings", report: Reporter) -> dict[str, "CVE"]:
    """Fetch every NVD record, keyed by CVE ID, for merging into V5 records."""
    report("Fetching NVD data (this may take a while)...")
    nvd_cache: dict[str, CVE] = {}
    async for cve in NVDService(settings).fetch_all():
        nvd_cache[cve.cve_id] = cve
        if len(nvd_cache) % 5000 == 0:
            report(f"Fetching NVD data... {len(nvd_cache):,} CVEs")
    report(f"[green]✓[/] Loaded {len(nvd_cache):,} NVD records")
    return nvd_cache


def _summary(result: SyncResult) -> str:
    """Describe a finished sync run."""
    details = [f"Indexed {result.indexed:,} CVEs"]
    if result.deleted:
        details.append(f"removed {result.deleted:,} rejected")
    if result.refreshed:
        details.append(f"refreshed EPSS/KEV on {result.refreshed:,}")
    return f"[green]✓[/] {', '.join(details)} ({result.errors} errors)"


async def _run_sync_nvd(
    settings: "Settings",
    *,
    days: int | None,
    full: bool,
    skip_epss: bool,
    skip_kev: bool,
    batch_size: int = 1000,
) -> None:
    """Execute the NVD sync operation."""
    with _progress() as progress:
        task = progress.add_task("Starting...", total=None)

        def report(message: str) -> None:
            progress.update(task, description=message)

        es_service = _connect_elasticsearch(settings, report)
        try:
            epss_service, kev_service = await _load_enrichment(
                settings, skip_epss, skip_kev, report
            )

            nvd_service = NVDService(settings)
            cves: AsyncIterator[CVE]
            if full:
                report("Fetching ALL CVEs (this will take a while)...")
                cves = nvd_service.fetch_all()
            else:
                sync_days = days or 7
                report(f"Fetching CVEs from last {sync_days} days...")
                cves = nvd_service.fetch_recent(days=sync_days)

            pipeline = SyncPipeline(
                es_service,
                epss_service=epss_service,
                kev_service=kev_service,
                batch_size=batch_size,
                report=report,
            )
            result = await pipeline.run(cves)
            es_service.refresh()
        finally:
            es_service.close()

        report(_summary(result))


@app.command(name="sync-nvd")
def sync_nvd(
    days: Annotated[
        int | None,
        typer.Option(
            "--days",
            "-d",
            help="Only sync CVEs modified in the last N days.",
        ),
    ] = None,
    full: Annotated[
        bool,
        typer.Option(
            "--full",
            "-f",
            help="Perform a full sync of all CVE data.",
        ),
    ] = False,
    skip_epss: Annotated[
        bool,
        typer.Option(
            "--skip-epss",
            help="Skip EPSS data enrichment.",
        ),
    ] = False,
    skip_kev: Annotated[
        bool,
        typer.Option(
            "--skip-kev",
            help="Skip KEV data enrichment.",
        ),
    ] = False,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            "-b",
            help="Number of CVEs to index per batch.",
        ),
    ] = 1000,
) -> None:
    """Sync CVE data from NVD API to Elasticsearch.

    By default, syncs CVEs from the last 7 days.
    Use --days to specify a different time range.
    Use --full for a complete sync (can take hours).

    Note: For a complete sync from the authoritative CVE source,
    use 'cvelk sync' which uses the CVE List V5 repository.
    """
    settings = get_settings()
    console.print(Panel.fit("[bold blue]CVElk NVD Sync[/]", border_style="blue"))
    asyncio.run(
        _run_sync_nvd(
            settings,
            days=days,
            full=full,
            skip_epss=skip_epss,
            skip_kev=skip_kev,
            batch_size=batch_size,
        )
    )
    console.print("\n[green]✓[/] NVD Sync complete!")


async def _run_sync_v5(
    settings: "Settings",
    *,
    skip_nvd: bool,
    skip_epss: bool,
    skip_kev: bool,
    batch_size: int,
    incremental: bool = False,
) -> None:
    """Sync from the CVE List V5 repository, optionally merging NVD data.

    With ``incremental``, only records changed since the last successful sync are
    processed, and EPSS/KEV values on unchanged CVEs are refreshed when a new
    feed release is out.
    """
    with _progress() as progress:
        task = progress.add_task("Starting...", total=None)

        def report(message: str) -> None:
            progress.update(task, description=message)

        es_service = _connect_elasticsearch(settings, report)
        try:
            v5_service = CVEListV5Service(settings)
            report("Cloning/updating CVE List V5 repository...")
            if not v5_service.clone_or_update():
                console.print("[red]✗[/] Failed to clone/update CVE List V5 repository")
                raise typer.Exit(1)

            stats = v5_service.get_stats()
            total_cves = stats.get("total_cves", 0)
            report(f"[green]✓[/] Repository ready with {total_cves:,} CVE files")

            epss_service, kev_service = await _load_enrichment(
                settings, skip_epss, skip_kev, report
            )
            nvd_cache = None if skip_nvd else await _load_nvd_cache(settings, report)

            pipeline = SyncPipeline(
                es_service,
                epss_service=epss_service,
                kev_service=kev_service,
                nvd_cache=nvd_cache,
                batch_size=batch_size,
                report=report,
            )

            # Without a checkpoint an incremental sync falls back to a complete scan
            incremental = incremental and v5_service.load_sync_commit() is not None
            removed_ids = v5_service.removed_cve_ids() if incremental else []

            report("Processing CVEs from repository...")
            result = await pipeline.run(
                v5_service.iter_cves(changed_only=incremental),
                removed_ids=removed_ids,
            )

            if incremental:
                result.refreshed = pipeline.refresh_stale_enrichment(v5_service.state)
            elif result.errors == 0:
                pipeline.mark_enrichment_current(v5_service.state)

            if result.errors == 0:
                v5_service.save_sync_commit()
            es_service.refresh()
        finally:
            es_service.close()

        report(_summary(result))


@app.command(name="sync-v5")
def sync_v5(
    years: Annotated[
        list[int] | None,
        typer.Option(
            "--years",
            "-y",
            help="Only sync CVEs from specific years (e.g., --years 2023 --years 2024).",
        ),
    ] = None,
    skip_epss: Annotated[
        bool,
        typer.Option(
            "--skip-epss",
            help="Skip EPSS data enrichment.",
        ),
    ] = False,
    skip_kev: Annotated[
        bool,
        typer.Option(
            "--skip-kev",
            help="Skip KEV data enrichment.",
        ),
    ] = False,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            "-b",
            help="Number of CVEs to index per batch.",
        ),
    ] = 1000,
    incremental: Annotated[
        bool,
        typer.Option(
            "--incremental",
            help="Only process CVE files changed since the last successful sync.",
        ),
    ] = False,
) -> None:
    """Sync CVE data from the official CVE List V5 repository.

    This syncs from https://github.com/CVEProject/cvelistV5 which is the
    authoritative source for CVE data, updated every 7 minutes.

    The repository will be cloned on first run and updated on subsequent runs.
    Use --years to limit sync to specific years.
    """
    settings = get_settings()

    # Override years filter if specified
    if years:
        settings.cve_list_v5.years = years

    console.print(Panel.fit("[bold blue]CVElk CVE V5 Sync[/]", border_style="blue"))
    console.print(f"[dim]Repository: {settings.cve_list_v5.repo_url}[/]")
    if years:
        console.print(f"[dim]Years filter: {years}[/]")
    console.print()

    asyncio.run(
        _run_sync_v5(
            settings,
            skip_nvd=True,
            skip_epss=skip_epss,
            skip_kev=skip_kev,
            batch_size=batch_size,
            incremental=incremental,
        )
    )
    console.print("\n[green]✓[/] CVE V5 Sync complete!")


@app.command()
def sync(
    skip_nvd: Annotated[
        bool,
        typer.Option(
            "--skip-nvd",
            help="Skip NVD data enrichment (faster, but less CVSS/CWE data).",
        ),
    ] = False,
    skip_epss: Annotated[
        bool,
        typer.Option(
            "--skip-epss",
            help="Skip EPSS data enrichment.",
        ),
    ] = False,
    skip_kev: Annotated[
        bool,
        typer.Option(
            "--skip-kev",
            help="Skip KEV data enrichment.",
        ),
    ] = False,
    years: Annotated[
        list[int] | None,
        typer.Option(
            "--years",
            "-y",
            help="Only sync CVEs from specific years.",
        ),
    ] = None,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            "-b",
            help="Number of CVEs to index per batch.",
        ),
    ] = 1000,
) -> None:
    """Sync all CVE data to Elasticsearch.

    This is the main sync command that:
    1. Fetches CVE data from CVE List V5 (authoritative source)
    2. Enriches with NVD data (CVSS scores, CWEs, status)
    3. Enriches with EPSS scores (exploitation probability)
    4. Enriches with CISA KEV catalog (known exploited vulnerabilities)

    Examples:
        cvelk sync                    # Full sync (recommended)
        cvelk sync --years 2024       # Sync only 2024 CVEs
        cvelk sync --skip-nvd         # Skip NVD enrichment (faster)
    """
    settings = get_settings()

    # Override years filter if specified
    if years:
        settings.cve_list_v5.years = years

    console.print(Panel.fit("[bold blue]CVElk Full Sync[/]", border_style="blue"))
    console.print("[dim]Sources:[/]")
    console.print("  • CVE List V5 Repository (primary)")
    if not skip_nvd:
        console.print("  • NVD API (CVSS/CWE enrichment)")
    if not skip_epss:
        console.print("  • EPSS (exploitation probability)")
    if not skip_kev:
        console.print("  • CISA KEV (known exploited)")
    if years:
        console.print(f"[dim]Years filter: {years}[/]")
    console.print()

    asyncio.run(
        _run_sync_v5(
            settings,
            skip_nvd=skip_nvd,
            skip_epss=skip_epss,
            skip_kev=skip_kev,
            batch_size=batch_size,
        )
    )
    console.print("\n[green]✓[/] Full sync complete!")


@app.command()
def setup(
    dashboard: Annotated[
        Path | None,
        typer.Option(
            "--dashboard",
            "-d",
            help="Path to dashboard NDJSON file to import.",
        ),
    ] = None,
) -> None:
    """Set up Kibana dashboards and data views."""
    settings = get_settings()

    async def _setup() -> None:
        kb_service = KibanaService(settings)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Checking Kibana connection...", total=None)

            if not await kb_service.ping():
                console.print("[red]✗[/] Failed to connect to Kibana")
                raise typer.Exit(1)

            progress.update(task, description="[green]✓[/] Connected to Kibana")

            # Set up dashboard
            default_dashboard = Path(__file__).parent / "resources" / "dashboards" / "cvelk.ndjson"
            dashboard_path = dashboard or default_dashboard

            if not dashboard_path.exists():
                console.print(f"[red]✗[/] Dashboard file not found: {dashboard_path}")
                raise typer.Exit(1)

            progress.update(task, description="Setting up CVElk dashboard...")
            result = await kb_service.setup_cvelk_dashboard(dashboard_path)

            if "dashboard_url" not in result:
                console.print("[red]✗[/] Dashboard setup failed; see the log for details")
                raise typer.Exit(1)
            progress.update(task, description="[green]✓[/] Dashboard configured")
            console.print(f"\n[bold]Dashboard URL:[/] {result['dashboard_url']}")

    console.print(Panel.fit("[bold blue]CVElk Setup[/]", border_style="blue"))
    asyncio.run(_setup())


@app.command()
def stats() -> None:
    """Show statistics about indexed CVE data."""
    settings = get_settings()
    es_service = ElasticsearchService(settings)

    if not es_service.ping():
        console.print("[red]✗[/] Failed to connect to Elasticsearch")
        raise typer.Exit(1)

    index_name = settings.elasticsearch.index_name
    if not es_service.index_exists():
        console.print(
            f"[yellow]Index '{index_name}' does not exist yet. Run 'cvelk sync' first.[/]"
        )
        es_service.close()
        raise typer.Exit(1)

    stats = es_service.get_stats()

    if "error" in stats:
        console.print(f"[red]✗[/] Failed to get Elasticsearch statistics: {stats['error']}")
        es_service.close()
        raise typer.Exit(1)

    table = Table(title="CVElk Statistics", border_style="blue")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Index Name", stats.get("index_name", "N/A"))
    table.add_row("Document Count", f"{stats.get('document_count', 0):,}")
    table.add_row("Index Size", f"{stats.get('size_bytes', 0) / 1024 / 1024:.2f} MB")

    console.print(table)
    es_service.close()


@app.command()
def search(
    query: Annotated[
        str,
        typer.Argument(help="Search query (CVE ID or keyword)"),
    ],
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum results"),
    ] = 10,
) -> None:
    """Search for CVEs in Elasticsearch."""
    settings = get_settings()
    es_service = ElasticsearchService(settings)

    if not es_service.ping():
        console.print("[red]✗[/] Failed to connect to Elasticsearch")
        raise typer.Exit(1)

    # Build query
    es_query: dict[str, Any]
    if query.upper().startswith("CVE-"):
        # Exact CVE ID search
        es_query = {"term": {"cveId": query.upper()}}
    else:
        # Full text search
        es_query = {"multi_match": {"query": query, "fields": ["description", "cveId"]}}

    results = es_service.search_cves(es_query, size=limit)

    if not results:
        console.print(f"[yellow]No results found for '{query}'[/]")
        raise typer.Exit(0)

    table = Table(title=f"Search Results for '{query}'", border_style="blue")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Score", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("EPSS", style="magenta")
    table.add_column("KEV", style="green")
    table.add_column("Description", max_width=50)

    for cve in results:
        table.add_row(
            cve.get("cveId", ""),
            f"{cve['baseScore']:.1f}" if cve.get("baseScore") is not None else "N/A",
            cve.get("baseSeverity") or "N/A",
            f"{cve.get('epssScore', 0):.2f}%" if cve.get("epssScore") else "N/A",
            "✓" if cve.get("isKev") else "",
            cve.get("description", "")[:100] + "...",
        )

    console.print(table)
    es_service.close()


@app.command()
def config() -> None:
    """Show current configuration."""
    settings = get_settings()

    table = Table(title="CVElk Configuration", border_style="blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Log Level", settings.log_level)
    table.add_row("Data Directory", str(settings.data_dir))
    table.add_row("", "")
    table.add_row("[bold]Elasticsearch[/]", "")
    table.add_row("  Host", settings.elasticsearch.host)
    table.add_row("  Index", settings.elasticsearch.index_name)
    table.add_row("  Cloud", "Yes" if settings.elasticsearch.is_cloud else "No")
    table.add_row("", "")
    table.add_row("[bold]Kibana[/]", "")
    table.add_row("  Host", settings.kibana.host)
    table.add_row("", "")
    table.add_row("[bold]CVE List V5[/]", "")
    table.add_row("  Repository", settings.cve_list_v5.repo_url)
    table.add_row("  Local Path", str(settings.cve_list_v5.local_path))
    table.add_row("  Shallow Clone", "Yes" if settings.cve_list_v5.use_shallow_clone else "No")
    table.add_row("", "")
    table.add_row("[bold]NVD[/]", "")
    table.add_row("  API Key", "Set" if settings.nvd.api_key else "Not set")
    # Rate limit is 50 req/30s with API key, 5 req/30s without
    table.add_row("  Rate Limit", f"{settings.nvd.effective_rate_limit} req/30s")

    console.print(table)


@app.command()
def watch(
    interval: Annotated[
        int,
        typer.Option(
            "--interval",
            "-i",
            help="Update interval in minutes.",
        ),
    ] = 15,
    skip_nvd: Annotated[
        bool,
        typer.Option(
            "--skip-nvd/--no-skip-nvd",
            help="Skip NVD data enrichment (faster updates). Use --no-skip-nvd to include it.",
        ),
    ] = True,
    skip_epss: Annotated[
        bool,
        typer.Option(
            "--skip-epss",
            help="Skip EPSS data enrichment.",
        ),
    ] = False,
    skip_kev: Annotated[
        bool,
        typer.Option(
            "--skip-kev",
            help="Skip KEV data enrichment.",
        ),
    ] = False,
) -> None:
    """Watch for CVE updates and sync automatically.

    Runs continuous updates at the specified interval (default: 15 minutes).
    By default, skips NVD enrichment for faster incremental updates.

    The CVE List V5 repository updates every 7 minutes, so a 15-minute
    interval ensures you catch all updates with minimal load.

    Examples:
        cvelk watch                    # Update every 15 minutes
        cvelk watch --interval 30      # Update every 30 minutes
        cvelk watch --interval 5       # Update every 5 minutes
        cvelk watch --no-skip-nvd      # Include NVD enrichment (full sync each time)
    """
    import time  # noqa: PLC0415
    from datetime import datetime  # noqa: PLC0415

    settings = get_settings()

    console.print(Panel.fit("[bold blue]CVElk Watch Mode[/]", border_style="blue"))
    console.print(f"[dim]Update interval: {interval} minutes[/]")
    console.print(f"[dim]NVD enrichment: {'Disabled' if skip_nvd else 'Enabled'}[/]")
    console.print(f"[dim]EPSS enrichment: {'Disabled' if skip_epss else 'Enabled'}[/]")
    console.print(f"[dim]KEV enrichment: {'Disabled' if skip_kev else 'Enabled'}[/]")
    console.print("\n[yellow]Press Ctrl+C to stop[/]\n")

    update_count = 0
    while True:
        update_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"\n[bold cyan]═══ Update #{update_count} at {timestamp} ═══[/]")

        try:
            # NVD merging needs every record, so only V5-only updates are incremental
            asyncio.run(
                _run_sync_v5(
                    settings,
                    skip_nvd=skip_nvd,
                    skip_epss=skip_epss,
                    skip_kev=skip_kev,
                    batch_size=1000,
                    incremental=skip_nvd,
                )
            )
            console.print(f"[green]✓[/] Update complete. Next update in {interval} minutes.")
        except Exception as e:
            console.print(f"[red]✗[/] Update failed: {e}")
            console.print(f"[yellow]Will retry in {interval} minutes.[/]")

        # Sleep for the interval
        try:
            for remaining in range(interval * 60, 0, -1):
                mins, secs = divmod(remaining, 60)
                timer = f"Next update in: {mins:02d}:{secs:02d}"
                console.print(f"\r{timer}", end="")
                time.sleep(1)
            console.print("\r" + " " * 30 + "\r", end="")  # Clear the line
        except KeyboardInterrupt:
            console.print("\n\n[yellow]Watch mode stopped by user.[/]")
            raise typer.Exit(0) from None


if __name__ == "__main__":
    app()
