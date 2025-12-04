"""CVElk CLI - Command Line Interface.

A modern CLI built with Typer for managing CVE data in Elasticsearch.
"""

import asyncio
import sys
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn
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


async def _run_sync_nvd(
    settings: "Settings",
    days: int | None,
    full: bool,
    skip_epss: bool,
    skip_kev: bool,
) -> None:
    """Execute the NVD sync operation."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Initialize services
        es_service = ElasticsearchService(settings)
        nvd_service = NVDService(settings)
        epss_service = EPSSService(settings) if not skip_epss else None
        kev_service = KEVService(settings) if not skip_kev else None

        # Check Elasticsearch connection
        task = progress.add_task("Connecting to Elasticsearch...", total=None)
        if not es_service.ping():
            console.print("[red]✗[/] Failed to connect to Elasticsearch")
            raise typer.Exit(1)
        progress.update(task, description="[green]✓[/] Connected to Elasticsearch")

        # Ensure index exists
        es_service.ensure_index()

        # Fetch EPSS data
        if epss_service:
            progress.update(task, description="Fetching EPSS scores...")
            await epss_service.fetch()
            epss_count = epss_service.data.total_count if epss_service.data else 0
            progress.update(task, description=f"[green]✓[/] Loaded {epss_count} EPSS scores")

        # Fetch KEV data
        if kev_service:
            progress.update(task, description="Fetching KEV catalog...")
            await kev_service.fetch()
            kev_count = kev_service.catalog.total_count if kev_service.catalog else 0
            progress.update(task, description=f"[green]✓[/] Loaded {kev_count} KEV entries")

        # Fetch CVEs
        sync_days = days or (None if full else 7)
        cve_generator = _get_cve_generator(nvd_service, full, sync_days, progress, task)

        # Process and enrich CVEs
        cves = await _process_cves(cve_generator, epss_service, kev_service, progress, task)
        progress.update(task, description=f"[green]✓[/] Fetched {len(cves)} CVEs")

        # Index to Elasticsearch
        if cves:
            progress.update(task, description=f"Indexing {len(cves)} CVEs...")
            success, errors = es_service.bulk_index_cves(cves)
            msg = f"[green]✓[/] Indexed {success} CVEs ({errors} errors)"
            progress.update(task, description=msg)

        es_service.close()


def _get_cve_generator(
    nvd_service: NVDService,
    full: bool,
    sync_days: int | None,
    progress: Progress,
    task: TaskID,
) -> AsyncGenerator[Any, None]:
    """Get the appropriate CVE generator based on sync options."""
    if full:
        progress.update(task, description="Fetching ALL CVEs (this will take a while)...")
        return nvd_service.fetch_all()
    if sync_days:
        progress.update(task, description=f"Fetching CVEs from last {sync_days} days...")
        return nvd_service.fetch_recent(days=sync_days)
    progress.update(task, description="Fetching recent CVEs...")
    return nvd_service.fetch_recent(days=7)


async def _process_cves(
    cve_generator: AsyncGenerator[Any, None],
    epss_service: EPSSService | None,
    kev_service: KEVService | None,
    progress: Progress,
    task: TaskID,
) -> list[Any]:
    """Process and enrich CVEs from the generator."""
    cves = []
    async for cve in cve_generator:
        if epss_service:
            epss_service.enrich_cve(cve)
        if kev_service:
            kev_service.enrich_cve(cve)
        cves.append(cve)
        if len(cves) % 100 == 0:
            progress.update(task, description=f"Processed {len(cves)} CVEs...")
    return cves


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
    asyncio.run(_run_sync_nvd(settings, days, full, skip_epss, skip_kev))
    console.print("\n[green]✓[/] NVD Sync complete!")


async def _run_sync_v5(  # noqa: PLR0915
    settings: "Settings",
    years: list[int] | None,
    skip_epss: bool,
    skip_kev: bool,
    batch_size: int,
) -> None:
    """Execute the CVE List V5 sync operation."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Initialize services
        es_service = ElasticsearchService(settings)
        v5_service = CVEListV5Service(settings)
        epss_service = EPSSService(settings) if not skip_epss else None
        kev_service = KEVService(settings) if not skip_kev else None

        # Check Elasticsearch connection
        task = progress.add_task("Connecting to Elasticsearch...", total=None)
        if not es_service.ping():
            console.print("[red]✗[/] Failed to connect to Elasticsearch")
            raise typer.Exit(1)
        progress.update(task, description="[green]✓[/] Connected to Elasticsearch")

        # Ensure index exists
        es_service.ensure_index()

        # Clone or update the repository
        progress.update(task, description="Cloning/updating CVE List V5 repository...")
        if not v5_service.clone_or_update():
            console.print("[red]✗[/] Failed to clone/update CVE List V5 repository")
            raise typer.Exit(1)

        # Get repository stats
        stats = v5_service.get_stats()
        total_cves = stats.get("total_cves", 0)
        progress.update(
            task,
            description=f"[green]✓[/] Repository ready with {total_cves:,} CVE files",
        )

        # Fetch EPSS data
        if epss_service:
            progress.update(task, description="Fetching EPSS scores...")
            await epss_service.fetch()
            epss_count = epss_service.data.total_count if epss_service.data else 0
            progress.update(task, description=f"[green]✓[/] Loaded {epss_count:,} EPSS scores")

        # Fetch KEV data
        if kev_service:
            progress.update(task, description="Fetching KEV catalog...")
            await kev_service.fetch()
            kev_count = kev_service.catalog.total_count if kev_service.catalog else 0
            progress.update(task, description=f"[green]✓[/] Loaded {kev_count:,} KEV entries")

        # Process CVEs in batches
        progress.update(task, description="Processing CVEs from repository...")
        cves = []
        processed = 0
        indexed = 0
        errors = 0

        for cve in v5_service.iter_cves():
            # Skip non-published CVEs
            if cve.vuln_status not in ["Published", "PUBLISHED"]:
                continue

            # Enrich with EPSS and KEV data
            if epss_service:
                epss_service.enrich_cve(cve)
            if kev_service:
                kev_service.enrich_cve(cve)

            cves.append(cve)
            processed += 1

            # Index in batches
            if len(cves) >= batch_size:
                progress.update(
                    task,
                    description=f"Indexing batch... ({indexed:,}/{processed:,} processed)",
                )
                success, errs = es_service.bulk_index_cves(cves)
                indexed += success
                errors += errs
                cves = []

            if processed % 10000 == 0:
                progress.update(
                    task,
                    description=f"Processing... {processed:,} CVEs ({indexed:,} indexed)",
                )

        # Index remaining CVEs
        if cves:
            progress.update(task, description=f"Indexing final batch ({len(cves)} CVEs)...")
            success, errs = es_service.bulk_index_cves(cves)
            indexed += success
            errors += errs

        progress.update(
            task,
            description=f"[green]✓[/] Indexed {indexed:,} CVEs ({errors} errors)",
        )

        es_service.close()


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

    asyncio.run(_run_sync_v5(settings, years, skip_epss, skip_kev, batch_size))
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

    asyncio.run(_run_full_sync(settings, skip_nvd, skip_epss, skip_kev, batch_size))
    console.print("\n[green]✓[/] Full sync complete!")


async def _run_full_sync(  # noqa: PLR0912, PLR0915
    settings: "Settings",
    skip_nvd: bool,
    skip_epss: bool,
    skip_kev: bool,
    batch_size: int,
) -> None:
    """Execute the full sync operation combining V5 + NVD + EPSS + KEV."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Initialize services
        es_service = ElasticsearchService(settings)
        v5_service = CVEListV5Service(settings)
        nvd_service = NVDService(settings) if not skip_nvd else None
        epss_service = EPSSService(settings) if not skip_epss else None
        kev_service = KEVService(settings) if not skip_kev else None

        # Check Elasticsearch connection
        task = progress.add_task("Connecting to Elasticsearch...", total=None)
        if not es_service.ping():
            console.print("[red]✗[/] Failed to connect to Elasticsearch")
            raise typer.Exit(1)
        progress.update(task, description="[green]✓[/] Connected to Elasticsearch")

        # Ensure index exists
        es_service.ensure_index()

        # Clone or update the V5 repository
        progress.update(task, description="Cloning/updating CVE List V5 repository...")
        if not v5_service.clone_or_update():
            console.print("[red]✗[/] Failed to clone/update CVE List V5 repository")
            raise typer.Exit(1)

        # Get repository stats
        stats = v5_service.get_stats()
        total_cves = stats.get("total_cves", 0)
        progress.update(
            task,
            description=f"[green]✓[/] Repository ready with {total_cves:,} CVE files",
        )

        # Fetch EPSS data
        if epss_service:
            progress.update(task, description="Fetching EPSS scores...")
            await epss_service.fetch()
            epss_count = epss_service.data.total_count if epss_service.data else 0
            progress.update(task, description=f"[green]✓[/] Loaded {epss_count:,} EPSS scores")

        # Fetch KEV data
        if kev_service:
            progress.update(task, description="Fetching KEV catalog...")
            await kev_service.fetch()
            kev_count = kev_service.catalog.total_count if kev_service.catalog else 0
            progress.update(task, description=f"[green]✓[/] Loaded {kev_count:,} KEV entries")

        # Build NVD lookup cache if enabled
        nvd_cache: dict[str, Any] = {}
        if nvd_service:
            progress.update(task, description="Fetching NVD data (this may take a while)...")
            nvd_count = 0
            async for cve in nvd_service.fetch_all():
                nvd_cache[cve.cve_id] = cve
                nvd_count += 1
                if nvd_count % 5000 == 0:
                    progress.update(
                        task,
                        description=f"Fetching NVD data... {nvd_count:,} CVEs",
                    )
            progress.update(task, description=f"[green]✓[/] Loaded {nvd_count:,} NVD records")

        # Process CVEs in batches
        progress.update(task, description="Processing CVEs from repository...")
        cves = []
        processed = 0
        indexed = 0
        errors = 0

        for cve in v5_service.iter_cves():
            # Skip non-published CVEs
            if cve.vuln_status not in ["Published", "PUBLISHED"]:
                continue

            # Enrich with NVD data (better CVSS, CWE, status)
            if nvd_service and cve.cve_id in nvd_cache:
                nvd_cve = nvd_cache[cve.cve_id]
                _merge_nvd_data(cve, nvd_cve)

            # Enrich with EPSS and KEV data
            if epss_service:
                epss_service.enrich_cve(cve)
            if kev_service:
                kev_service.enrich_cve(cve)

            cves.append(cve)
            processed += 1

            # Index in batches
            if len(cves) >= batch_size:
                progress.update(
                    task,
                    description=f"Indexing batch... ({indexed:,}/{processed:,} processed)",
                )
                success, errs = es_service.bulk_index_cves(cves)
                indexed += success
                errors += errs
                cves = []

            if processed % 10000 == 0:
                progress.update(
                    task,
                    description=f"Processing... {processed:,} CVEs ({indexed:,} indexed)",
                )

        # Index remaining CVEs
        if cves:
            progress.update(task, description=f"Indexing final batch ({len(cves)} CVEs)...")
            success, errs = es_service.bulk_index_cves(cves)
            indexed += success
            errors += errs

        progress.update(
            task,
            description=f"[green]✓[/] Indexed {indexed:,} CVEs ({errors} errors)",
        )

        es_service.close()


def _merge_nvd_data(v5_cve: "CVE", nvd_cve: "CVE") -> None:
    """Merge NVD data into a V5 CVE record.

    NVD provides better:
    - CVSS v2/v3/v4 scores with full metrics
    - CWE mappings
    - Vulnerability status
    - References with tags

    Args:
        v5_cve: CVE from V5 repository (modified in place)
        nvd_cve: CVE from NVD API
    """
    # Prefer NVD CVSS scores (more detailed)
    if nvd_cve.cvss_v2 and not v5_cve.cvss_v2:
        v5_cve.cvss_v2 = nvd_cve.cvss_v2
    if nvd_cve.cvss_v3:
        v5_cve.cvss_v3 = nvd_cve.cvss_v3  # NVD usually has better v3 data
    if nvd_cve.cvss_v4 and not v5_cve.cvss_v4:
        v5_cve.cvss_v4 = nvd_cve.cvss_v4

    # Merge weaknesses (CWEs)
    existing_cwes = {w.cwe_id for w in v5_cve.weaknesses}
    for weakness in nvd_cve.weaknesses:
        if weakness.cwe_id not in existing_cwes:
            v5_cve.weaknesses.append(weakness)

    # Use NVD vulnerability status if more specific
    if nvd_cve.vuln_status and nvd_cve.vuln_status != "Published":
        v5_cve.vuln_status = nvd_cve.vuln_status

    # Merge references
    existing_urls = {r.url for r in v5_cve.references}
    for ref in nvd_cve.references:
        if ref.url not in existing_urls:
            v5_cve.references.append(ref)


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

            progress.update(task, description="Setting up CVElk dashboard...")
            result = await kb_service.setup_cvelk_dashboard(
                dashboard_path=dashboard_path if dashboard_path.exists() else None,
            )

            if "dashboard_url" in result:
                progress.update(task, description="[green]✓[/] Dashboard configured")
                console.print(f"\n[bold]Dashboard URL:[/] {result['dashboard_url']}")
            else:
                progress.update(task, description="[green]✓[/] Data view created")

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

    stats = es_service.get_stats()

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
            f"{cve.get('baseScore', 0):.1f}",
            cve.get("baseSeverity", "N/A"),
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
    effective_rate = 50 if settings.nvd.api_key else 5
    table.add_row("  Rate Limit", f"{effective_rate} req/30s")

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
            "--skip-nvd",
            help="Skip NVD data enrichment (faster updates).",
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
            asyncio.run(_run_full_sync(settings, skip_nvd, skip_epss, skip_kev, batch_size=1000))
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
