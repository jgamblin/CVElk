"""Sync pipeline shared by the CLI sync commands.

Takes a stream of CVEs from any source, enriches them with NVD, EPSS and KEV
data, indexes them in batches and removes rejected CVEs from the index.
"""

from collections.abc import AsyncIterable, AsyncIterator, Callable, Iterable
from dataclasses import dataclass

from loguru import logger

from cvelk.models.cve import CVE
from cvelk.services import ElasticsearchService, EPSSService, KEVService
from cvelk.utils.sync_state import SyncState

# Progress callback; messages may contain Rich markup.
Reporter = Callable[[str], None]

EPSS_STATE_KEY = "epss_score_date"
KEV_STATE_KEY = "kev_version"


@dataclass
class SyncResult:
    """Counts from a sync run."""

    processed: int = 0
    indexed: int = 0
    deleted: int = 0
    refreshed: int = 0
    errors: int = 0


def merge_nvd_data(v5_cve: CVE, nvd_cve: CVE) -> None:
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


async def _iterate(cves: Iterable[CVE] | AsyncIterable[CVE]) -> AsyncIterator[CVE]:
    """Iterate over a sync or async CVE source."""
    if isinstance(cves, AsyncIterable):
        async for cve in cves:
            yield cve
    else:
        for cve in cves:
            yield cve


class SyncPipeline:
    """Enrich, index and prune CVEs in Elasticsearch."""

    def __init__(
        self,
        es_service: ElasticsearchService,
        *,
        epss_service: EPSSService | None = None,
        kev_service: KEVService | None = None,
        nvd_cache: dict[str, CVE] | None = None,
        batch_size: int = 1000,
        report: Reporter | None = None,
    ):
        """Initialize the pipeline.

        Args:
            es_service: Elasticsearch service to write to.
            epss_service: Loaded EPSS service, or None to skip EPSS enrichment.
            kev_service: Loaded KEV service, or None to skip KEV enrichment.
            nvd_cache: NVD records by CVE ID to merge into each CVE, if any.
            batch_size: Number of CVEs to index or delete per batch.
            report: Progress callback.
        """
        self.es_service = es_service
        self.epss_service = epss_service
        self.kev_service = kev_service
        self.nvd_cache = nvd_cache
        self.batch_size = batch_size
        self.report: Reporter = report or (lambda _message: None)

    def enrich(self, cve: CVE) -> None:
        """Apply NVD, EPSS and KEV data to a CVE in place."""
        if self.nvd_cache and (nvd_cve := self.nvd_cache.get(cve.cve_id)):
            merge_nvd_data(cve, nvd_cve)
        if self.epss_service:
            self.epss_service.enrich_cve(cve)
        if self.kev_service:
            self.kev_service.enrich_cve(cve)

    async def run(
        self,
        cves: Iterable[CVE] | AsyncIterable[CVE],
        removed_ids: Iterable[str] = (),
    ) -> SyncResult:
        """Index published CVEs and delete rejected or removed ones.

        Args:
            cves: CVE source.
            removed_ids: IDs of CVEs that no longer exist at the source.

        Returns:
            Counts for the run.
        """
        result = SyncResult()
        to_index: list[CVE] = []
        to_delete: list[str] = list(removed_ids)

        async for cve in _iterate(cves):
            result.processed += 1

            if cve.is_rejected:
                to_delete.append(cve.cve_id)
            else:
                self.enrich(cve)
                to_index.append(cve)

            if len(to_index) >= self.batch_size:
                self.report(
                    f"Indexing batch... ({result.indexed:,}/{result.processed:,} processed)"
                )
                self._flush_index(to_index, result)
            if len(to_delete) >= self.batch_size:
                self._flush_delete(to_delete, result)

            if result.processed % 10000 == 0:
                self.report(f"Processing... {result.processed:,} CVEs ({result.indexed:,} indexed)")

        if to_index:
            self.report(f"Indexing final batch ({len(to_index)} CVEs)...")
            self._flush_index(to_index, result)
        if to_delete:
            self._flush_delete(to_delete, result)

        return result

    def _flush_index(self, cves: list[CVE], result: SyncResult) -> None:
        success, errors = self.es_service.bulk_index_cves(cves)
        result.indexed += success
        result.errors += errors
        cves.clear()

    def _flush_delete(self, cve_ids: list[str], result: SyncResult) -> None:
        deleted, errors = self.es_service.bulk_delete_cves(cve_ids)
        result.deleted += deleted
        result.errors += errors
        cve_ids.clear()

    def _epss_version(self) -> str | None:
        data = self.epss_service.data if self.epss_service else None
        return data.score_date.isoformat() if data and data.score_date else None

    def _kev_version(self) -> str | None:
        catalog = self.kev_service.catalog if self.kev_service else None
        return f"{catalog.catalog_version}:{catalog.total_count}" if catalog else None

    def mark_enrichment_current(self, state: SyncState) -> None:
        """Record that every indexed CVE has the currently loaded EPSS and KEV data.

        Call this after a successful complete scan.
        """
        if version := self._epss_version():
            state.set(EPSS_STATE_KEY, version)
        if version := self._kev_version():
            state.set(KEV_STATE_KEY, version)

    def refresh_stale_enrichment(self, state: SyncState) -> int:
        """Re-apply EPSS and KEV data to indexed CVEs when a new feed release is loaded.

        Incremental syncs only re-index CVEs whose records changed, but EPSS scores
        change daily and KEV adds older CVEs. This writes the new values to every
        indexed CVE, once per feed release.

        Returns:
            Number of documents updated.
        """
        return self._refresh_epss(state) + self._refresh_kev(state)

    def _refresh_epss(self, state: SyncState) -> int:
        version = self._epss_version()
        if not (self.epss_service and self.epss_service.data and version):
            return 0
        if state.get(EPSS_STATE_KEY) == version:
            return 0

        self.report(f"Refreshing EPSS scores from {version}...")
        scores = self.epss_service.data.scores
        updated, errors = self.es_service.bulk_update_cves(
            (cve_id, score.to_es_fields()) for cve_id, score in scores.items()
        )
        if errors == 0:
            state.set(EPSS_STATE_KEY, version)
        else:
            logger.warning(f"EPSS refresh had {errors} errors; will retry next sync")
        return updated

    def _refresh_kev(self, state: SyncState) -> int:
        version = self._kev_version()
        if not (self.kev_service and self.kev_service.catalog and version):
            return 0
        if state.get(KEV_STATE_KEY) == version:
            return 0

        self.report("Refreshing KEV status...")
        entries = self.kev_service.catalog.entries
        updated, errors = self.es_service.bulk_update_cves(
            (cve_id, entry.to_es_fields()) for cve_id, entry in entries.items()
        )
        updated += self.es_service.clear_kev_except(entries.keys())
        if errors == 0:
            state.set(KEV_STATE_KEY, version)
        else:
            logger.warning(f"KEV refresh had {errors} errors; will retry next sync")
        return updated
