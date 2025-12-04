"""CISA Known Exploited Vulnerabilities (KEV) service.

Fetches the KEV catalog which contains vulnerabilities that are
actively being exploited in the wild.

Data source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from datetime import date, timedelta
from typing import Any

from loguru import logger

from cvelk.config import Settings
from cvelk.models.kev import KEVCatalog, KEVEntry
from cvelk.utils.http_client import (
    RetryableHTTPError,
    create_http_client,
    create_retry_decorator,
)


class KEVService:
    """Service for fetching and processing CISA KEV data.

    The KEV catalog is updated frequently and contains vulnerabilities
    that federal agencies are required to remediate within specific timeframes.
    """

    def __init__(self, settings: Settings):
        """Initialize KEV service.

        Args:
            settings: Application settings.
        """
        self.settings = settings
        self.url = settings.kev.url
        self._catalog: KEVCatalog | None = None

    @property
    def catalog(self) -> KEVCatalog | None:
        """Get cached KEV catalog."""
        return self._catalog

    @create_retry_decorator(max_attempts=3, min_wait=5, max_wait=30)  # type: ignore[misc, untyped-decorator]
    async def fetch(self) -> KEVCatalog:
        """Fetch and parse the KEV catalog.

        Returns:
            KEVCatalog containing all entries.
        """
        logger.info(f"Fetching CISA KEV catalog from {self.url}")

        async with create_http_client(timeout=self.settings.kev.timeout) as client:
            response = await client.get(self.url)

            if response.status_code != 200:
                raise RetryableHTTPError(
                    f"Failed to fetch KEV catalog: HTTP {response.status_code}",
                    response.status_code,
                )

            data = response.json()
            self._catalog = KEVCatalog.from_api(data)

            logger.info(f"Loaded {self._catalog.total_count} KEV entries")
            return self._catalog

    def get_entry(self, cve_id: str) -> KEVEntry | None:
        """Get KEV entry for a specific CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            KEVEntry if found and catalog is loaded, None otherwise.
        """
        if self._catalog:
            return self._catalog.get_entry(cve_id)
        return None

    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier.

        Returns:
            True if CVE is in KEV catalog and catalog is loaded.
        """
        if self._catalog:
            return self._catalog.is_kev(cve_id)
        return False

    def enrich_cve(self, cve: Any) -> None:
        """Enrich a CVE object with KEV data.

        Args:
            cve: CVE model instance to enrich.
        """
        if self._catalog:
            self._catalog.enrich_cve(cve)

    def get_ransomware_cves(self) -> list[KEVEntry]:
        """Get all CVEs known to be used in ransomware campaigns.

        Returns:
            List of KEV entries with ransomware association.
        """
        if not self._catalog:
            return []

        return [
            entry for entry in self._catalog.entries.values() if entry.known_ransomware_campaign_use
        ]

    def get_overdue(self) -> list[KEVEntry]:
        """Get all KEV entries past their due date.

        Returns:
            List of overdue KEV entries.
        """
        if not self._catalog:
            return []

        today = date.today()
        return [entry for entry in self._catalog.entries.values() if entry.due_date < today]

    def get_recent(self, days: int = 30) -> list[KEVEntry]:
        """Get KEV entries added in the last N days.

        Args:
            days: Number of days to look back.

        Returns:
            List of recent KEV entries.
        """
        if not self._catalog:
            return []

        cutoff = date.today() - timedelta(days=days)
        return [entry for entry in self._catalog.entries.values() if entry.date_added >= cutoff]

    async def get_stats(self) -> dict[str, Any]:
        """Get statistics about KEV data.

        Returns:
            Dictionary with statistics.
        """
        if not self._catalog:
            await self.fetch()

        if not self._catalog:
            return {}

        entries = list(self._catalog.entries.values())
        ransomware_count = sum(1 for e in entries if e.known_ransomware_campaign_use)

        return {
            "total_count": self._catalog.total_count,
            "catalog_version": self._catalog.catalog_version,
            "date_released": (
                self._catalog.date_released.isoformat() if self._catalog.date_released else None
            ),
            "ransomware_associated": ransomware_count,
            "unique_vendors": len({e.vendor_project for e in entries}),
            "unique_products": len({e.product for e in entries}),
        }
