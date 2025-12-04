"""NVD 2.0 API service for fetching CVE data.

This service implements the NVD 2.0 API with proper rate limiting,
pagination, and retry logic.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import httpx
from loguru import logger

from cvelk.config import Settings
from cvelk.models.cve import CVE
from cvelk.utils.http_client import (
    RateLimiter,
    create_http_client,
    create_retry_decorator,
    handle_response,
)


class NVDService:
    """Service for interacting with the NVD 2.0 API.

    Handles CVE data fetching with:
    - Automatic pagination
    - Rate limiting (5 req/30s without API key, 50 req/30s with)
    - Retry logic with exponential backoff
    - Incremental updates using last modified dates
    """

    def __init__(self, settings: Settings):
        """Initialize NVD service.

        Args:
            settings: Application settings.
        """
        self.settings = settings
        self.base_url = settings.nvd.base_url

        # Determine rate limit based on API key presence
        rate_limit = 50 if settings.nvd.api_key else 5
        self.rate_limiter = RateLimiter(
            requests_per_window=rate_limit,
            window_seconds=30,
        )

        # Build headers
        self.headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "CVElk/2.0 (https://github.com/jgamblin/CVElk)",
        }
        if settings.nvd.api_key:
            self.headers["apiKey"] = settings.nvd.api_key.get_secret_value()

        self._retry = create_retry_decorator()

    async def fetch_cves(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        cve_id: str | None = None,
        keyword: str | None = None,
        results_per_page: int | None = None,
    ) -> AsyncGenerator[CVE, None]:
        """Fetch CVEs from NVD API with automatic pagination.

        Args:
            start_date: Filter CVEs modified after this date.
            end_date: Filter CVEs modified before this date.
            cve_id: Fetch a specific CVE by ID.
            keyword: Search CVEs by keyword in description.
            results_per_page: Number of results per API page.

        Yields:
            CVE instances parsed from API responses.
        """
        params = self._build_params(
            start_date=start_date,
            end_date=end_date,
            cve_id=cve_id,
            keyword=keyword,
            results_per_page=results_per_page,
        )

        start_index = 0
        total_results = None

        async with create_http_client(timeout=self.settings.nvd.timeout) as client:
            while True:
                params["startIndex"] = start_index
                data = await self._fetch_page(client, params)

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info(f"NVD API reports {total_results} total CVEs matching criteria")

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    try:
                        cve = CVE.from_nvd_api(vuln)
                        yield cve
                    except Exception as e:
                        cve_id_str = vuln.get("cve", {}).get("id", "unknown")
                        logger.error(f"Failed to parse CVE {cve_id_str}: {e}")
                        continue

                start_index += len(vulnerabilities)
                logger.info(f"Fetched {start_index}/{total_results} CVEs")

                # Check if we've fetched all results
                if start_index >= total_results:
                    break

    async def fetch_cve(self, cve_id: str) -> CVE | None:
        """Fetch a single CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-12345).

        Returns:
            CVE instance if found, None otherwise.
        """
        async for cve in self.fetch_cves(cve_id=cve_id):
            return cve
        return None

    async def fetch_recent(self, days: int = 7) -> AsyncGenerator[CVE, None]:
        """Fetch CVEs modified in the last N days.

        Args:
            days: Number of days to look back.

        Yields:
            CVE instances.
        """
        end_date = datetime.now(UTC)
        start_date = datetime.fromtimestamp(
            end_date.timestamp() - (days * 24 * 60 * 60),
            tz=UTC,
        )

        async for cve in self.fetch_cves(start_date=start_date, end_date=end_date):
            yield cve

    async def fetch_all(self) -> AsyncGenerator[CVE, None]:
        """Fetch all CVEs from NVD.

        Warning: This can take a very long time and make many API requests.

        Yields:
            CVE instances.
        """
        logger.warning("Fetching ALL CVEs from NVD. This may take several hours.")
        async for cve in self.fetch_cves():
            yield cve

    def _build_params(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        cve_id: str | None = None,
        keyword: str | None = None,
        results_per_page: int | None = None,
    ) -> dict[str, Any]:
        """Build query parameters for NVD API request.

        Args:
            start_date: Filter by modification date start.
            end_date: Filter by modification date end.
            cve_id: Specific CVE ID to fetch.
            keyword: Keyword search in description.
            results_per_page: Results per page.

        Returns:
            Dictionary of query parameters.
        """
        params: dict[str, Any] = {
            "resultsPerPage": results_per_page or self.settings.nvd.results_per_page,
        }

        if cve_id:
            params["cveId"] = cve_id.upper()

        if keyword:
            params["keywordSearch"] = keyword

        # NVD API requires ISO 8601 format with timezone (Z suffix for UTC)
        if start_date:
            params["lastModStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if end_date:
            params["lastModEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        return params

    @create_retry_decorator()  # type: ignore[misc]
    async def _fetch_page(
        self,
        client: httpx.AsyncClient,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Fetch a single page of results from NVD API.

        Args:
            client: HTTP client instance.
            params: Query parameters.

        Returns:
            Parsed JSON response.
        """
        await self.rate_limiter.acquire()

        logger.debug(f"Fetching NVD page with params: {params}")
        response = await client.get(
            self.base_url,
            params=params,
            headers=self.headers,
        )

        return await handle_response(response)

    async def get_stats(self) -> dict[str, Any]:
        """Get statistics about available CVE data.

        Returns:
            Dictionary with total CVE count and date range.
        """
        params = {"resultsPerPage": 1}

        async with create_http_client(timeout=self.settings.nvd.timeout) as client:
            data = await self._fetch_page(client, params)

            return {
                "total_cves": data.get("totalResults", 0),
                "format": data.get("format", ""),
                "version": data.get("version", ""),
                "timestamp": data.get("timestamp", ""),
            }
