"""EPSS (Exploit Prediction Scoring System) service.

Fetches EPSS scores from the FIRST.org EPSS API/data feed.
EPSS provides probability scores for CVE exploitation within 30 days.

Data source: https://www.first.org/epss/
"""

import contextlib
import csv
import gzip
import io
from datetime import date
from typing import Any

from loguru import logger

from cvelk.config import Settings
from cvelk.models.epss import EPSSData, EPSSScore
from cvelk.utils.http_client import (
    RetryableHTTPError,
    create_http_client,
    create_retry_decorator,
)


class EPSSService:
    """Service for fetching and processing EPSS data.

    Downloads the daily EPSS scores CSV and provides methods
    to look up scores and enrich CVE data.
    """

    def __init__(self, settings: Settings):
        """Initialize EPSS service.

        Args:
            settings: Application settings.
        """
        self.settings = settings
        self.url = settings.epss.url
        self._data: EPSSData | None = None

    @property
    def data(self) -> EPSSData | None:
        """Get cached EPSS data."""
        return self._data

    @create_retry_decorator(max_attempts=3, min_wait=5, max_wait=30)  # type: ignore[misc]
    async def fetch(self) -> EPSSData:
        """Fetch and parse EPSS scores from the data feed.

        Returns:
            EPSSData containing all scores.
        """
        logger.info(f"Fetching EPSS data from {self.url}")

        async with create_http_client(timeout=self.settings.epss.timeout) as client:
            response = await client.get(self.url)

            if response.status_code != 200:
                raise RetryableHTTPError(
                    f"Failed to fetch EPSS data: HTTP {response.status_code}",
                    response.status_code,
                )

            # Decompress if gzipped
            content = response.content
            if self.url.endswith(".gz"):
                content = gzip.decompress(content)

            # Parse CSV
            scores = self._parse_csv(content.decode("utf-8"))
            self._data = scores

            logger.info(f"Loaded {scores.total_count} EPSS scores")
            return scores

    def _parse_csv(self, content: str) -> EPSSData:
        """Parse EPSS CSV content.

        The EPSS CSV has a header comment line followed by:
        cve,epss,percentile

        Args:
            content: CSV file content as string.

        Returns:
            EPSSData with parsed scores.
        """
        scores: dict[str, EPSSScore] = {}
        model_version = ""
        score_date: date | None = None

        reader = csv.reader(io.StringIO(content))

        for row in reader:
            # Skip empty rows
            if not row:
                continue

            # Parse header comment (first line starting with #)
            if row[0].startswith("#"):
                # Extract model version and date from comment
                # Format: # model_version:v2023.03.01,score_date:2024-01-15
                header = row[0].lstrip("# ")
                for part in header.split(","):
                    if ":" in part:
                        key, value = part.split(":", 1)
                        if key == "model_version":
                            model_version = value
                        elif key == "score_date":
                            with contextlib.suppress(ValueError):
                                score_date = date.fromisoformat(value)
                continue

            # Skip header row
            if row[0] == "cve":
                continue

            # Parse data row
            if len(row) >= 3:
                try:
                    cve_id = row[0].upper()
                    scores[cve_id] = EPSSScore(
                        cve_id=cve_id,
                        score=float(row[1]),
                        percentile=float(row[2]),
                        model_version=model_version,
                        score_date=score_date,
                    )
                except (ValueError, IndexError) as e:
                    logger.debug(f"Failed to parse EPSS row {row}: {e}")
                    continue

        return EPSSData(
            scores=scores,
            model_version=model_version,
            score_date=score_date,
            total_count=len(scores),
        )

    def get_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a specific CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            EPSSScore if found and data is loaded, None otherwise.
        """
        if self._data:
            return self._data.get_score(cve_id)
        return None

    def enrich_cve(self, cve: Any) -> None:
        """Enrich a CVE object with EPSS data.

        Args:
            cve: CVE model instance to enrich.
        """
        if self._data:
            self._data.enrich_cve(cve)

    def get_top_scores(self, limit: int = 100) -> list[EPSSScore]:
        """Get CVEs with highest EPSS scores.

        Args:
            limit: Maximum number of results.

        Returns:
            List of EPSSScore instances sorted by score descending.
        """
        if not self._data:
            return []

        sorted_scores = sorted(
            self._data.scores.values(),
            key=lambda x: x.score,
            reverse=True,
        )
        return sorted_scores[:limit]

    async def get_stats(self) -> dict[str, Any]:
        """Get statistics about EPSS data.

        Returns:
            Dictionary with statistics.
        """
        if not self._data:
            await self.fetch()

        if not self._data:
            return {}

        scores = list(self._data.scores.values())
        if not scores:
            return {}

        return {
            "total_count": self._data.total_count,
            "model_version": self._data.model_version,
            "score_date": self._data.score_date.isoformat() if self._data.score_date else None,
            "avg_score": sum(s.score for s in scores) / len(scores),
            "max_score": max(s.score for s in scores),
            "min_score": min(s.score for s in scores),
        }
