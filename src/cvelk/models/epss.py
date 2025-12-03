"""EPSS (Exploit Prediction Scoring System) data models."""

from datetime import date
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EPSSScore(BaseModel):
    """EPSS score for a single CVE.

    EPSS provides a probability score (0-1) indicating the likelihood
    that a vulnerability will be exploited in the wild within the next 30 days.
    """

    cve_id: str = Field(..., description="CVE identifier")
    score: float = Field(
        ...,
        ge=0,
        le=1,
        description="EPSS probability score (0-1)",
    )
    percentile: float = Field(
        ...,
        ge=0,
        le=1,
        description="EPSS percentile ranking (0-1)",
    )
    model_version: str = Field(
        default="",
        description="EPSS model version used for scoring",
    )
    score_date: date | None = Field(
        default=None,
        description="Date the score was calculated",
    )

    @property
    def score_percentage(self) -> float:
        """Get EPSS score as a percentage (0-100)."""
        return round(self.score * 100, 4)

    @property
    def percentile_percentage(self) -> float:
        """Get EPSS percentile as a percentage (0-100)."""
        return round(self.percentile * 100, 2)

    @field_validator("cve_id", mode="before")
    @classmethod
    def normalize_cve_id(cls, v: str) -> str:
        """Normalize CVE ID to uppercase."""
        return v.upper() if v else v

    @classmethod
    def from_csv_row(cls, row: dict[str, Any]) -> "EPSSScore":
        """Create EPSSScore from a CSV row.

        Args:
            row: Dictionary with 'cve', 'epss', and 'percentile' keys.

        Returns:
            EPSSScore instance.
        """
        return cls(
            cve_id=row.get("cve", ""),
            score=float(row.get("epss", 0)),
            percentile=float(row.get("percentile", 0)),
        )


class EPSSData(BaseModel):
    """Container for EPSS data with metadata."""

    scores: dict[str, EPSSScore] = Field(
        default_factory=dict,
        description="CVE ID to EPSS score mapping",
    )
    model_version: str = Field(
        default="",
        description="EPSS model version",
    )
    score_date: date | None = Field(
        default=None,
        description="Date scores were calculated",
    )
    total_count: int = Field(
        default=0,
        description="Total number of CVEs with EPSS scores",
    )

    def get_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            EPSSScore if found, None otherwise.
        """
        return self.scores.get(cve_id.upper())

    def enrich_cve(self, cve: Any) -> None:
        """Enrich a CVE object with EPSS data.

        Args:
            cve: CVE model instance to enrich.
        """
        if score := self.get_score(cve.cve_id):
            cve.epss_score = score.score_percentage
            cve.epss_percentile = score.percentile_percentage
