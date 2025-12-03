"""CISA Known Exploited Vulnerabilities (KEV) data models."""

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class KEVEntry(BaseModel):
    """Single entry in the CISA KEV catalog.

    The KEV catalog contains vulnerabilities that are known to be
    actively exploited in the wild.
    """

    cve_id: str = Field(..., description="CVE identifier")
    vendor_project: str = Field(..., description="Vendor or project name")
    product: str = Field(..., description="Affected product name")
    vulnerability_name: str = Field(..., description="Vulnerability name/title")
    date_added: date = Field(..., description="Date added to KEV catalog")
    short_description: str = Field(..., description="Brief vulnerability description")
    required_action: str = Field(..., description="Required remediation action")
    due_date: date = Field(..., description="Federal agency remediation due date")
    known_ransomware_campaign_use: bool = Field(
        default=False,
        description="Known to be used in ransomware campaigns",
    )
    notes: str = Field(default="", description="Additional notes")

    @field_validator("cve_id", mode="before")
    @classmethod
    def normalize_cve_id(cls, v: str) -> str:
        """Normalize CVE ID to uppercase."""
        return v.upper() if v else v

    @field_validator("date_added", "due_date", mode="before")
    @classmethod
    def parse_date(cls, v: str | date) -> date:
        """Parse date string to date object."""
        if isinstance(v, date):
            return v
        if isinstance(v, str):
            return datetime.strptime(v, "%Y-%m-%d").date()
        raise ValueError(f"Cannot parse date: {v}")

    @field_validator("known_ransomware_campaign_use", mode="before")
    @classmethod
    def parse_ransomware_use(cls, v: str | bool) -> bool:
        """Parse ransomware use field."""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() == "known"
        return False

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "KEVEntry":
        """Create KEVEntry from CISA API response data.

        Args:
            data: Single vulnerability entry from KEV JSON.

        Returns:
            KEVEntry instance.
        """
        return cls(
            cve_id=data.get("cveID", ""),
            vendor_project=data.get("vendorProject", ""),
            product=data.get("product", ""),
            vulnerability_name=data.get("vulnerabilityName", ""),
            date_added=data.get("dateAdded", "2000-01-01"),
            short_description=data.get("shortDescription", ""),
            required_action=data.get("requiredAction", ""),
            due_date=data.get("dueDate", "2000-01-01"),
            known_ransomware_campaign_use=data.get("knownRansomwareCampaignUse", "Unknown"),
            notes=data.get("notes", ""),
        )


class KEVCatalog(BaseModel):
    """CISA KEV catalog container."""

    title: str = Field(default="", description="Catalog title")
    catalog_version: str = Field(default="", description="Catalog version")
    date_released: datetime | None = Field(
        default=None,
        description="Catalog release date",
    )
    entries: dict[str, KEVEntry] = Field(
        default_factory=dict,
        description="CVE ID to KEV entry mapping",
    )
    total_count: int = Field(
        default=0,
        description="Total number of KEV entries",
    )

    @field_validator("date_released", mode="before")
    @classmethod
    def parse_datetime(cls, v: str | datetime | None) -> datetime | None:
        """Parse datetime string."""
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return None

    def get_entry(self, cve_id: str) -> KEVEntry | None:
        """Get KEV entry for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            KEVEntry if found, None otherwise.
        """
        return self.entries.get(cve_id.upper())

    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier.

        Returns:
            True if CVE is in KEV catalog.
        """
        return cve_id.upper() in self.entries

    def enrich_cve(self, cve: Any) -> None:
        """Enrich a CVE object with KEV data.

        Args:
            cve: CVE model instance to enrich.
        """
        if entry := self.get_entry(cve.cve_id):
            cve.is_kev = True
            cve.kev_date_added = datetime.combine(entry.date_added, datetime.min.time())
            cve.kev_due_date = datetime.combine(entry.due_date, datetime.min.time())
            cve.kev_ransomware_use = entry.known_ransomware_campaign_use

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "KEVCatalog":
        """Create KEVCatalog from CISA API response.

        Args:
            data: Full KEV catalog JSON response.

        Returns:
            KEVCatalog instance.
        """
        entries: dict[str, KEVEntry] = {}
        for vuln in data.get("vulnerabilities", []):
            entry = KEVEntry.from_api(vuln)
            entries[entry.cve_id] = entry

        return cls(
            title=data.get("title", ""),
            catalog_version=data.get("catalogVersion", ""),
            date_released=data.get("dateReleased"),
            entries=entries,
            total_count=len(entries),
        )
