"""CVE data models following NVD CVE 2.0 API schema."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class CVSSVersion(StrEnum):
    """CVSS version enumeration."""

    V2 = "2.0"
    V30 = "3.0"
    V31 = "3.1"
    V40 = "4.0"


class Severity(StrEnum):
    """CVSS severity levels."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackVector(StrEnum):
    """CVSS Attack Vector values."""

    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class AttackComplexity(StrEnum):
    """CVSS Attack Complexity values."""

    LOW = "LOW"
    HIGH = "HIGH"


class PrivilegesRequired(StrEnum):
    """CVSS Privileges Required values."""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class UserInteraction(StrEnum):
    """CVSS User Interaction values."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"


class Scope(StrEnum):
    """CVSS Scope values."""

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"


class Impact(StrEnum):
    """CVSS Impact values for CIA triad."""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class CVSSMetrics(BaseModel):
    """CVSS metrics model supporting v2.0, v3.0, v3.1, and v4.0."""

    version: CVSSVersion
    vector_string: str = Field(..., description="CVSS vector string")
    base_score: float = Field(..., ge=0, le=10, description="CVSS base score")
    base_severity: Severity = Field(..., description="CVSS severity rating")

    # CVSS v3.x specific metrics
    attack_vector: AttackVector | None = None
    attack_complexity: AttackComplexity | None = None
    privileges_required: PrivilegesRequired | None = None
    user_interaction: UserInteraction | None = None
    scope: Scope | None = None
    confidentiality_impact: Impact | None = None
    integrity_impact: Impact | None = None
    availability_impact: Impact | None = None

    # Derived scores
    exploitability_score: float | None = Field(default=None, ge=0, le=10)
    impact_score: float | None = Field(default=None, ge=0, le=10)

    @field_validator("base_score", mode="before")
    @classmethod
    def round_base_score(cls, v: float) -> float:
        """Round base score to one decimal place."""
        return round(float(v), 1)

    @classmethod
    def from_nvd_v3(cls, data: dict[str, Any]) -> "CVSSMetrics":
        """Create CVSSMetrics from NVD API v3.x CVSS data."""
        cvss_data = data.get("cvssData", data)
        return cls(
            version=CVSSVersion(cvss_data.get("version", "3.1")),
            vector_string=cvss_data.get("vectorString", ""),
            base_score=cvss_data.get("baseScore", 0.0),
            base_severity=Severity(cvss_data.get("baseSeverity", "NONE")),
            attack_vector=AttackVector(cvss_data["attackVector"])
            if cvss_data.get("attackVector")
            else None,
            attack_complexity=AttackComplexity(cvss_data["attackComplexity"])
            if cvss_data.get("attackComplexity")
            else None,
            privileges_required=PrivilegesRequired(cvss_data["privilegesRequired"])
            if cvss_data.get("privilegesRequired")
            else None,
            user_interaction=UserInteraction(cvss_data["userInteraction"])
            if cvss_data.get("userInteraction")
            else None,
            scope=Scope(cvss_data["scope"]) if cvss_data.get("scope") else None,
            confidentiality_impact=Impact(cvss_data["confidentialityImpact"])
            if cvss_data.get("confidentialityImpact")
            else None,
            integrity_impact=Impact(cvss_data["integrityImpact"])
            if cvss_data.get("integrityImpact")
            else None,
            availability_impact=Impact(cvss_data["availabilityImpact"])
            if cvss_data.get("availabilityImpact")
            else None,
            exploitability_score=data.get("exploitabilityScore"),
            impact_score=data.get("impactScore"),
        )


class Weakness(BaseModel):
    """CWE weakness information."""

    cwe_id: str = Field(..., description="CWE identifier (e.g., CWE-79)")
    description: str = Field(default="", description="CWE description")

    @field_validator("cwe_id", mode="before")
    @classmethod
    def normalize_cwe_id(cls, v: str) -> str:
        """Normalize CWE ID format."""
        if v and not v.upper().startswith("CWE-"):
            return f"CWE-{v}"
        return v.upper() if v else "CWE-UNKNOWN"


class Reference(BaseModel):
    """CVE reference link."""

    url: str = Field(..., description="Reference URL")
    source: str = Field(default="", description="Reference source")
    tags: list[str] = Field(default_factory=list, description="Reference tags")


class CVE(BaseModel):
    """Complete CVE record model for NVD 2.0 API."""

    # Core identifiers
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-12345)")
    source_identifier: str = Field(default="", description="Source that identified the CVE")

    # Timestamps
    published: datetime = Field(..., description="CVE publication date")
    last_modified: datetime = Field(..., description="Last modification date")

    # Status
    vuln_status: str = Field(default="", description="Vulnerability status")

    # Description
    description: str = Field(..., description="CVE description in English")

    # CVSS Metrics
    cvss_v2: CVSSMetrics | None = Field(default=None, description="CVSS v2.0 metrics")
    cvss_v3: CVSSMetrics | None = Field(default=None, description="CVSS v3.x metrics")
    cvss_v4: CVSSMetrics | None = Field(default=None, description="CVSS v4.0 metrics")

    weaknesses: list[Weakness] = Field(default_factory=list, description="Associated CWE IDs")

    # References
    references: list[Reference] = Field(default_factory=list, description="Reference links")

    # EPSS enrichment (populated separately)
    epss_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="EPSS score as percentage",
    )
    epss_percentile: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="EPSS percentile as percentage",
    )

    # KEV enrichment (populated separately)
    is_kev: bool = Field(
        default=False,
        description="Whether this CVE is in CISA KEV catalog",
    )
    kev_date_added: datetime | None = Field(
        default=None,
        description="Date added to KEV catalog",
    )
    kev_due_date: datetime | None = Field(
        default=None,
        description="KEV remediation due date",
    )
    kev_ransomware_use: bool = Field(
        default=False,
        description="Known ransomware campaign use",
    )

    @property
    def primary_cvss(self) -> CVSSMetrics | None:
        """Get the primary (highest version) CVSS metrics."""
        return self.cvss_v4 or self.cvss_v3 or self.cvss_v2

    @property
    def base_score(self) -> float:
        """Get the primary CVSS base score."""
        if cvss := self.primary_cvss:
            return cvss.base_score
        return 0.0

    @property
    def severity(self) -> str:
        """Get the primary CVSS severity."""
        if cvss := self.primary_cvss:
            return cvss.base_severity.value
        return "NONE"

    @property
    def primary_cwe(self) -> str:
        """Get the primary CWE ID."""
        if self.weaknesses:
            return self.weaknesses[0].cwe_id
        return "CWE-UNKNOWN"

    @staticmethod
    def _extract_description(cve_data: dict[str, Any]) -> str:
        """Extract English description from CVE data."""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                return str(desc.get("value", ""))
        descriptions = cve_data.get("descriptions", [])
        return str(descriptions[0].get("value", "")) if descriptions else ""

    @staticmethod
    def _extract_cvss_v2(metrics: dict[str, Any]) -> "CVSSMetrics | None":
        """Extract CVSS v2 metrics from NVD data."""
        for v2_data in metrics.get("cvssMetricV2", []):
            cvss_data = v2_data.get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            # Map v2 severity based on score
            severity = (
                Severity.HIGH
                if base_score >= 7.0
                else Severity.MEDIUM
                if base_score >= 4.0
                else Severity.LOW
            )
            return CVSSMetrics(
                version=CVSSVersion.V2,
                vector_string=cvss_data.get("vectorString", ""),
                base_score=base_score,
                base_severity=severity,
                exploitability_score=v2_data.get("exploitabilityScore"),
                impact_score=v2_data.get("impactScore"),
            )
        return None

    @staticmethod
    def _extract_cvss_v3(metrics: dict[str, Any]) -> "CVSSMetrics | None":
        """Extract CVSS v3.x metrics from NVD data."""
        v3_list = metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", [])
        for v3_data in v3_list:
            return CVSSMetrics.from_nvd_v3(v3_data)
        return None

    @staticmethod
    def _extract_cvss_v4(metrics: dict[str, Any]) -> "CVSSMetrics | None":
        """Extract CVSS v4.0 metrics from NVD data."""
        for v4_data in metrics.get("cvssMetricV40", []):
            cvss_data = v4_data.get("cvssData", {})
            return CVSSMetrics(
                version=CVSSVersion.V40,
                vector_string=cvss_data.get("vectorString", ""),
                base_score=cvss_data.get("baseScore", 0.0),
                base_severity=Severity(cvss_data.get("baseSeverity", "NONE")),
            )
        return None

    @staticmethod
    def _extract_weaknesses(cve_data: dict[str, Any]) -> list["Weakness"]:
        """Extract CWE weaknesses from CVE data."""
        weaknesses: list[Weakness] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value"):
                    weaknesses.append(Weakness(cwe_id=desc["value"], description=""))
        return weaknesses

    @staticmethod
    def _extract_references(cve_data: dict[str, Any]) -> list["Reference"]:
        """Extract references from CVE data."""
        return [
            Reference(
                url=ref.get("url", ""),
                source=ref.get("source", ""),
                tags=ref.get("tags", []),
            )
            for ref in cve_data.get("references", [])
        ]

    @classmethod
    def from_nvd_api(cls, data: dict[str, Any]) -> "CVE":
        """Create CVE from NVD 2.0 API response data.

        Args:
            data: Single vulnerability item from NVD API response.

        Returns:
            CVE instance populated from API data.
        """
        cve_data = data.get("cve", data)
        metrics = cve_data.get("metrics", {})

        return cls(
            cve_id=cve_data.get("id", ""),
            source_identifier=cve_data.get("sourceIdentifier", ""),
            published=datetime.fromisoformat(
                cve_data.get("published", "2000-01-01T00:00:00.000").replace("Z", "+00:00")
            ),
            last_modified=datetime.fromisoformat(
                cve_data.get("lastModified", "2000-01-01T00:00:00.000").replace("Z", "+00:00")
            ),
            vuln_status=cve_data.get("vulnStatus", ""),
            description=cls._extract_description(cve_data),
            cvss_v2=cls._extract_cvss_v2(metrics),
            cvss_v3=cls._extract_cvss_v3(metrics),
            cvss_v4=cls._extract_cvss_v4(metrics),
            weaknesses=cls._extract_weaknesses(cve_data),
            references=cls._extract_references(cve_data),
        )

    @classmethod
    def from_cve_v5(cls, data: dict[str, Any]) -> "CVE":  # noqa: PLR0912
        """Create CVE from CVE JSON 5.x format (CVE List V5 repository).

        Args:
            data: CVE JSON 5.x record from CVE List V5 repository.

        Returns:
            CVE instance populated from CVE V5 data.
        """
        metadata = data.get("cveMetadata", {})
        cve_id = metadata.get("cveId", "")
        state = metadata.get("state", "")

        # Parse dates with fallback
        def parse_date(date_str: str | None) -> datetime:
            if not date_str:
                return datetime(2000, 1, 1, tzinfo=None)
            try:
                # Handle various ISO formats
                date_str = date_str.replace("Z", "+00:00")
                return datetime.fromisoformat(date_str)
            except ValueError:
                return datetime(2000, 1, 1, tzinfo=None)

        published = parse_date(metadata.get("datePublished"))
        last_modified = parse_date(metadata.get("dateUpdated") or metadata.get("datePublished"))

        # Skip non-published CVEs with minimal data
        if state != "PUBLISHED":
            return cls(
                cve_id=cve_id,
                source_identifier=metadata.get("assignerShortName", ""),
                published=published,
                last_modified=last_modified,
                vuln_status=state,
                description=f"CVE {state}",
            )

        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        adp_list = containers.get("adp", [])

        # Extract description from CNA
        description = ""
        for desc in cna.get("descriptions", []):
            if desc.get("lang", "").startswith("en"):
                description = desc.get("value", "")
                break
        if not description:
            descriptions = cna.get("descriptions", [])
            if descriptions:
                description = descriptions[0].get("value", "")

        # Extract CVSS metrics from CNA and ADP containers
        cvss_v3 = cls._extract_cvss_v3_from_v5(cna)
        cvss_v4 = cls._extract_cvss_v4_from_v5(cna)

        # Try ADP containers if CNA doesn't have CVSS
        for adp in adp_list:
            if not cvss_v3:
                cvss_v3 = cls._extract_cvss_v3_from_v5(adp)
            if not cvss_v4:
                cvss_v4 = cls._extract_cvss_v4_from_v5(adp)

        # Extract weaknesses from CNA and ADP
        weaknesses = cls._extract_weaknesses_from_v5(cna)
        for adp in adp_list:
            adp_weaknesses = cls._extract_weaknesses_from_v5(adp)
            for w in adp_weaknesses:
                if not any(existing.cwe_id == w.cwe_id for existing in weaknesses):
                    weaknesses.append(w)

        # Extract references from CNA and ADP
        references = cls._extract_references_from_v5(cna)
        for adp in adp_list:
            adp_refs = cls._extract_references_from_v5(adp)
            for r in adp_refs:
                if not any(existing.url == r.url for existing in references):
                    references.append(r)

        return cls(
            cve_id=cve_id,
            source_identifier=metadata.get("assignerShortName", ""),
            published=published,
            last_modified=last_modified,
            vuln_status="Published",  # Normalize status
            description=description,
            cvss_v3=cvss_v3,
            cvss_v4=cvss_v4,
            weaknesses=weaknesses,
            references=references,
        )

    @staticmethod
    def _extract_cvss_v3_from_v5(container: dict[str, Any]) -> "CVSSMetrics | None":
        """Extract CVSS v3.x metrics from CVE V5 container.

        Args:
            container: CNA or ADP container data.

        Returns:
            CVSSMetrics if found, None otherwise.
        """
        for metric in container.get("metrics", []):
            cvss_data = None
            version = "3.1"

            if "cvssV3_1" in metric:
                cvss_data = metric["cvssV3_1"]
                version = "3.1"
            elif "cvssV3_0" in metric:
                cvss_data = metric["cvssV3_0"]
                version = "3.0"
            elif "cvssV3" in metric:
                # Some records use generic cvssV3 key
                cvss_data = metric["cvssV3"]
                version = cvss_data.get("version", "3.1")

            if cvss_data:
                base_severity = cvss_data.get("baseSeverity", "NONE").upper()
                if base_severity not in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    base_severity = "NONE"

                return CVSSMetrics(
                    version=CVSSVersion(version),
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=float(cvss_data.get("baseScore", 0.0)),
                    base_severity=Severity(base_severity),
                    attack_vector=AttackVector(cvss_data["attackVector"])
                    if cvss_data.get("attackVector")
                    else None,
                    attack_complexity=AttackComplexity(cvss_data["attackComplexity"])
                    if cvss_data.get("attackComplexity")
                    else None,
                    privileges_required=PrivilegesRequired(cvss_data["privilegesRequired"])
                    if cvss_data.get("privilegesRequired")
                    else None,
                    user_interaction=UserInteraction(cvss_data["userInteraction"])
                    if cvss_data.get("userInteraction")
                    else None,
                    scope=Scope(cvss_data["scope"]) if cvss_data.get("scope") else None,
                    confidentiality_impact=Impact(cvss_data["confidentialityImpact"])
                    if cvss_data.get("confidentialityImpact")
                    else None,
                    integrity_impact=Impact(cvss_data["integrityImpact"])
                    if cvss_data.get("integrityImpact")
                    else None,
                    availability_impact=Impact(cvss_data["availabilityImpact"])
                    if cvss_data.get("availabilityImpact")
                    else None,
                )
        return None

    @staticmethod
    def _extract_cvss_v4_from_v5(container: dict[str, Any]) -> "CVSSMetrics | None":
        """Extract CVSS v4.0 metrics from CVE V5 container.

        Args:
            container: CNA or ADP container data.

        Returns:
            CVSSMetrics if found, None otherwise.
        """
        for metric in container.get("metrics", []):
            if "cvssV4_0" in metric:
                cvss_data = metric["cvssV4_0"]
                base_severity = cvss_data.get("baseSeverity", "NONE").upper()
                if base_severity not in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    base_severity = "NONE"

                return CVSSMetrics(
                    version=CVSSVersion.V40,
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=float(cvss_data.get("baseScore", 0.0)),
                    base_severity=Severity(base_severity),
                )
        return None

    @staticmethod
    def _extract_weaknesses_from_v5(container: dict[str, Any]) -> list["Weakness"]:
        """Extract CWE weaknesses from CVE V5 container.

        Args:
            container: CNA or ADP container data.

        Returns:
            List of Weakness objects.
        """
        weaknesses: list[Weakness] = []
        for pt in container.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    weaknesses.append(
                        Weakness(
                            cwe_id=cwe_id,
                            description=desc.get("description", ""),
                        )
                    )
        return weaknesses

    @staticmethod
    def _extract_references_from_v5(container: dict[str, Any]) -> list["Reference"]:
        """Extract references from CVE V5 container.

        Args:
            container: CNA or ADP container data.

        Returns:
            List of Reference objects.
        """
        return [
            Reference(
                url=ref.get("url", ""),
                source="",
                tags=ref.get("tags", []),
            )
            for ref in container.get("references", [])
            if ref.get("url")
        ]

    def to_elasticsearch_doc(self) -> dict[str, Any]:
        """Convert CVE to Elasticsearch document format.

        Returns:
            Dictionary suitable for Elasticsearch indexing.
        """
        doc: dict[str, Any] = {
            "_id": self.cve_id,
            "cveId": self.cve_id,
            "sourceIdentifier": self.source_identifier,
            "published": self.published.isoformat(),
            "lastModified": self.last_modified.isoformat(),
            "vulnStatus": self.vuln_status,
            "description": self.description,
            "baseScore": self.base_score,
            "baseSeverity": self.severity,
            "primaryCwe": self.primary_cwe,
            "cweIds": [w.cwe_id for w in self.weaknesses],
            "referenceUrls": [r.url for r in self.references],
            "epssScore": self.epss_score,
            "epssPercentile": self.epss_percentile,
            "isKev": self.is_kev,
            "kevDateAdded": self.kev_date_added.isoformat() if self.kev_date_added else None,
            "kevDueDate": self.kev_due_date.isoformat() if self.kev_due_date else None,
            "kevRansomwareUse": self.kev_ransomware_use,
        }

        # Add CVSS v3 fields if present
        if self.cvss_v3:
            doc.update(
                {
                    "cvssV3Version": self.cvss_v3.version.value,
                    "cvssV3VectorString": self.cvss_v3.vector_string,
                    "cvssV3BaseScore": self.cvss_v3.base_score,
                    "cvssV3BaseSeverity": self.cvss_v3.base_severity.value,
                    "cvssV3AttackVector": self.cvss_v3.attack_vector.value
                    if self.cvss_v3.attack_vector
                    else None,
                    "cvssV3AttackComplexity": self.cvss_v3.attack_complexity.value
                    if self.cvss_v3.attack_complexity
                    else None,
                    "cvssV3PrivilegesRequired": self.cvss_v3.privileges_required.value
                    if self.cvss_v3.privileges_required
                    else None,
                    "cvssV3UserInteraction": self.cvss_v3.user_interaction.value
                    if self.cvss_v3.user_interaction
                    else None,
                    "cvssV3Scope": self.cvss_v3.scope.value if self.cvss_v3.scope else None,
                    "cvssV3ConfidentialityImpact": self.cvss_v3.confidentiality_impact.value
                    if self.cvss_v3.confidentiality_impact
                    else None,
                    "cvssV3IntegrityImpact": self.cvss_v3.integrity_impact.value
                    if self.cvss_v3.integrity_impact
                    else None,
                    "cvssV3AvailabilityImpact": self.cvss_v3.availability_impact.value
                    if self.cvss_v3.availability_impact
                    else None,
                    "cvssV3ExploitabilityScore": self.cvss_v3.exploitability_score,
                    "cvssV3ImpactScore": self.cvss_v3.impact_score,
                }
            )

        # Add CVSS v4 fields if present
        if self.cvss_v4:
            doc.update(
                {
                    "cvssV4VectorString": self.cvss_v4.vector_string,
                    "cvssV4BaseScore": self.cvss_v4.base_score,
                    "cvssV4BaseSeverity": self.cvss_v4.base_severity.value,
                }
            )

        return doc
