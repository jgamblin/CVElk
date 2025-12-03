"""Pytest configuration and fixtures for CVElk tests."""

from datetime import UTC, datetime

import pytest

from cvelk.config import Settings
from cvelk.models.cve import CVE, CVSSMetrics, CVSSVersion, Severity, Weakness


@pytest.fixture
def sample_nvd_cve_response():
    """Sample NVD 2.0 API CVE response."""
    return {
        "cve": {
            "id": "CVE-2024-12345",
            "sourceIdentifier": "security@example.com",
            "published": "2024-01-15T10:30:00.000",
            "lastModified": "2024-01-16T14:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {
                    "lang": "en",
                    "value": (
                        "A critical vulnerability in Example Software allows remote code execution."
                    ),
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }
                ]
            },
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-79"}],
                }
            ],
            "references": [
                {
                    "url": "https://example.com/advisory/2024-001",
                    "source": "security@example.com",
                    "tags": ["Vendor Advisory"],
                }
            ],
        }
    }


@pytest.fixture
def sample_epss_csv():
    """Sample EPSS CSV content."""
    return """# model_version:v2024.01.01,score_date:2024-01-15
cve,epss,percentile
CVE-2024-12345,0.95432,0.99123
CVE-2024-12346,0.00123,0.12345
CVE-2024-12347,0.50000,0.75000
"""


@pytest.fixture
def sample_kev_response():
    """Sample CISA KEV catalog response."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2024.01.15",
        "dateReleased": "2024-01-15T00:00:00.000Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-12345",
                "vendorProject": "Example Corp",
                "product": "Example Software",
                "vulnerabilityName": "Example Software Remote Code Execution",
                "dateAdded": "2024-01-10",
                "shortDescription": "Critical RCE vulnerability in Example Software",
                "requiredAction": "Apply vendor patch or disable affected service",
                "dueDate": "2024-01-31",
                "knownRansomwareCampaignUse": "Known",
                "notes": "Actively exploited in the wild",
            },
            {
                "cveID": "CVE-2024-12346",
                "vendorProject": "Another Vendor",
                "product": "Another Product",
                "vulnerabilityName": "Another Product Privilege Escalation",
                "dateAdded": "2024-01-12",
                "shortDescription": "Local privilege escalation vulnerability",
                "requiredAction": "Apply vendor patch",
                "dueDate": "2024-02-05",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            },
        ],
    }


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    return Settings(
        log_level="DEBUG",
        elasticsearch={"host": "http://localhost:9200"},
        kibana={"host": "http://localhost:5601"},
    )


@pytest.fixture
def sample_cve():
    """Create a sample CVE model instance."""
    return CVE(
        cve_id="CVE-2024-12345",
        source_identifier="test@example.com",
        published=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        last_modified=datetime(2024, 1, 16, 14, 0, 0, tzinfo=UTC),
        vuln_status="Analyzed",
        description="A test vulnerability for unit testing.",
        cvss_v3=CVSSMetrics(
            version=CVSSVersion.V31,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            base_severity=Severity.CRITICAL,
        ),
        weaknesses=[Weakness(cwe_id="CWE-79", description="XSS")],
    )
