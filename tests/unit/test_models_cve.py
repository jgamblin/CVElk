"""Tests for CVE data models."""

from datetime import UTC, datetime

from cvelk.models.cve import (
    CVE,
    AttackComplexity,
    AttackVector,
    CVSSMetrics,
    CVSSVersion,
    Severity,
    Weakness,
)


class TestCVSSMetrics:
    """Tests for CVSSMetrics model."""

    def test_create_cvss_v3_metrics(self):
        """Test creating CVSS v3.1 metrics."""
        metrics = CVSSMetrics(
            version=CVSSVersion.V31,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            base_severity=Severity.CRITICAL,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
        )

        assert metrics.version == CVSSVersion.V31
        assert metrics.base_score == 9.8
        assert metrics.base_severity == Severity.CRITICAL
        assert metrics.attack_vector == AttackVector.NETWORK

    def test_base_score_rounding(self):
        """Test that base score is rounded to one decimal."""
        metrics = CVSSMetrics(
            version=CVSSVersion.V31,
            vector_string="test",
            base_score=7.89999,
            base_severity=Severity.HIGH,
        )

        assert metrics.base_score == 7.9

    def test_from_nvd_v3(self, sample_nvd_cve_response):
        """Test creating CVSSMetrics from NVD API response."""
        cvss_data = sample_nvd_cve_response["cve"]["metrics"]["cvssMetricV31"][0]
        metrics = CVSSMetrics.from_nvd_v3(cvss_data)

        assert metrics.base_score == 9.8
        assert metrics.base_severity == Severity.CRITICAL
        assert metrics.attack_vector == AttackVector.NETWORK
        assert metrics.exploitability_score == 3.9


class TestWeakness:
    """Tests for Weakness model."""

    def test_normalize_cwe_id_with_prefix(self):
        """Test CWE ID normalization when prefix exists."""
        weakness = Weakness(cwe_id="CWE-79", description="XSS")
        assert weakness.cwe_id == "CWE-79"

    def test_normalize_cwe_id_without_prefix(self):
        """Test CWE ID normalization when prefix is missing."""
        weakness = Weakness(cwe_id="79", description="XSS")
        assert weakness.cwe_id == "CWE-79"

    def test_normalize_cwe_id_lowercase(self):
        """Test CWE ID normalization to uppercase."""
        weakness = Weakness(cwe_id="cwe-79", description="XSS")
        assert weakness.cwe_id == "CWE-79"


class TestCVE:
    """Tests for CVE model."""

    def test_create_cve(self, sample_cve):
        """Test creating a CVE instance."""
        assert sample_cve.cve_id == "CVE-2024-12345"
        assert sample_cve.base_score == 9.8
        assert sample_cve.severity == "CRITICAL"

    def test_from_nvd_api(self, sample_nvd_cve_response):
        """Test creating CVE from NVD API response."""
        cve = CVE.from_nvd_api(sample_nvd_cve_response)

        assert cve.cve_id == "CVE-2024-12345"
        expected_desc = "A critical vulnerability in Example Software allows remote code execution."
        assert cve.description == expected_desc
        assert cve.cvss_v3 is not None
        assert cve.cvss_v3.base_score == 9.8
        assert cve.primary_cwe == "CWE-79"

    def test_primary_cvss_prefers_v4(self):
        """Test that primary_cvss prefers v4 over v3."""
        cve = CVE(
            cve_id="CVE-2024-12345",
            published=datetime.now(UTC),
            last_modified=datetime.now(UTC),
            description="Test",
            cvss_v3=CVSSMetrics(
                version=CVSSVersion.V31,
                vector_string="test",
                base_score=7.5,
                base_severity=Severity.HIGH,
            ),
            cvss_v4=CVSSMetrics(
                version=CVSSVersion.V40,
                vector_string="test",
                base_score=8.5,
                base_severity=Severity.HIGH,
            ),
        )

        assert cve.primary_cvss == cve.cvss_v4
        assert cve.base_score == 8.5

    def test_to_elasticsearch_doc(self, sample_cve):
        """Test converting CVE to Elasticsearch document."""
        doc = sample_cve.to_elasticsearch_doc()

        assert doc["_id"] == "CVE-2024-12345"
        assert doc["cveId"] == "CVE-2024-12345"
        assert doc["baseScore"] == 9.8
        assert doc["baseSeverity"] == "CRITICAL"
        assert doc["cvssV3BaseScore"] == 9.8
        assert "CWE-79" in doc["cweIds"]

    def test_cve_without_cvss(self):
        """Test CVE without any CVSS scores."""
        cve = CVE(
            cve_id="CVE-2024-99999",
            published=datetime.now(UTC),
            last_modified=datetime.now(UTC),
            description="Test CVE without CVSS",
        )

        assert cve.base_score == 0.0
        assert cve.severity == "NONE"
        assert cve.primary_cvss is None
