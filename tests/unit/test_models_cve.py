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

    def test_to_elasticsearch_doc_includes_enrichment(self, sample_cve):
        """Test that EPSS and KEV enrichment is persisted in the document."""
        sample_cve.epss_score = 55.1
        sample_cve.epss_percentile = 44.08
        sample_cve.is_kev = True
        sample_cve.kev_date_added = datetime(2024, 1, 10, tzinfo=UTC)
        sample_cve.kev_due_date = datetime(2024, 1, 31, tzinfo=UTC)
        sample_cve.kev_ransomware_use = True

        doc = sample_cve.to_elasticsearch_doc()

        assert doc["epssScore"] == 55.1
        assert doc["epssPercentile"] == 44.08
        assert doc["isKev"] is True
        assert doc["kevDateAdded"] == "2024-01-10T00:00:00+00:00"
        assert doc["kevDueDate"] == "2024-01-31T00:00:00+00:00"
        assert doc["kevRansomwareUse"] is True

    def test_cve_without_cvss(self):
        """Test CVE without any CVSS scores."""
        cve = CVE(
            cve_id="CVE-2024-99999",
            published=datetime.now(UTC),
            last_modified=datetime.now(UTC),
            description="Test CVE without CVSS",
        )

        assert cve.base_score is None
        assert cve.severity is None
        assert cve.primary_cvss is None

        doc = cve.to_elasticsearch_doc()
        assert doc["baseScore"] is None
        assert doc["baseSeverity"] is None

    def test_is_rejected(self, sample_cve):
        """Rejected status is detected regardless of source casing."""
        assert sample_cve.is_rejected is False
        sample_cve.vuln_status = "Rejected"
        assert sample_cve.is_rejected is True
        sample_cve.vuln_status = "REJECTED"
        assert sample_cve.is_rejected is True


class TestWeaknessNormalization:
    """Tests for CWE ID normalization."""

    def test_keeps_nvd_placeholders(self):
        """NVD placeholder values are not given a second CWE- prefix."""
        assert Weakness(cwe_id="NVD-CWE-Other").cwe_id == "NVD-CWE-Other"
        assert Weakness(cwe_id="NVD-CWE-noinfo").cwe_id == "NVD-CWE-noinfo"

    def test_normalizes_cwe_ids(self):
        """CWE IDs are upper-cased and bare numbers get the CWE- prefix."""
        assert Weakness(cwe_id="cwe-79").cwe_id == "CWE-79"
        assert Weakness(cwe_id="79").cwe_id == "CWE-79"
        assert Weakness(cwe_id="").cwe_id == "CWE-UNKNOWN"


def _v5_record(state="PUBLISHED", cna=None, adp=None):
    """Build a minimal CVE JSON 5.x record."""
    return {
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "state": state,
            "assignerShortName": "example",
            "datePublished": "2024-01-15T10:30:00.000Z",
            "dateUpdated": "2024-02-01T08:00:00.000Z",
        },
        "containers": {"cna": cna or {}, "adp": adp or []},
    }


V31_DATA = {
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
}


class TestFromCVEV5:
    """Tests for parsing CVE List V5 records."""

    def test_published_record_with_cna_metrics(self):
        """CNA description, CVSS, CWEs and references are parsed."""
        cve = CVE.from_cve_v5(
            _v5_record(
                cna={
                    "descriptions": [{"lang": "en-US", "value": "Remote code execution."}],
                    "metrics": [
                        {"cvssV3_1": V31_DATA},
                        {"cvssV4_0": {"vectorString": "CVSS:4.0/AV:N", "baseScore": 9.3}},
                    ],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}],
                    "references": [{"url": "https://example.com/a"}, {"url": ""}],
                }
            )
        )

        assert cve.vuln_status == "Published"
        assert cve.description == "Remote code execution."
        assert cve.published == datetime(2024, 1, 15, 10, 30, tzinfo=UTC)
        assert cve.last_modified == datetime(2024, 2, 1, 8, 0, tzinfo=UTC)
        assert cve.cvss_v3 is not None
        assert cve.cvss_v3.version == CVSSVersion.V31
        assert cve.cvss_v3.attack_vector == AttackVector.NETWORK
        assert cve.cvss_v4 is not None
        assert cve.cvss_v4.base_score == 9.3
        assert cve.cvss_v4.base_severity == Severity.NONE  # missing severity defaults
        assert [w.cwe_id for w in cve.weaknesses] == ["CWE-78"]
        assert [r.url for r in cve.references] == ["https://example.com/a"]

    def test_adp_fills_missing_cna_data(self):
        """ADP containers supply CVSS, CWEs and extra references the CNA lacks."""
        cve = CVE.from_cve_v5(
            _v5_record(
                cna={
                    "descriptions": [{"lang": "en", "value": "Bug."}],
                    "references": [{"url": "https://example.com/a"}],
                },
                adp=[
                    {
                        "metrics": [{"cvssV3_0": {**V31_DATA, "version": "3.0"}}],
                        "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
                        "references": [
                            {"url": "https://example.com/a"},
                            {"url": "https://example.com/b"},
                        ],
                    }
                ],
            )
        )

        assert cve.cvss_v3 is not None
        assert cve.cvss_v3.version == CVSSVersion.V30
        assert cve.primary_cwe == "CWE-79"
        assert [r.url for r in cve.references] == [
            "https://example.com/a",
            "https://example.com/b",
        ]

    def test_unknown_severity_falls_back_to_none(self):
        """An unrecognized severity does not make the whole record fail to parse."""
        cve = CVE.from_cve_v5(
            _v5_record(cna={"metrics": [{"cvssV3_1": {**V31_DATA, "baseSeverity": "Severe"}}]})
        )

        assert cve.cvss_v3 is not None
        assert cve.cvss_v3.base_severity == Severity.NONE

    def test_rejected_record(self):
        """Rejected records keep their state so the sync can remove them."""
        cve = CVE.from_cve_v5(_v5_record(state="REJECTED"))

        assert cve.vuln_status == "REJECTED"
        assert cve.is_rejected is True

    def test_v5_and_nvd_v3_parse_identically(self):
        """V5 and NVD CVSS v3 objects share one builder and produce the same metrics."""
        v5 = CVE.from_cve_v5(_v5_record(cna={"metrics": [{"cvssV3_1": V31_DATA}]}))
        nvd = CVSSMetrics.from_nvd_v3({"cvssData": V31_DATA})

        assert v5.cvss_v3 == nvd
        assert nvd.attack_complexity == AttackComplexity.LOW
