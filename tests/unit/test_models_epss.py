"""Tests for EPSS data models and service."""

from cvelk.models.epss import EPSSData, EPSSScore


class TestEPSSScore:
    """Tests for EPSSScore model."""

    def test_create_epss_score(self):
        """Test creating an EPSS score."""
        score = EPSSScore(
            cve_id="CVE-2024-12345",
            score=0.95432,
            percentile=0.99123,
        )

        assert score.cve_id == "CVE-2024-12345"
        assert score.score == 0.95432
        assert score.percentile == 0.99123

    def test_score_percentage(self):
        """Test EPSS score percentage conversion."""
        score = EPSSScore(
            cve_id="CVE-2024-12345",
            score=0.95432,
            percentile=0.99123,
        )

        assert score.score_percentage == 95.432
        assert score.percentile_percentage == 99.12

    def test_normalize_cve_id(self):
        """Test CVE ID normalization to uppercase."""
        score = EPSSScore(
            cve_id="cve-2024-12345",
            score=0.5,
            percentile=0.5,
        )

        assert score.cve_id == "CVE-2024-12345"

    def test_from_csv_row(self):
        """Test creating EPSSScore from CSV row."""
        row = {
            "cve": "CVE-2024-12345",
            "epss": "0.95432",
            "percentile": "0.99123",
        }

        score = EPSSScore.from_csv_row(row)

        assert score.cve_id == "CVE-2024-12345"
        assert score.score == 0.95432
        assert score.percentile == 0.99123


class TestEPSSData:
    """Tests for EPSSData container."""

    def test_get_score(self):
        """Test getting score by CVE ID."""
        scores = {
            "CVE-2024-12345": EPSSScore(
                cve_id="CVE-2024-12345",
                score=0.95,
                percentile=0.99,
            ),
        }
        data = EPSSData(scores=scores, total_count=1)

        score = data.get_score("CVE-2024-12345")
        assert score is not None
        assert score.score == 0.95

    def test_get_score_case_insensitive(self):
        """Test that score lookup is case insensitive."""
        scores = {
            "CVE-2024-12345": EPSSScore(
                cve_id="CVE-2024-12345",
                score=0.95,
                percentile=0.99,
            ),
        }
        data = EPSSData(scores=scores, total_count=1)

        score = data.get_score("cve-2024-12345")
        assert score is not None

    def test_get_score_not_found(self):
        """Test getting score for non-existent CVE."""
        data = EPSSData(scores={}, total_count=0)

        score = data.get_score("CVE-9999-99999")
        assert score is None

    def test_enrich_cve(self, sample_cve):
        """Test enriching a CVE with EPSS data."""
        scores = {
            "CVE-2024-12345": EPSSScore(
                cve_id="CVE-2024-12345",
                score=0.95432,
                percentile=0.99123,
            ),
        }
        data = EPSSData(scores=scores, total_count=1)

        data.enrich_cve(sample_cve)

        assert sample_cve.epss_score == 95.432
        assert sample_cve.epss_percentile == 99.12
