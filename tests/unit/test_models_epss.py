"""Tests for EPSS data models and service."""

from datetime import date

from cvelk.models.epss import EPSSData, EPSSScore
from cvelk.services.epss_service import EPSSService


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


class TestEPSSServiceParsing:
    """Tests for parsing the EPSS CSV feed."""

    def test_parses_current_header_format(self, mock_settings):
        """The current header carries a full timestamp with no space after '#'."""
        content = (
            "#model_version:v2025.03.14,score_date:2026-10-24T12:03:08Z\n"
            "cve,epss,percentile\n"
            "CVE-2024-0001,0.5,0.9\n"
        )

        data = EPSSService(mock_settings)._parse_csv(content)

        assert data.model_version == "v2025.03.14"
        assert data.score_date == date(2026, 10, 24)
        assert data.scores["CVE-2024-0001"].score_date == date(2026, 10, 24)

    def test_parses_legacy_header_format(self, mock_settings, sample_epss_csv):
        """Older files used a plain date and a space after '#'."""
        data = EPSSService(mock_settings)._parse_csv(sample_epss_csv)

        assert data.model_version == "v2024.01.01"
        assert data.score_date == date(2024, 1, 15)
        assert data.total_count == 3

    def test_es_fields_match_indexed_document(self, sample_cve):
        """Partial updates write the same values as a full index of the CVE."""
        score = EPSSScore(cve_id=sample_cve.cve_id, score=0.95432, percentile=0.99123)
        EPSSData(scores={score.cve_id: score}).enrich_cve(sample_cve)

        doc = sample_cve.to_elasticsearch_doc()

        assert score.to_es_fields() == {
            "epssScore": doc["epssScore"],
            "epssPercentile": doc["epssPercentile"],
        }
