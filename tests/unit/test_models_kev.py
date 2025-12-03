"""Tests for KEV data models."""

from datetime import date

from cvelk.models.kev import KEVCatalog, KEVEntry


class TestKEVEntry:
    """Tests for KEVEntry model."""

    def test_create_kev_entry(self):
        """Test creating a KEV entry."""
        entry = KEVEntry(
            cve_id="CVE-2024-12345",
            vendor_project="Example Corp",
            product="Example Software",
            vulnerability_name="Example RCE",
            date_added=date(2024, 1, 10),
            short_description="Critical RCE",
            required_action="Apply patch",
            due_date=date(2024, 1, 31),
            known_ransomware_campaign_use=True,
        )

        assert entry.cve_id == "CVE-2024-12345"
        assert entry.known_ransomware_campaign_use is True

    def test_parse_date_string(self):
        """Test parsing date from string."""
        entry = KEVEntry(
            cve_id="CVE-2024-12345",
            vendor_project="Test",
            product="Test",
            vulnerability_name="Test",
            date_added="2024-01-10",
            short_description="Test",
            required_action="Test",
            due_date="2024-01-31",
        )

        assert entry.date_added == date(2024, 1, 10)
        assert entry.due_date == date(2024, 1, 31)

    def test_parse_ransomware_use_known(self):
        """Test parsing ransomware use 'Known' value."""
        entry = KEVEntry(
            cve_id="CVE-2024-12345",
            vendor_project="Test",
            product="Test",
            vulnerability_name="Test",
            date_added=date(2024, 1, 10),
            short_description="Test",
            required_action="Test",
            due_date=date(2024, 1, 31),
            known_ransomware_campaign_use="Known",
        )

        assert entry.known_ransomware_campaign_use is True

    def test_from_api(self, sample_kev_response):
        """Test creating KEVEntry from API response."""
        vuln_data = sample_kev_response["vulnerabilities"][0]
        entry = KEVEntry.from_api(vuln_data)

        assert entry.cve_id == "CVE-2024-12345"
        assert entry.vendor_project == "Example Corp"
        assert entry.known_ransomware_campaign_use is True


class TestKEVCatalog:
    """Tests for KEVCatalog model."""

    def test_from_api(self, sample_kev_response):
        """Test creating KEVCatalog from API response."""
        catalog = KEVCatalog.from_api(sample_kev_response)

        assert catalog.total_count == 2
        assert "CVE-2024-12345" in catalog.entries
        assert "CVE-2024-12346" in catalog.entries

    def test_is_kev(self, sample_kev_response):
        """Test checking if CVE is in KEV."""
        catalog = KEVCatalog.from_api(sample_kev_response)

        assert catalog.is_kev("CVE-2024-12345") is True
        assert catalog.is_kev("cve-2024-12345") is True  # Case insensitive
        assert catalog.is_kev("CVE-9999-99999") is False

    def test_get_entry(self, sample_kev_response):
        """Test getting KEV entry."""
        catalog = KEVCatalog.from_api(sample_kev_response)

        entry = catalog.get_entry("CVE-2024-12345")
        assert entry is not None
        assert entry.vendor_project == "Example Corp"

    def test_enrich_cve(self, sample_cve, sample_kev_response):
        """Test enriching CVE with KEV data."""
        catalog = KEVCatalog.from_api(sample_kev_response)

        catalog.enrich_cve(sample_cve)

        assert sample_cve.is_kev is True
        assert sample_cve.kev_ransomware_use is True
        assert sample_cve.kev_date_added is not None
