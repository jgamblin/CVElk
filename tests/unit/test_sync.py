"""Tests for the shared sync pipeline."""

from datetime import UTC, datetime

import pytest

from cvelk.models.cve import CVE, Weakness
from cvelk.models.kev import KEVCatalog
from cvelk.services import EPSSService, KEVService
from cvelk.sync import EPSS_STATE_KEY, KEV_STATE_KEY, SyncPipeline, merge_nvd_data
from cvelk.utils.sync_state import SyncState


class FakeES:
    """Records the bulk calls the pipeline makes."""

    def __init__(self) -> None:
        self.indexed: list[list[str]] = []
        self.deleted: list[list[str]] = []
        self.updates: list[tuple[str, dict]] = []
        self.kev_kept: set[str] | None = None
        self.update_errors = 0

    def bulk_index_cves(self, cves):
        self.indexed.append([cve.cve_id for cve in cves])
        return len(cves), 0

    def bulk_delete_cves(self, cve_ids):
        ids = list(cve_ids)
        self.deleted.append(ids)
        return len(ids), 0

    def bulk_update_cves(self, updates):
        batch = list(updates)
        self.updates.extend(batch)
        return len(batch), self.update_errors

    def clear_kev_except(self, kev_ids):
        self.kev_kept = set(kev_ids)
        return 0


def make_cve(cve_id: str, status: str = "Published") -> CVE:
    """Create a minimal CVE."""
    now = datetime(2024, 1, 1, tzinfo=UTC)
    return CVE(
        cve_id=cve_id,
        published=now,
        last_modified=now,
        vuln_status=status,
        description="test",
    )


@pytest.fixture
def epss_service(mock_settings, sample_epss_csv):
    """EPSS service loaded with the sample feed (score date 2024-01-15)."""
    service = EPSSService(mock_settings)
    service._data = service._parse_csv(sample_epss_csv)
    return service


@pytest.fixture
def kev_service(mock_settings, sample_kev_response):
    """KEV service loaded with the sample catalog."""
    service = KEVService(mock_settings)
    service._catalog = KEVCatalog.from_api(sample_kev_response)
    return service


@pytest.fixture
def state(tmp_path):
    """Empty sync state."""
    return SyncState(tmp_path / "state.json")


async def test_run_indexes_in_batches_and_deletes_rejected() -> None:
    """Published CVEs are indexed in batches; rejected and removed CVEs are deleted."""
    es = FakeES()
    pipeline = SyncPipeline(es, batch_size=2)
    cves = [
        make_cve("CVE-2024-0001"),
        make_cve("CVE-2024-0002", status="REJECTED"),
        make_cve("CVE-2024-0003"),
        make_cve("CVE-2024-0004"),
    ]

    result = await pipeline.run(cves, removed_ids=["CVE-2020-0001"])

    assert es.indexed == [["CVE-2024-0001", "CVE-2024-0003"], ["CVE-2024-0004"]]
    assert es.deleted == [["CVE-2020-0001", "CVE-2024-0002"]]
    assert (result.processed, result.indexed, result.deleted, result.errors) == (4, 3, 2, 0)


async def test_run_accepts_async_sources() -> None:
    """NVD sources are async generators."""

    async def source():
        yield make_cve("CVE-2024-0001")
        yield make_cve("CVE-2024-0002", status="Rejected")

    es = FakeES()
    result = await SyncPipeline(es).run(source())

    assert es.indexed == [["CVE-2024-0001"]]
    assert es.deleted == [["CVE-2024-0002"]]
    assert result.processed == 2


async def test_run_enriches_cves(epss_service, kev_service) -> None:
    """EPSS, KEV and NVD data are applied before indexing."""
    cve = make_cve("CVE-2024-12345")
    nvd = make_cve("CVE-2024-12345", status="Analyzed")
    nvd.weaknesses = [Weakness(cwe_id="CWE-79")]
    pipeline = SyncPipeline(
        FakeES(),
        epss_service=epss_service,
        kev_service=kev_service,
        nvd_cache={nvd.cve_id: nvd},
    )

    await pipeline.run([cve])

    assert cve.epss_score == pytest.approx(95.432)
    assert cve.is_kev is True
    assert cve.vuln_status == "Analyzed"
    assert cve.primary_cwe == "CWE-79"


def test_merge_nvd_data_keeps_v5_values_and_dedupes() -> None:
    """NVD fills gaps without duplicating CWEs or references."""
    v5 = make_cve("CVE-2024-0001")
    v5.weaknesses = [Weakness(cwe_id="CWE-79")]
    nvd = make_cve("CVE-2024-0001", status="Published")
    nvd.weaknesses = [Weakness(cwe_id="CWE-79"), Weakness(cwe_id="CWE-20")]

    merge_nvd_data(v5, nvd)

    assert [w.cwe_id for w in v5.weaknesses] == ["CWE-79", "CWE-20"]
    assert v5.vuln_status == "Published"


def test_refresh_updates_all_indexed_cves_once_per_release(
    epss_service, kev_service, state
) -> None:
    """A new feed release is written to every CVE, then skipped until the next release."""
    es = FakeES()
    pipeline = SyncPipeline(es, epss_service=epss_service, kev_service=kev_service)

    updated = pipeline.refresh_stale_enrichment(state)

    epss_ids = {cve_id for cve_id, fields in es.updates if "epssScore" in fields}
    kev_ids = {cve_id for cve_id, fields in es.updates if fields.get("isKev")}
    assert epss_ids == {"CVE-2024-12345", "CVE-2024-12346", "CVE-2024-12347"}
    assert kev_ids == {"CVE-2024-12345", "CVE-2024-12346"}
    assert es.kev_kept == kev_ids
    assert updated == 5
    assert state.get(EPSS_STATE_KEY) == "2024-01-15"
    assert state.get(KEV_STATE_KEY) == "2024.01.15:2"

    es.updates.clear()
    assert pipeline.refresh_stale_enrichment(state) == 0
    assert es.updates == []


def test_refresh_retries_after_errors(epss_service, state) -> None:
    """The release is not recorded if any update failed."""
    es = FakeES()
    es.update_errors = 1

    SyncPipeline(es, epss_service=epss_service).refresh_stale_enrichment(state)

    assert state.get(EPSS_STATE_KEY) is None


def test_mark_enrichment_current_skips_next_refresh(epss_service, kev_service, state) -> None:
    """After a complete scan the loaded feed versions are recorded as applied."""
    es = FakeES()
    pipeline = SyncPipeline(es, epss_service=epss_service, kev_service=kev_service)

    pipeline.mark_enrichment_current(state)

    assert pipeline.refresh_stale_enrichment(state) == 0
    assert es.updates == []


def test_refresh_without_feeds_is_noop(state) -> None:
    """Skipped feeds are never refreshed or recorded."""
    assert SyncPipeline(FakeES()).refresh_stale_enrichment(state) == 0
    assert state.get(EPSS_STATE_KEY) is None
