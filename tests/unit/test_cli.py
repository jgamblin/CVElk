"""Tests for CLI commands and sync orchestration."""

from datetime import UTC, datetime
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from cvelk import cli
from cvelk.models.cve import CVE
from cvelk.sync import SyncPipeline
from cvelk.utils.sync_state import SyncState

runner = CliRunner()


@pytest.fixture
def recorded_sync(monkeypatch):
    """Replace the V5 sync with a recorder and stop watch mode after one update."""
    calls: list[dict] = []

    async def fake_run_sync_v5(settings, **kwargs):
        calls.append(kwargs)

    def stop(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_run_sync_v5", fake_run_sync_v5)
    monkeypatch.setattr("time.sleep", stop)
    return calls


def test_watch_defaults_to_incremental_v5_only(recorded_sync) -> None:
    """By default watch skips NVD and syncs incrementally."""
    result = runner.invoke(cli.app, ["watch", "--interval", "1"])

    assert result.exit_code == 0, result.output
    assert recorded_sync == [
        {
            "skip_nvd": True,
            "skip_epss": False,
            "skip_kev": False,
            "batch_size": 1000,
            "incremental": True,
        }
    ]


def test_watch_no_skip_nvd_enables_nvd(recorded_sync) -> None:
    """--no-skip-nvd turns NVD enrichment on, which requires a complete scan."""
    result = runner.invoke(cli.app, ["watch", "--no-skip-nvd", "--interval", "1"])

    assert result.exit_code == 0, result.output
    assert recorded_sync[0]["skip_nvd"] is False
    assert recorded_sync[0]["incremental"] is False


class FakeES:
    """Minimal Elasticsearch service for orchestration tests."""

    exists = True

    def __init__(self, settings) -> None:
        self.closed = False
        self.refreshed = False

    def ping(self) -> bool:
        return True

    def ensure_index(self) -> None:
        pass

    def index_exists(self) -> bool:
        return self.exists

    def refresh(self) -> None:
        self.refreshed = True

    def bulk_index_cves(self, cves):
        return len(cves), 0

    def bulk_delete_cves(self, cve_ids):
        return len(list(cve_ids)), 0

    def close(self) -> None:
        self.closed = True

    def search_cves(self, query, size):
        return [{"cveId": "CVE-2024-0001", "baseScore": None, "description": "Unscored"}]


class FakeV5:
    """V5 repository with one changed record and one removed record."""

    instances: ClassVar[list["FakeV5"]] = []

    def __init__(self, settings) -> None:
        self.state = SyncState(settings.data_dir / "state.json")
        self.commit: str | None = "abc123"
        self.changed_only: bool | None = None
        self.saved = False
        FakeV5.instances.append(self)

    def clone_or_update(self) -> bool:
        return True

    def get_stats(self):
        return {"total_cves": 1}

    def load_sync_commit(self):
        return self.commit

    def removed_cve_ids(self):
        return ["CVE-2020-0001"]

    def iter_cves(self, changed_only=False):
        self.changed_only = changed_only
        now = datetime(2024, 1, 1, tzinfo=UTC)
        yield CVE(cve_id="CVE-2024-0001", published=now, last_modified=now, description="x")

    def save_sync_commit(self) -> bool:
        self.saved = True
        return True


@pytest.fixture
def fake_services(monkeypatch, mock_settings, tmp_path):
    """Swap in fake services and record which enrichment step ran."""
    mock_settings.data_dir = tmp_path
    FakeV5.instances.clear()
    steps: list[str] = []

    async def no_enrichment(*_args):
        return None, None

    monkeypatch.setattr(cli, "ElasticsearchService", FakeES)
    monkeypatch.setattr(cli, "CVEListV5Service", FakeV5)
    monkeypatch.setattr(cli, "_load_enrichment", no_enrichment)
    monkeypatch.setattr(
        SyncPipeline, "refresh_stale_enrichment", lambda self, state: steps.append("refresh") or 0
    )
    monkeypatch.setattr(
        SyncPipeline, "mark_enrichment_current", lambda self, state: steps.append("mark")
    )
    return steps


async def test_incremental_sync_refreshes_enrichment(fake_services, mock_settings) -> None:
    """An incremental run processes changed files and refreshes EPSS/KEV."""
    await cli._run_sync_v5(
        mock_settings,
        skip_nvd=True,
        skip_epss=False,
        skip_kev=False,
        batch_size=10,
        incremental=True,
    )

    v5 = FakeV5.instances[0]
    assert v5.changed_only is True
    assert fake_services == ["refresh"]
    assert v5.saved is True


async def test_incremental_without_checkpoint_scans_everything(
    fake_services, mock_settings, monkeypatch
) -> None:
    """With no checkpoint the run is a complete scan and records the feed versions."""
    monkeypatch.setattr(FakeV5, "load_sync_commit", lambda self: None)

    await cli._run_sync_v5(
        mock_settings,
        skip_nvd=True,
        skip_epss=False,
        skip_kev=False,
        batch_size=10,
        incremental=True,
    )

    assert FakeV5.instances[0].changed_only is False
    assert fake_services == ["mark"]


def test_search_shows_unscored_cves(monkeypatch) -> None:
    """CVEs without a CVSS score display N/A instead of failing to format."""
    monkeypatch.setattr(cli, "ElasticsearchService", FakeES)

    result = runner.invoke(cli.app, ["search", "unscored"])

    assert result.exit_code == 0, result.output
    assert "CVE-2024-0001" in result.output
    assert "N/A" in result.output


def test_setup_requires_dashboard_file(monkeypatch, tmp_path) -> None:
    """Setup fails clearly when the dashboard file does not exist."""

    class FakeKibana:
        def __init__(self, settings) -> None:
            pass

        async def ping(self) -> bool:
            return True

    monkeypatch.setattr(cli, "KibanaService", FakeKibana)

    result = runner.invoke(cli.app, ["setup", "--dashboard", str(tmp_path / "missing.ndjson")])

    assert result.exit_code == 1
    assert "Dashboard file not found" in result.output


def test_stats_explains_missing_index(monkeypatch) -> None:
    """Stats before the first sync explains what to do instead of showing a 404."""
    monkeypatch.setattr(FakeES, "exists", False)
    monkeypatch.setattr(cli, "ElasticsearchService", FakeES)

    result = runner.invoke(cli.app, ["stats"])

    assert result.exit_code == 1
    assert "does not exist yet" in result.output
