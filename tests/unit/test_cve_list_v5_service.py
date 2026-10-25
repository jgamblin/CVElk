"""Tests for CVE List V5 synchronization state and incremental changes."""

import json
import subprocess
from pathlib import Path

import pytest

from cvelk.services.cve_list_v5_service import CVEListV5Service
from cvelk.utils.sync_state import SyncState


def test_sync_checkpoint_round_trip(mock_settings, tmp_path: Path) -> None:
    """Persist and reload the repository commit checkpoint."""
    mock_settings.data_dir = tmp_path
    service = CVEListV5Service(mock_settings)
    service.current_commit = lambda: "commit-123"  # type: ignore[method-assign]

    assert service.save_sync_commit() is True
    assert service.load_sync_commit() == "commit-123"


def test_sync_state_preserves_other_keys(tmp_path: Path) -> None:
    """Saving one checkpoint keeps the others."""
    state = SyncState(tmp_path / "state.json")
    state.set("commit", "abc")
    state.set("epss_score_date", "2026-10-24")

    assert state.get("commit") == "abc"
    assert state.get("epss_score_date") == "2026-10-24"
    assert SyncState(tmp_path / "missing.json").get("commit") is None


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _write_record(repo: Path, cve_id: str) -> Path:
    year = cve_id.split("-")[1]
    path = repo / "cves" / year / "0xxx" / f"{cve_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"}}))
    return path


@pytest.fixture
def repo_service(mock_settings, tmp_path: Path) -> CVEListV5Service:
    """A V5 service over a real git repo with a checkpoint and one later commit.

    After the checkpoint, CVE-2024-0001 is modified, CVE-2024-0002 is deleted,
    and CVE-2024-0003 and CVE-2023-0009 are added.
    """
    repo = tmp_path / "cvelistV5"
    repo.mkdir()
    _git(repo, "init", "-q")
    first = _write_record(repo, "CVE-2024-0001")
    deleted = _write_record(repo, "CVE-2024-0002")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial")

    mock_settings.data_dir = tmp_path / "data"
    mock_settings.cve_list_v5.local_path = repo
    service = CVEListV5Service(mock_settings)
    assert service.save_sync_commit() is True

    first.write_text(first.read_text() + "\n")
    deleted.unlink()
    _write_record(repo, "CVE-2024-0003")
    _write_record(repo, "CVE-2023-0009")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "update")
    return service


def test_changed_files_since_checkpoint(repo_service: CVEListV5Service) -> None:
    """Only added and modified records are returned."""
    names = [path.name for path in repo_service.iter_cve_files(changed_only=True)]

    assert names == ["CVE-2023-0009.json", "CVE-2024-0001.json", "CVE-2024-0003.json"]


def test_removed_cve_ids_since_checkpoint(repo_service: CVEListV5Service) -> None:
    """Deleted records are reported so the sync can remove them from the index."""
    assert repo_service.removed_cve_ids() == ["CVE-2024-0002"]


def test_years_filter_applies_to_changed_files(repo_service: CVEListV5Service) -> None:
    """The years filter limits incremental results too."""
    repo_service.years_filter = [2024]

    names = [path.name for path in repo_service.iter_cve_files(changed_only=True)]

    assert names == ["CVE-2024-0001.json", "CVE-2024-0003.json"]


def test_no_checkpoint_means_full_scan(mock_settings, tmp_path: Path) -> None:
    """Without a checkpoint there is nothing to diff against."""
    mock_settings.data_dir = tmp_path
    service = CVEListV5Service(mock_settings)

    assert service._changed_cve_files() is None
    assert service.removed_cve_ids() == []
