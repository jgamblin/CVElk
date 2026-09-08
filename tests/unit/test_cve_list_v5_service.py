"""Tests for CVE List V5 synchronization state."""

from pathlib import Path

from cvelk.services.cve_list_v5_service import CVEListV5Service


def test_sync_checkpoint_round_trip(mock_settings, tmp_path: Path) -> None:
    """Persist and reload the repository commit checkpoint."""
    mock_settings.data_dir = tmp_path
    service = CVEListV5Service(mock_settings)
    service.current_commit = lambda: "commit-123"  # type: ignore[method-assign]

    assert service.save_sync_commit() is True
    assert service.load_sync_commit() == "commit-123"
