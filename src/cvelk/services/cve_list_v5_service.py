"""CVE List V5 service for fetching CVE data from the official CVE repository.

This service clones/updates the CVE List V5 repository and parses CVE JSON 5.x records.
The repository is the authoritative source for CVE data, updated every 7 minutes.

Repository: https://github.com/CVEProject/cvelistV5
Documentation: https://github.com/CVEProject/cve-schema
"""

import json
import subprocess
from collections.abc import Generator
from pathlib import Path
from typing import Any

from loguru import logger

from cvelk.config import Settings
from cvelk.models.cve import CVE
from cvelk.utils.sync_state import SyncState


class CVEListV5Service:
    """Service for fetching and parsing CVE data from CVE List V5 repository.

    The CVE List V5 repository contains all CVE records in JSON 5.x format.
    Records may have:
    - CNA container (CVE Numbering Authority) - primary CVE info
    - ADP containers (Authorized Data Publishers) - enrichment data
      - CISA-ADP: SSVC scores, KEV data, vulnrichment (CVSS, CWE, CPE)
      - CVE Program Container: Additional references
    """

    def __init__(self, settings: Settings):
        """Initialize CVE List V5 service.

        Args:
            settings: Application settings.
        """
        self.settings = settings
        self.repo_path = settings.cve_list_v5.local_path
        self.repo_url = settings.cve_list_v5.repo_url
        self.use_shallow = settings.cve_list_v5.use_shallow_clone
        self.years_filter = settings.cve_list_v5.years
        self.state = SyncState(settings.data_dir / "cvelist-v5-sync.json")

    def clone_or_update(self) -> bool:
        """Clone the CVE List V5 repository or update if it exists.

        Returns:
            True if successful, False otherwise.
        """
        if self.repo_path.exists() and (self.repo_path / ".git").exists():
            return self._update_repo()
        return self._clone_repo()

    def _clone_repo(self) -> bool:
        """Clone the CVE List V5 repository.

        Returns:
            True if successful, False otherwise.
        """
        try:
            # Ensure parent directory exists
            self.repo_path.parent.mkdir(parents=True, exist_ok=True)

            cmd = ["git", "clone"]
            if self.use_shallow:
                cmd.extend(["--depth", "1"])
            cmd.extend([self.repo_url, str(self.repo_path)])

            logger.info(f"Cloning CVE List V5 repository to {self.repo_path}...")
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            logger.info("Repository cloned successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error cloning repository: {e}")
            return False

    def _update_repo(self) -> bool:
        """Update the existing CVE List V5 repository.

        Returns:
            True if successful, False otherwise.
        """
        try:
            logger.info("Updating CVE List V5 repository...")
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
            )
            if "Already up to date" in result.stdout:
                logger.info("Repository is already up to date")
            else:
                logger.info("Repository updated successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update repository: {e.stderr}")
            # Try to reset and pull
            try:
                subprocess.run(
                    ["git", "fetch", "--all"],
                    cwd=self.repo_path,
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    ["git", "reset", "--hard", "origin/main"],
                    cwd=self.repo_path,
                    capture_output=True,
                    check=True,
                )
                logger.info("Repository reset and updated")
                return True
            except subprocess.CalledProcessError as e2:
                logger.error(f"Failed to reset repository: {e2.stderr}")
                return False
        except Exception as e:
            logger.error(f"Unexpected error updating repository: {e}")
            return False

    def iter_cve_files(self, changed_only: bool = False) -> Generator[Path, None, None]:
        """Iterate over all CVE JSON files in the repository.

        Yields:
            Path to each CVE JSON file.
        """
        cves_dir = self.repo_path / "cves"
        if not cves_dir.exists():
            logger.error(f"CVE directory not found: {cves_dir}")
            return

        if changed_only:
            changed_files = self._changed_cve_files()
            if changed_files is not None:
                yield from changed_files
                return

        # Filter by years if specified
        year_dirs = sorted(cves_dir.iterdir())
        for year_dir in year_dirs:
            if not year_dir.is_dir():
                continue

            # Extract year from directory name (e.g., "2024")
            try:
                year = int(year_dir.name)
            except ValueError:
                continue

            # Apply year filter if specified
            if self.years_filter and year not in self.years_filter:
                continue

            # Iterate through xxx directories (e.g., 0xxx, 1xxx, etc.)
            for range_dir in sorted(year_dir.iterdir()):
                if not range_dir.is_dir():
                    continue

                # Yield all JSON files in this range directory
                yield from sorted(range_dir.glob("CVE-*.json"))

    def _changed_cve_files(self) -> list[Path] | None:
        """Return CVE files added or modified since the last successful sync.

        Returns ``None`` when no usable checkpoint exists, which tells callers
        to fall back to a complete scan.
        """
        names = self._diff_since_checkpoint("d")
        if names is None:
            return None

        changed_files = [
            self.repo_path / name for name in names if (self.repo_path / name).exists()
        ]
        return sorted(changed_files)

    def removed_cve_ids(self) -> list[str]:
        """Return IDs of CVE records deleted from the repository since the last sync."""
        names = self._diff_since_checkpoint("D") or []
        return sorted(Path(name).stem for name in names)

    def _diff_since_checkpoint(self, diff_filter: str) -> list[str] | None:
        """List CVE JSON files changed since the checkpoint, honoring the years filter.

        Args:
            diff_filter: ``git diff --diff-filter`` value, e.g. ``"D"`` for deleted
                files or ``"d"`` for everything except deletions.

        Returns:
            Repository-relative paths, or ``None`` when there is no usable checkpoint.
        """
        previous_commit = self.load_sync_commit()
        if not previous_commit:
            return None

        try:
            result = subprocess.run(
                [
                    "git",
                    "diff",
                    "--name-only",
                    f"--diff-filter={diff_filter}",
                    previous_commit,
                    "HEAD",
                    "--",
                    "cves",
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as e:
            logger.warning(f"Unable to calculate changed CVE files: {e}")
            return None

        names: list[str] = []
        for name in result.stdout.splitlines():
            parts = Path(name).parts
            if not name.endswith(".json") or not Path(name).name.startswith("CVE-"):
                continue
            if self.years_filter:
                try:
                    if int(parts[1]) not in self.years_filter:
                        continue
                except (IndexError, ValueError):
                    continue
            names.append(name)
        return names

    def current_commit(self) -> str | None:
        """Return the current repository commit hash."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None
        return result.stdout.strip() or None

    def load_sync_commit(self) -> str | None:
        """Load the commit recorded by the last successful sync."""
        return self.state.get("commit")

    def save_sync_commit(self) -> bool:
        """Record the current repository commit after a successful sync."""
        commit = self.current_commit()
        if not commit:
            return False
        return self.state.set("commit", commit)

    def count_cves(self) -> int:
        """Count total CVE files in the repository.

        Returns:
            Number of CVE JSON files.
        """
        count = 0
        for _ in self.iter_cve_files():
            count += 1
        return count

    def parse_cve_file(self, file_path: Path) -> CVE | None:
        """Parse a single CVE JSON file.

        Args:
            file_path: Path to the CVE JSON file.

        Returns:
            Parsed CVE object, or None if parsing fails.
        """
        try:
            with file_path.open() as f:
                data = json.load(f)
            return CVE.from_cve_v5(data)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return None

    def iter_cves(self, changed_only: bool = False) -> Generator[CVE, None, None]:
        """Iterate over all CVEs in the repository.

        Yields:
            Parsed CVE objects.
        """
        for file_path in self.iter_cve_files(changed_only=changed_only):
            cve = self.parse_cve_file(file_path)
            if cve:
                yield cve

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the CVE List V5 repository.

        Returns:
            Dictionary with repository stats.
        """
        cves_dir = self.repo_path / "cves"

        if not cves_dir.exists():
            return {
                "status": "not_cloned",
                "repo_path": str(self.repo_path),
            }

        # Count CVEs by year
        year_counts: dict[int, int] = {}
        total = 0

        for file_path in self.iter_cve_files():
            total += 1
            # Extract year from path (e.g., cves/2024/0xxx/CVE-2024-0001.json)
            try:
                year = int(file_path.parts[-3])
                year_counts[year] = year_counts.get(year, 0) + 1
            except (ValueError, IndexError):
                pass

        # Get latest commit info
        commit_info = self._get_commit_info()

        return {
            "status": "ready",
            "repo_path": str(self.repo_path),
            "total_cves": total,
            "cves_by_year": dict(sorted(year_counts.items())),
            "years_filter": self.years_filter,
            **commit_info,
        }

    def _get_commit_info(self) -> dict[str, str]:
        """Get information about the latest commit.

        Returns:
            Dictionary with commit hash and date.
        """
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%H|%ci|%s"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
            )
            parts = result.stdout.strip().split("|", 2)
            if len(parts) >= 3:
                return {
                    "commit_hash": parts[0][:12],
                    "commit_date": parts[1],
                    "commit_message": parts[2][:100],
                }
        except Exception:
            pass
        return {}
