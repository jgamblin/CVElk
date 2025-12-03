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

    def iter_cve_files(self) -> Generator[Path, None, None]:
        """Iterate over all CVE JSON files in the repository.

        Yields:
            Path to each CVE JSON file.
        """
        cves_dir = self.repo_path / "cves"
        if not cves_dir.exists():
            logger.error(f"CVE directory not found: {cves_dir}")
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

    def iter_cves(self) -> Generator[CVE, None, None]:
        """Iterate over all CVEs in the repository.

        Yields:
            Parsed CVE objects.
        """
        for file_path in self.iter_cve_files():
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


def parse_cve_v5_record(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a CVE JSON 5.x record into a normalized format.

    This function extracts and merges data from CNA and ADP containers.

    Args:
        data: Raw CVE JSON 5.x record.

    Returns:
        Normalized CVE data dictionary.
    """
    result: dict[str, Any] = {
        "cve_id": "",
        "state": "",
        "date_reserved": None,
        "date_published": None,
        "date_updated": None,
        "description": "",
        "cvss_v3": None,
        "cvss_v4": None,
        "cwes": [],
        "cpes": [],
        "references": [],
        "affected": [],
        "ssvc": None,
        "source": "CVE_V5",
    }

    # Extract metadata
    metadata = data.get("cveMetadata", {})
    result["cve_id"] = metadata.get("cveId", "")
    result["state"] = metadata.get("state", "")
    result["assigner_org_id"] = metadata.get("assignerOrgId", "")
    result["assigner_short_name"] = metadata.get("assignerShortName", "")
    result["date_reserved"] = metadata.get("dateReserved")
    result["date_published"] = metadata.get("datePublished")
    result["date_updated"] = metadata.get("dateUpdated")

    # Skip rejected/reserved CVEs
    if result["state"] != "PUBLISHED":
        return result

    containers = data.get("containers", {})

    # Parse CNA container (primary CVE data from CVE Numbering Authority)
    cna = containers.get("cna", {})
    if cna:
        _parse_cna_container(cna, result)

    # Parse ADP containers (enrichment from Authorized Data Publishers)
    adp_list = containers.get("adp", [])
    for adp in adp_list:
        _parse_adp_container(adp, result)

    return result


def _parse_cna_container(cna: dict[str, Any], result: dict[str, Any]) -> None:  # noqa: PLR0912
    """Parse CNA (CVE Numbering Authority) container.

    Args:
        cna: CNA container data.
        result: Result dictionary to update.
    """
    # Extract description
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            result["description"] = desc.get("value", "")
            break
    if not result["description"]:
        descriptions = cna.get("descriptions", [])
        if descriptions:
            result["description"] = descriptions[0].get("value", "")

    # Extract CVSS metrics
    for metric in cna.get("metrics", []):
        if "cvssV3_1" in metric:
            result["cvss_v3"] = _parse_cvss_v3(metric["cvssV3_1"])
        elif "cvssV3_0" in metric:
            result["cvss_v3"] = _parse_cvss_v3(metric["cvssV3_0"])
        elif "cvssV4_0" in metric:
            result["cvss_v4"] = _parse_cvss_v4(metric["cvssV4_0"])

    # Extract problem types (CWEs)
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id:
                result["cwes"].append(
                    {
                        "cwe_id": cwe_id,
                        "description": desc.get("description", ""),
                    }
                )

    # Extract references
    for ref in cna.get("references", []):
        result["references"].append(
            {
                "url": ref.get("url", ""),
                "tags": ref.get("tags", []),
            }
        )

    # Extract affected products
    for affected in cna.get("affected", []):
        result["affected"].append(
            {
                "vendor": affected.get("vendor", ""),
                "product": affected.get("product", ""),
                "versions": affected.get("versions", []),
                "cpes": affected.get("cpes", []),
            }
        )


def _parse_adp_container(adp: dict[str, Any], result: dict[str, Any]) -> None:  # noqa: PLR0912
    """Parse ADP (Authorized Data Publisher) container.

    Handles CISA-ADP (with SSVC, vulnrichment) and CVE Program Container.

    Args:
        adp: ADP container data.
        result: Result dictionary to update.
    """
    provider = adp.get("providerMetadata", {})
    short_name = provider.get("shortName", "")

    if short_name == "CISA-ADP":
        _parse_cisa_adp(adp, result)
    elif short_name == "CVE":
        _parse_cve_program_container(adp, result)

    # Extract additional references
    for ref in adp.get("references", []):
        url = ref.get("url", "")
        if url and not any(r["url"] == url for r in result["references"]):
            result["references"].append(
                {
                    "url": url,
                    "tags": ref.get("tags", []),
                }
            )

    # Extract additional CPEs
    for affected in adp.get("affected", []):
        for cpe in affected.get("cpes", []):
            if cpe not in result["cpes"]:
                result["cpes"].append(cpe)

    # Extract CWEs from ADP
    for pt in adp.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id and not any(c["cwe_id"] == cwe_id for c in result["cwes"]):
                result["cwes"].append(
                    {
                        "cwe_id": cwe_id,
                        "description": desc.get("description", ""),
                    }
                )

    # Extract CVSS from ADP if not already set
    for metric in adp.get("metrics", []):
        if not result["cvss_v3"]:
            if "cvssV3_1" in metric:
                result["cvss_v3"] = _parse_cvss_v3(metric["cvssV3_1"])
            elif "cvssV3_0" in metric:
                result["cvss_v3"] = _parse_cvss_v3(metric["cvssV3_0"])


def _parse_cisa_adp(adp: dict[str, Any], result: dict[str, Any]) -> None:
    """Parse CISA-ADP container with SSVC and vulnrichment data.

    Args:
        adp: CISA-ADP container data.
        result: Result dictionary to update.
    """
    for metric in adp.get("metrics", []):
        other = metric.get("other", {})
        if other.get("type") == "ssvc":
            content = other.get("content", {})
            result["ssvc"] = {
                "version": content.get("version", ""),
                "timestamp": content.get("timestamp", ""),
                "role": content.get("role", ""),
                "options": content.get("options", []),
            }
            # Extract SSVC decision values
            for opt in content.get("options", []):
                if "Exploitation" in opt:
                    result["ssvc"]["exploitation"] = opt["Exploitation"]
                elif "Automatable" in opt:
                    result["ssvc"]["automatable"] = opt["Automatable"]
                elif "Technical Impact" in opt:
                    result["ssvc"]["technical_impact"] = opt["Technical Impact"]


def _parse_cve_program_container(adp: dict[str, Any], result: dict[str, Any]) -> None:
    """Parse CVE Program Container.

    Args:
        adp: CVE Program Container data.
        result: Result dictionary to update.
    """
    # This container mainly contains transferred references
    # Already handled by the generic ADP parsing
    pass


def _parse_cvss_v3(cvss: dict[str, Any]) -> dict[str, Any]:
    """Parse CVSS v3.x data from CVE JSON 5.x format.

    Args:
        cvss: CVSS v3.x data.

    Returns:
        Normalized CVSS v3.x dictionary.
    """
    return {
        "version": cvss.get("version", "3.1"),
        "vector_string": cvss.get("vectorString", ""),
        "base_score": cvss.get("baseScore", 0.0),
        "base_severity": cvss.get("baseSeverity", "NONE"),
        "attack_vector": cvss.get("attackVector"),
        "attack_complexity": cvss.get("attackComplexity"),
        "privileges_required": cvss.get("privilegesRequired"),
        "user_interaction": cvss.get("userInteraction"),
        "scope": cvss.get("scope"),
        "confidentiality_impact": cvss.get("confidentialityImpact"),
        "integrity_impact": cvss.get("integrityImpact"),
        "availability_impact": cvss.get("availabilityImpact"),
    }


def _parse_cvss_v4(cvss: dict[str, Any]) -> dict[str, Any]:
    """Parse CVSS v4.0 data from CVE JSON 5.x format.

    Args:
        cvss: CVSS v4.0 data.

    Returns:
        Normalized CVSS v4.0 dictionary.
    """
    return {
        "version": "4.0",
        "vector_string": cvss.get("vectorString", ""),
        "base_score": cvss.get("baseScore", 0.0),
        "base_severity": cvss.get("baseSeverity", "NONE"),
    }
