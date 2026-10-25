# Changelog

All notable changes to CVElk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Elastic Stack 9.5.5** - Updated Elasticsearch and Kibana development and production deployments.
- **Python 3.14 Image** - The Docker image now runs on Python 3.14, and CI tests Python 3.11 through 3.14.
- **NVD Rate Limits** - Configured rate limits now control the NVD client, with API-key defaults preserved.
- **Incremental V5 Sync** - Watch mode can process only CVE files changed since the last successful repository sync.
- **EPSS Units** - Dashboard thresholds and documentation now use the stored 0-100 percentage scale.
- **Dashboard Refresh** - Kibana 9 severity-aware palettes and priority-risk filtering improve analyst triage.
- **Unscored CVEs** - CVEs without a CVSS score are indexed with a null `baseScore` and `baseSeverity` instead of `0.0`/`NONE`, and the `cvssVersion` runtime field reports them as `Unscored`. Re-run `cvelk sync` to update existing documents.
- **Shared Sync Pipeline** - `sync`, `sync-v5`, `sync-nvd` and `watch` use one pipeline that indexes in batches. `sync-nvd` no longer holds every CVE in memory and gains `--batch-size`.
- **Kibana System Password** - The secure Compose stack now reads `KIBANA_SYSTEM_PASSWORD` for the `kibana_system` user, so `KIBANA_PASSWORD` is free for the CLI's own Kibana login. Rename the variable in an existing `docker/.env`.

### Fixed
- **`.env` Loading** - Prefixed settings such as `ELASTICSEARCH_HOST` in `.env` were ignored; only the `ELASTICSEARCH__HOST` form worked.
- **Docker Sync** - The image now includes `git`, which the CVE List V5 sync needs.
- **Stale EPSS/KEV in Watch Mode** - Incremental syncs now re-apply EPSS scores and KEV status to unchanged CVEs once per new feed release, and clear KEV fields for CVEs removed from the catalog.
- **Rejected CVEs** - Rejected CVEs, and records deleted from the CVE List V5 repository, are removed from the index.
- **`watch --no-skip-nvd`** - The flag now exists, so watch mode can include NVD enrichment.
- **EPSS Score Date** - The score date in the EPSS feed header is parsed again.
- **NVD CWE Placeholders** - `NVD-CWE-Other` and `NVD-CWE-noinfo` are kept as-is instead of becoming `CWE-NVD-CWE-Other`.
- **Sync Results Visible Immediately** - Syncs refresh the index when they finish, so `cvelk stats` and searches see the new documents without waiting for the 30-second refresh interval.
- **`cvelk stats` Before First Sync** - Explains that the index does not exist yet instead of printing a raw 404.
- **Example Configuration** - `docker/.env.example` now works for both Compose and the CLI (HTTP Kibana URL, CA certificate path).

### Removed
- **Unused Code** - The standalone `setup_dashboard.py` script, the programmatic dashboard fallback in `KibanaService`, and the unused `parse_cve_v5_record` parser. `cvelk setup` now requires the dashboard NDJSON file.
- **Root `docker-compose.yml`** - It ran Elasticsearch 8.17, which the 9.x client cannot connect to. Use `docker/docker-compose.yml` or `docker/docker-compose.dev.yml`.
- **Unused Dependencies** - `pandas`, `Pillow`, `fonttools` and `requests` (and their stub packages).

## [2.0.0] - 2024-XX-XX

### Added
- **NVD 2.0 API Support** - Complete migration from deprecated NVD 1.1 feeds to NVD 2.0 REST API
- **CISA KEV Integration** - Automatic enrichment with Known Exploited Vulnerabilities data
- **CVSS v4.0 Support** - Parse and store CVSS 4.0 scores alongside v3.x and v2.0
- **Modern CLI** - New command-line interface built with Typer and Rich
- **Async Architecture** - Asynchronous HTTP clients for improved performance
- **Pydantic Models** - Type-safe data validation throughout
- **Rate Limiting** - Automatic rate limiting with NVD API key support
- **Retry Logic** - Exponential backoff for transient failures
- **Docker Security** - Production-ready Docker setup with TLS and authentication
- **CI/CD Pipeline** - GitHub Actions for testing, security scanning, and releases
- **Comprehensive Tests** - Unit and integration test suite with pytest

### Changed
- **Project Structure** - Reorganized as proper Python package with `src/` layout
- **Dependencies** - Updated all dependencies to latest versions
- **Elasticsearch** - Updated to Elasticsearch 8.12 with security enabled by default
- **Configuration** - Environment-based configuration with Pydantic Settings

### Removed
- **NVD 1.1 Feeds** - Removed deprecated JSON feed support (EOL December 2023)
- **Legacy Script** - Replaced `CVElk.sh` with proper Python CLI

### Fixed
- Various bug fixes and improvements from community feedback

## [1.0.0] - 2022-XX-XX

### Added
- Initial release
- NVD 1.1 JSON feed support
- EPSS score enrichment
- Basic Kibana dashboard
- Docker Compose deployment

---

[Unreleased]: https://github.com/jgamblin/CVElk/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/jgamblin/CVElk/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/jgamblin/CVElk/releases/tag/v1.0.0
