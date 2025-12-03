# Changelog

All notable changes to CVElk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
