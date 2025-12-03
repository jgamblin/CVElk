# CVElk - Vulnerability Intelligence Platform

[![CI](https://github.com/jgamblin/CVElk/actions/workflows/ci.yml/badge.svg)](https://github.com/jgamblin/CVElk/actions/workflows/ci.yml)
[![Security](https://github.com/jgamblin/CVElk/actions/workflows/security.yml/badge.svg)](https://github.com/jgamblin/CVElk/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A world-class vulnerability intelligence platform that imports CVE data from **NVD**, **EPSS**, and **CISA KEV** into Elasticsearch for analysis and visualization with Kibana.

![CVElk Dashboard](Images/Dashboard.png)

## ✨ Features

- **NVD 2.0 API Integration** - Fetch CVE data from the latest NVD API with automatic pagination and rate limiting
- **EPSS Scoring** - Enrich CVEs with Exploit Prediction Scoring System probabilities
- **CISA KEV Catalog** - Flag vulnerabilities known to be actively exploited
- **Elasticsearch + Kibana** - Powerful search, analysis, and visualization
- **Modern CLI** - Beautiful command-line interface with rich output
- **Docker Ready** - One-command deployment with security enabled
- **Async & Fast** - Built with modern Python async patterns

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/jgamblin/CVElk.git
cd CVElk

# Copy and configure environment variables
cp docker/.env.example docker/.env
# Edit docker/.env with your settings (especially passwords!)

# Start Elasticsearch and Kibana (secure mode)
cd docker && docker compose up -d

# Wait for services to be healthy (~60 seconds)
docker compose logs -f

# Run CVElk to sync data
docker run --rm --network host \
  -e ELASTICSEARCH_HOST=https://localhost:9200 \
  -e ELASTICSEARCH_PASSWORD=your-password \
  ghcr.io/jgamblin/cvelk:latest sync --days 30
```

### Option 2: Development Mode (No Security)

```bash
# Start Elasticsearch and Kibana without security
cd docker && docker compose -f docker-compose.dev.yml up -d

# Install CVElk
pip install -e ".[dev]"

# Sync recent CVEs
cvelk sync --days 7

# Set up Kibana dashboard
cvelk setup
```

### Option 3: pip Install

```bash
pip install cvelk

# Configure via environment variables
export ELASTICSEARCH_HOST=http://localhost:9200
export KIBANA_HOST=http://localhost:5601

# Sync and visualize
cvelk sync --days 30
cvelk setup
```

## 📖 Usage

### CLI Commands

```bash
# Sync CVEs from the last 7 days (default)
cvelk sync

# Sync CVEs from the last 30 days
cvelk sync --days 30

# Full sync of ALL CVEs (takes several hours)
cvelk sync --full

# Skip EPSS or KEV enrichment
cvelk sync --skip-epss --skip-kev

# Set up Kibana dashboards
cvelk setup

# Show statistics
cvelk stats

# Search for CVEs
cvelk search "log4j"
cvelk search CVE-2021-44228

# Show current configuration
cvelk config

# Get help
cvelk --help
```

### Python API

```python
import asyncio
from cvelk.config import get_settings
from cvelk.services import NVDService, EPSSService, KEVService

async def main():
    settings = get_settings()

    # Fetch recent CVEs
    nvd = NVDService(settings)
    async for cve in nvd.fetch_recent(days=7):
        print(f"{cve.cve_id}: {cve.base_score} - {cve.description[:50]}...")

asyncio.run(main())
```

## ⚙️ Configuration

CVElk is configured via environment variables or a `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `ELASTICSEARCH_HOST` | Elasticsearch URL | `http://localhost:9200` |
| `ELASTICSEARCH_USERNAME` | Elasticsearch username | `elastic` |
| `ELASTICSEARCH_PASSWORD` | Elasticsearch password | - |
| `ELASTICSEARCH_INDEX_NAME` | Index name for CVEs | `cves` |
| `KIBANA_HOST` | Kibana URL | `http://localhost:5601` |
| `NVD_API_KEY` | NVD API key (recommended) | - |
| `LOG_LEVEL` | Logging level | `INFO` |

### Getting an NVD API Key

While optional, an NVD API key increases your rate limit from 5 to 50 requests per 30 seconds:

1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form and receive your key via email
3. Set `NVD_API_KEY=your-key-here`

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   NVD 2.0 API   │     │   EPSS Feed     │     │   CISA KEV      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                          ┌──────▼──────┐
                          │   CVElk     │
                          │  (Python)   │
                          └──────┬──────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Elasticsearch       │
                    │      (CVE Index)        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │        Kibana           │
                    │     (Dashboards)        │
                    └─────────────────────────┘
```

## 🔒 Security

- **TLS/SSL** - All connections encrypted by default in production
- **Authentication** - Elasticsearch and Kibana protected with credentials
- **Non-root Docker** - Container runs as unprivileged user
- **Dependency Scanning** - Automated vulnerability scanning in CI

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## 🧪 Development

```bash
# Clone and setup
git clone https://github.com/jgamblin/CVElk.git
cd CVElk
pip install -e ".[dev]"

# Run linter
make lint

# Run tests
make test

# Run tests with coverage
make test-cov

# Format code
make format

# Type checking
make type-check
```

## 📊 Data Sources

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [NVD](https://nvd.nist.gov/) | NIST National Vulnerability Database | Real-time |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System | Daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities | As needed |

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Jerry Gamblin** - [@jgamblin](https://twitter.com/jgamblin)

## 🙏 Acknowledgments

- [NIST NVD](https://nvd.nist.gov/) for the comprehensive CVE database
- [FIRST.org](https://www.first.org/epss/) for the EPSS scoring system
- [CISA](https://www.cisa.gov/) for the KEV catalog
- [Elastic](https://www.elastic.co/) for the amazing ELK stack
