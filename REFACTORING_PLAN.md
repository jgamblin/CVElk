# CVElk Refactoring Plan

## Executive Summary

CVElk is a Docker-based tool for importing NVD (National Vulnerability Database) and EPSS (Exploit Prediction Scoring System) data into an Elastic Stack for analysis and visualization. This plan outlines a comprehensive refactoring strategy to modernize the codebase, improve maintainability, enhance security, and add new features to make it a world-class vulnerability intelligence platform.

---

## Current State Analysis

### Strengths
- Clear purpose and useful functionality
- Docker-based deployment for portability
- Integration with authoritative data sources (NVD, EPSS)
- Basic Kibana dashboard included

### Critical Issues Identified

| Category | Issue | Severity |
|----------|-------|----------|
| **Data Source** | NVD 1.1 JSON feeds are **deprecated** (EOL was Dec 2023) | 🔴 Critical |
| **Dependencies** | Outdated Elasticsearch/Kibana (8.4.3 vs current 8.x) | 🟠 High |
| **Dependencies** | Outdated Python packages (pandas 1.5.1, etc.) | 🟠 High |
| **Security** | No authentication on Elasticsearch/Kibana | 🔴 Critical |
| **Code Quality** | Monolithic main.py with repetitive try/except blocks | 🟡 Medium |
| **Testing** | No test coverage | 🟠 High |
| **Documentation** | Incomplete, outdated README | 🟡 Medium |
| **CI/CD** | No automated workflows | 🟡 Medium |

---

## Phase 1: Critical Updates (Week 1-2)

### 1.1 Migrate to NVD 2.0 API

**Priority: 🔴 CRITICAL**

The NVD 1.1 JSON feeds were discontinued. Must migrate to the [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities).

**Tasks:**
- [ ] Create new `nvd_api_v2.py` module for NVD 2.0 API integration
- [ ] Implement API rate limiting (with/without API key: 5/50 requests per 30 seconds)
- [ ] Add support for NVD API key authentication
- [ ] Update data parsing for new CVE JSON 5.0 schema
- [ ] Add support for CVSS 4.0 (in addition to CVSS 3.x)
- [ ] Implement incremental updates using `lastModStartDate`/`lastModEndDate` parameters
- [ ] Add retry logic with exponential backoff

**New API Endpoint:**
```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

**New Environment Variables:**
```bash
NVD_API_KEY=your-api-key  # Optional but recommended
NVD_API_RATE_LIMIT=50     # Requests per 30 seconds
```

### 1.2 Update Elastic Stack Version

**Priority: 🟠 HIGH**

**Tasks:**
- [ ] Update docker-compose.yml to Elasticsearch/Kibana 8.11+ (latest stable)
- [ ] Enable security features (required in ES 8.x)
- [ ] Generate and manage SSL certificates
- [ ] Implement proper authentication
- [ ] Update Kibana dashboard export format if needed

**Updated docker-compose.yml structure:**
```yaml
services:
  setup:
    # Certificate and credential setup container
  elasticsearch:
    # With security enabled
  kibana:
    # With security enabled
```

### 1.3 Update Python Dependencies

**Priority: 🟠 HIGH**

**Updated `pyproject.toml`:**
```toml
[tool.poetry.dependencies]
python = "^3.11"
pandas = "^2.1"
elasticsearch = "^8.11"
eland = "^8.11"
httpx = "^0.25"  # Replace requests with async-capable client
pydantic = "^2.5"  # For data validation
pydantic-settings = "^2.1"  # For configuration management
loguru = "^0.7"
tenacity = "^8.2"  # For retry logic
typer = "^0.9"  # Modern CLI framework
rich = "^13.7"  # Beautiful terminal output
```

---

## Phase 2: Architecture Refactoring (Week 3-4)

### 2.1 Project Structure Reorganization

```
CVElk/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── release.yml
│   │   └── security-scan.yml
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── docker/
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   ├── docker-compose.prod.yml
│   ├── .env.example
│   └── certs/
├── src/
│   └── cvelk/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── cve.py
│       │   ├── epss.py
│       │   └── kev.py
│       ├── services/
│       │   ├── __init__.py
│       │   ├── nvd_service.py
│       │   ├── epss_service.py
│       │   ├── kev_service.py
│       │   ├── elasticsearch_service.py
│       │   └── kibana_service.py
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── http_client.py
│       │   └── helpers.py
│       └── resources/
│           └── dashboards/
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── index.md
│   ├── installation.md
│   ├── configuration.md
│   ├── api.md
│   └── contributing.md
├── scripts/
│   ├── setup.sh
│   └── healthcheck.sh
├── Dockerfile
├── Makefile
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

### 2.2 Configuration Management with Pydantic

**Create `src/cvelk/config.py`:**

```python
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr
from typing import Optional

class ElasticsearchSettings(BaseSettings):
    host: str = Field(default="http://localhost:9200")
    username: str = Field(default="elastic")
    password: SecretStr = Field(default="")
    cloud_id: Optional[str] = None
    api_key: Optional[SecretStr] = None
    index_name: str = Field(default="cves")

    class Config:
        env_prefix = "ELASTICSEARCH_"

class NVDSettings(BaseSettings):
    api_key: Optional[SecretStr] = None
    rate_limit: int = Field(default=5)  # Requests per 30 seconds
    base_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")

    class Config:
        env_prefix = "NVD_"

class Settings(BaseSettings):
    elasticsearch: ElasticsearchSettings = ElasticsearchSettings()
    nvd: NVDSettings = NVDSettings()
    # ... other settings
```

### 2.3 Data Models with Pydantic

**Create `src/cvelk/models/cve.py`:**

```python
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
from enum import Enum

class CVSSVersion(str, Enum):
    V2 = "2.0"
    V3 = "3.1"
    V4 = "4.0"

class CVSSMetrics(BaseModel):
    version: CVSSVersion
    vector_string: str
    base_score: float
    base_severity: str
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    # ... other fields

class CVE(BaseModel):
    cve_id: str
    description: str
    published: datetime
    modified: datetime
    cvss_v3: Optional[CVSSMetrics] = None
    cvss_v4: Optional[CVSSMetrics] = None
    cwe_ids: List[str] = []
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
```

### 2.4 Service Layer Pattern

**Create `src/cvelk/services/nvd_service.py`:**

```python
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import AsyncGenerator
from ..models.cve import CVE
from ..config import Settings

class NVDService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_url = settings.nvd.base_url

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=60))
    async def fetch_cves(
        self,
        start_date: datetime = None,
        end_date: datetime = None
    ) -> AsyncGenerator[CVE, None]:
        """Fetch CVEs with pagination and rate limiting."""
        # Implementation with async/await
        pass
```

---

## Phase 3: Feature Enhancements (Week 5-6)

### 3.1 Add CISA KEV Integration

**Priority: 🟠 HIGH**

Integrate [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

**Tasks:**
- [ ] Create `kev_service.py` for KEV data fetching
- [ ] Add KEV fields to CVE model (is_kev, due_date, notes)
- [ ] Create KEV-specific Kibana visualizations
- [ ] Add KEV status to enriched CVE data

**KEV API Endpoint:**
```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### 3.2 Scheduled Data Updates

**Priority: 🟡 MEDIUM**

Implement automated data refresh using multiple strategies:

**Option A: Docker-based scheduler (Recommended)**
```yaml
services:
  scheduler:
    image: cvelk-scheduler
    environment:
      - UPDATE_INTERVAL=6h
    depends_on:
      - elasticsearch
```

**Option B: Celery/Redis for distributed scheduling**

**Tasks:**
- [ ] Add scheduler service to docker-compose
- [ ] Implement incremental updates (only changed CVEs)
- [ ] Add health monitoring and alerting
- [ ] Create update status API endpoint

### 3.3 Enhanced Kibana Dashboards

**Priority: 🟡 MEDIUM**

**New Dashboard Components:**
- [ ] EPSS Score Distribution (histogram)
- [ ] CVE Timeline (time series)
- [ ] Top 10 CWEs (pie chart)
- [ ] CVSS vs EPSS Scatter Plot
- [ ] KEV Status Overview
- [ ] Attack Vector Distribution
- [ ] Recent Critical CVEs Table
- [ ] CVE Search with filters

### 3.4 REST API Layer (Optional)

**Priority: 🟢 LOW**

Add a FastAPI-based REST API for programmatic access:

```python
from fastapi import FastAPI, Query
from typing import List

app = FastAPI(title="CVElk API", version="2.0.0")

@app.get("/api/v1/cves")
async def get_cves(
    cvss_min: float = Query(0, ge=0, le=10),
    epss_min: float = Query(0, ge=0, le=100),
    kev_only: bool = False,
    limit: int = Query(100, le=1000)
) -> List[CVE]:
    pass

@app.get("/api/v1/cves/{cve_id}")
async def get_cve(cve_id: str) -> CVE:
    pass

@app.get("/api/v1/stats")
async def get_stats() -> Stats:
    pass
```

---

## Phase 4: Quality & DevOps (Week 7-8)

### 4.1 Testing Strategy

**Unit Tests:**
```python
# tests/unit/test_nvd_service.py
import pytest
from cvelk.services.nvd_service import NVDService

class TestNVDService:
    @pytest.fixture
    def nvd_service(self, mock_settings):
        return NVDService(mock_settings)

    async def test_parse_cve_response(self, nvd_service, sample_cve_json):
        cve = nvd_service.parse_cve(sample_cve_json)
        assert cve.cve_id == "CVE-2024-12345"
        assert cve.cvss_v3.base_score == 9.8
```

**Integration Tests:**
```python
# tests/integration/test_elasticsearch.py
@pytest.mark.integration
async def test_index_cve(elasticsearch_container):
    # Test actual ES operations
    pass
```

**Test Coverage Target:** 80%+

### 4.2 CI/CD Pipeline

**`.github/workflows/ci.yml`:**
```yaml
name: CI

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Ruff
        uses: chartboost/ruff-action@v1

  test:
    runs-on: ubuntu-latest
    services:
      elasticsearch:
        image: elasticsearch:8.11.0
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
      - name: Install dependencies
        run: poetry install
      - name: Run tests
        run: poetry run pytest --cov

  security:
    runs-on: ubuntu-latest
    steps:
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
```

**`.github/workflows/release.yml`:**
```yaml
name: Release

on:
  release:
    types: [published]

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/jgamblin/cvelk:${{ github.ref_name }}
```

### 4.3 Code Quality Tools

**Add to `pyproject.toml`:**
```toml
[tool.ruff]
line-length = 100
target-version = "py311"
select = ["E", "F", "I", "N", "W", "UP", "B", "C4", "SIM"]

[tool.ruff.isort]
known-first-party = ["cvelk"]

[tool.mypy]
python_version = "3.11"
strict = true
ignore_missing_imports = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "--cov=cvelk --cov-report=xml"
```

### 4.4 Pre-commit Hooks

**`.pre-commit-config.yaml`:**
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.6
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.0
    hooks:
      - id: mypy
```

---

## Phase 5: Security Hardening (Ongoing)

### 5.1 Elasticsearch Security

**Tasks:**
- [ ] Enable TLS/SSL for all communications
- [ ] Implement role-based access control (RBAC)
- [ ] Create read-only user for Kibana dashboards
- [ ] Enable audit logging
- [ ] Implement index lifecycle management (ILM)

**Security Configuration:**
```yaml
# docker-compose.yml
services:
  elasticsearch:
    environment:
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.transport.ssl.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
```

### 5.2 Docker Security

**Tasks:**
- [ ] Use non-root user in Dockerfile
- [ ] Implement multi-stage builds
- [ ] Pin base image versions with SHA256
- [ ] Add health checks
- [ ] Scan images for vulnerabilities
- [ ] Use secrets management

**Secure Dockerfile:**
```dockerfile
# Build stage
FROM python:3.11-slim as builder
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry export -o requirements.txt

# Runtime stage
FROM python:3.11-slim
RUN useradd -m -r cvelk
WORKDIR /app
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=cvelk:cvelk src/ ./src/
USER cvelk
HEALTHCHECK CMD python -c "import cvelk; print('healthy')"
ENTRYPOINT ["python", "-m", "cvelk"]
```

### 5.3 Secrets Management

**Tasks:**
- [ ] Use Docker secrets or HashiCorp Vault
- [ ] Never commit credentials
- [ ] Implement secret rotation
- [ ] Use environment variable validation

---

## Phase 6: Documentation (Week 9)

### 6.1 README Overhaul

**New README Structure:**
1. Badges (CI status, version, license, etc.)
2. Project description with screenshot
3. Features list
4. Quick start guide
5. Configuration reference
6. Architecture diagram
7. Contributing guidelines link
8. Security policy link
9. Changelog link

### 6.2 Documentation Site

**Use MkDocs with Material theme:**

```yaml
# mkdocs.yml
site_name: CVElk Documentation
theme:
  name: material
  features:
    - navigation.tabs
    - content.code.copy
nav:
  - Home: index.md
  - Getting Started:
    - Installation: installation.md
    - Configuration: configuration.md
    - Quick Start: quickstart.md
  - User Guide:
    - Dashboards: dashboards.md
    - API Reference: api.md
  - Development:
    - Contributing: contributing.md
    - Architecture: architecture.md
```

### 6.3 API Documentation

**Auto-generate with Swagger/OpenAPI:**
- Interactive API explorer
- Request/response examples
- Authentication documentation

---

## Implementation Timeline

```
Week 1-2:  Phase 1 - Critical Updates (NVD 2.0, Dependencies)
Week 3-4:  Phase 2 - Architecture Refactoring
Week 5-6:  Phase 3 - Feature Enhancements
Week 7-8:  Phase 4 - Quality & DevOps
Week 9:    Phase 6 - Documentation
Ongoing:   Phase 5 - Security Hardening
```

---

## Migration Strategy

### For Existing Users

1. **Backup existing data:**
   ```bash
   ./scripts/backup.sh
   ```

2. **Update configuration:**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. **Run migration:**
   ```bash
   docker-compose -f docker-compose.migration.yml up
   ```

4. **Verify data integrity:**
   ```bash
   ./scripts/verify-migration.sh
   ```

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Test Coverage | 0% | 80%+ |
| Code Quality (Ruff) | N/A | 0 errors |
| Type Coverage | 0% | 90%+ |
| Docker Image Size | ~1GB | <500MB |
| Startup Time | ~45s | <15s |
| Data Freshness | Manual | <6 hours |
| Security Score | Low | A+ |

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| NVD API rate limiting | High | Implement caching, use API key |
| Breaking changes in ES 8.x | Medium | Thorough testing, gradual rollout |
| Data loss during migration | High | Backup strategy, rollback plan |
| Increased complexity | Medium | Comprehensive documentation |

---

## Resource Requirements

- **Development Time:** ~9 weeks (1 developer)
- **Infrastructure:** Docker, CI/CD runners
- **External Services:** NVD API key (recommended), GitHub Actions

---

## Quick Wins (Can Do Immediately)

1. ✅ Add `.gitignore` for Python projects
2. ✅ Add `Makefile` for common commands
3. ✅ Update README with current status
4. ✅ Add GitHub issue/PR templates
5. ✅ Set up basic CI with linting
6. ✅ Add SECURITY.md file
7. ✅ Add CONTRIBUTING.md file

---

## Conclusion

This refactoring plan transforms CVElk from a basic data import tool into a professional-grade vulnerability intelligence platform. The phased approach ensures continuous functionality while systematically improving every aspect of the codebase.

**Key Outcomes:**
- Modern, maintainable codebase
- Secure by default
- Automated testing and deployment
- Comprehensive documentation
- Extended functionality (KEV, scheduled updates, API)
- Production-ready Docker deployment

---

*Plan created: December 3, 2025*
*Last updated: December 3, 2025*
