"""Configuration management for CVElk using Pydantic Settings.

Configuration is loaded from environment variables and/or .env files.
Environment variables take precedence over .env file values.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ElasticsearchSettings(BaseSettings):
    """Elasticsearch connection settings."""

    model_config = SettingsConfigDict(env_prefix="ELASTICSEARCH_")

    host: str = Field(
        default="http://localhost:9200",
        description="Elasticsearch host URL",
    )
    username: str = Field(
        default="elastic",
        description="Elasticsearch username",
    )
    password: SecretStr = Field(
        default=SecretStr(""),
        description="Elasticsearch password",
    )
    cloud_id: str | None = Field(
        default=None,
        description="Elastic Cloud deployment ID",
    )
    api_key_id: str | None = Field(
        default=None,
        description="Elasticsearch API key ID",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="Elasticsearch API key secret",
    )
    index_name: str = Field(
        default="cves",
        description="Name of the Elasticsearch index for CVE data",
    )
    verify_certs: bool = Field(
        default=True,
        description="Whether to verify SSL certificates",
    )
    ca_certs: str | None = Field(
        default=None,
        description="Path to CA certificates file",
    )

    @property
    def is_cloud(self) -> bool:
        """Check if using Elastic Cloud."""
        return self.cloud_id is not None

    @property
    def has_api_key(self) -> bool:
        """Check if API key authentication is configured."""
        return self.api_key_id is not None and self.api_key is not None


class KibanaSettings(BaseSettings):
    """Kibana connection settings."""

    model_config = SettingsConfigDict(env_prefix="KIBANA_")

    host: str = Field(
        default="http://localhost:5601",
        description="Kibana host URL",
    )
    username: str = Field(
        default="elastic",
        description="Kibana username",
    )
    password: SecretStr = Field(
        default=SecretStr(""),
        description="Kibana password",
    )
    space_id: str = Field(
        default="default",
        description="Kibana space ID",
    )


class NVDSettings(BaseSettings):
    """NVD API settings."""

    model_config = SettingsConfigDict(env_prefix="NVD_")

    api_key: SecretStr | None = Field(
        default=None,
        description="NVD API key for higher rate limits",
    )
    base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD API base URL",
    )
    rate_limit: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Requests per 30 seconds (5 without API key, 50 with)",
    )
    results_per_page: int = Field(
        default=2000,
        ge=1,
        le=2000,
        description="Number of results per API page",
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="API request timeout in seconds",
    )

    @field_validator("rate_limit", mode="before")
    @classmethod
    def adjust_rate_limit(cls, v: int, info: "ValidationInfo") -> int:  # type: ignore[name-defined]  # noqa: F821
        """Adjust rate limit based on whether API key is provided."""
        # If api_key is set and rate_limit is at default, increase it
        return v


class EPSSSettings(BaseSettings):
    """EPSS data settings."""

    model_config = SettingsConfigDict(env_prefix="EPSS_")

    url: str = Field(
        default="https://epss.cyentia.com/epss_scores-current.csv.gz",
        description="URL for EPSS scores CSV file",
    )
    timeout: int = Field(
        default=60,
        ge=10,
        le=300,
        description="Download timeout in seconds",
    )


class KEVSettings(BaseSettings):
    """CISA KEV catalog settings."""

    model_config = SettingsConfigDict(env_prefix="KEV_")

    url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="URL for CISA KEV catalog JSON",
    )
    timeout: int = Field(
        default=30,
        ge=10,
        le=120,
        description="Download timeout in seconds",
    )


class CVEListV5Settings(BaseSettings):
    """CVE List V5 repository settings."""

    model_config = SettingsConfigDict(env_prefix="CVE_LIST_V5_")

    repo_url: str = Field(
        default="https://github.com/CVEProject/cvelistV5.git",
        description="CVE List V5 Git repository URL",
    )
    local_path: Path = Field(
        default=Path("./data/cvelistV5"),
        description="Local path to clone/store the CVE List V5 repository",
    )
    use_shallow_clone: bool = Field(
        default=True,
        description="Use shallow clone (--depth 1) for faster initial clone",
    )
    years: list[int] | None = Field(
        default=None,
        description="Specific years to process (e.g., [2023, 2024]). None means all years.",
    )

    @field_validator("local_path", mode="before")
    @classmethod
    def ensure_path(cls, v: str | Path) -> Path:
        """Ensure local_path is a Path object."""
        return Path(v) if isinstance(v, str) else v


class Settings(BaseSettings):
    """Main application settings.

    All settings can be configured via environment variables.
    Nested settings use double underscores, e.g., ELASTICSEARCH__HOST.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    # Application settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    data_dir: Path = Field(
        default=Path("./data"),
        description="Directory for storing downloaded data",
    )

    # Nested settings
    elasticsearch: ElasticsearchSettings = Field(default_factory=ElasticsearchSettings)
    kibana: KibanaSettings = Field(default_factory=KibanaSettings)
    nvd: NVDSettings = Field(default_factory=NVDSettings)
    epss: EPSSSettings = Field(default_factory=EPSSSettings)
    kev: KEVSettings = Field(default_factory=KEVSettings)
    cve_list_v5: CVEListV5Settings = Field(default_factory=CVEListV5Settings)

    @field_validator("data_dir", mode="before")
    @classmethod
    def ensure_path(cls, v: str | Path) -> Path:
        """Ensure data_dir is a Path object."""
        return Path(v) if isinstance(v, str) else v


@lru_cache
def get_settings() -> Settings:
    """Get cached application settings.

    Returns:
        Application settings instance, cached for reuse.
    """
    return Settings()
