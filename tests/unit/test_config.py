"""Tests for application configuration."""

from pydantic import SecretStr

from cvelk.config import NVDSettings


def test_nvd_rate_limit_defaults_to_unauthenticated_limit() -> None:
    """Use the unauthenticated NVD limit when no API key is configured."""
    settings = NVDSettings()

    assert settings.effective_rate_limit == 5


def test_nvd_rate_limit_uses_api_key_limit() -> None:
    """Use the higher NVD limit when an API key is configured."""
    settings = NVDSettings(api_key=SecretStr("test-key"))

    assert settings.effective_rate_limit == 50


def test_nvd_rate_limit_honors_custom_limit() -> None:
    """Preserve an explicitly configured NVD limit."""
    settings = NVDSettings(api_key=SecretStr("test-key"), rate_limit=10)

    assert settings.effective_rate_limit == 10
