"""Tests for application configuration."""

from pydantic import SecretStr

from cvelk.config import NVDSettings, Settings


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


def test_dotenv_prefixed_variables_are_loaded(tmp_path, monkeypatch) -> None:
    """Prefixed names like ELASTICSEARCH_HOST in .env configure the nested sections."""
    (tmp_path / ".env").write_text(
        "ELASTICSEARCH_HOST=https://es.example:9200\n"
        "KIBANA_PASSWORD=secret\n"
        "NVD_RATE_LIMIT=7\n"
        "LOG_LEVEL=DEBUG\n"
        "ES_PORT=9200\n"
    )
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.elasticsearch.host == "https://es.example:9200"
    assert settings.kibana.password.get_secret_value() == "secret"
    assert settings.nvd.rate_limit == 7
    assert settings.log_level == "DEBUG"


def test_dotenv_nested_delimiter_still_works(tmp_path, monkeypatch) -> None:
    """The double-underscore form (ELASTICSEARCH__HOST) keeps working."""
    (tmp_path / ".env").write_text("ELASTICSEARCH__HOST=https://nested.example:9200\n")
    monkeypatch.chdir(tmp_path)

    assert Settings().elasticsearch.host == "https://nested.example:9200"


def test_environment_overrides_dotenv(tmp_path, monkeypatch) -> None:
    """Process environment variables take precedence over .env values."""
    (tmp_path / ".env").write_text("ELASTICSEARCH_HOST=https://dotenv.example:9200\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ELASTICSEARCH_HOST", "https://env.example:9200")

    assert Settings().elasticsearch.host == "https://env.example:9200"
