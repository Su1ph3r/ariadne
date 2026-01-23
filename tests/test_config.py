"""Tests for Ariadne configuration."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

from ariadne.config import (
    AriadneConfig,
    LLMConfig,
    ScoringConfig,
    WebConfig,
    StorageConfig,
    load_config,
    get_config,
    set_config,
    get_ariadne_home,
)


class TestLLMConfig:
    """Test LLM configuration."""

    def test_default_values(self):
        """Test default LLM config values."""
        config = LLMConfig()

        assert config.provider == "anthropic"
        assert config.model == "claude-sonnet-4-20250514"
        assert config.temperature == 0.7
        assert config.max_tokens == 4096

    def test_env_var_substitution(self):
        """Test environment variable substitution in api_key."""
        with patch.dict(os.environ, {"MY_API_KEY": "secret-key-123"}):
            config = LLMConfig(api_key="${MY_API_KEY}")

            assert config.api_key == "secret-key-123"

    def test_env_var_not_set(self):
        """Test env var substitution when var not set."""
        config = LLMConfig(api_key="${NONEXISTENT_VAR}")

        assert config.api_key is None


class TestScoringConfig:
    """Test scoring configuration."""

    def test_default_weights(self):
        """Test default scoring weights."""
        config = ScoringConfig()

        assert config.weights.cvss == 0.3
        assert config.weights.exploit_available == 0.25
        assert config.weights.network_position == 0.2
        assert config.weights.privilege_required == 0.15
        assert config.weights.detection_likelihood == 0.1

    def test_weights_sum_to_one(self):
        """Test that default weights sum to 1.0."""
        config = ScoringConfig()
        total = (
            config.weights.cvss
            + config.weights.exploit_available
            + config.weights.network_position
            + config.weights.privilege_required
            + config.weights.detection_likelihood
        )

        assert abs(total - 1.0) < 0.001


class TestWebConfig:
    """Test web configuration."""

    def test_default_values(self):
        """Test default web config values."""
        config = WebConfig()

        assert config.host == "127.0.0.1"
        assert config.port == 8443
        assert config.debug is False
        assert config.persistent_sessions is False
        assert config.session_ttl_hours == 24


class TestStorageConfig:
    """Test storage configuration."""

    def test_default_values(self):
        """Test default storage config values."""
        config = StorageConfig()

        assert config.data_dir is None
        assert config.session_db is None

    def test_resolved_data_dir_default(self):
        """Test resolved data dir uses ariadne home."""
        config = StorageConfig()

        result = config.resolved_data_dir

        assert "ariadne" in str(result).lower() or ".ariadne" in str(result)
        assert result.name == "data"

    def test_resolved_data_dir_custom(self):
        """Test resolved data dir with custom path."""
        config = StorageConfig(data_dir="/custom/data")

        assert config.resolved_data_dir == Path("/custom/data")

    def test_resolved_session_db_default(self):
        """Test resolved session db uses ariadne home."""
        config = StorageConfig()

        result = config.resolved_session_db

        assert result.name == "sessions.db"

    def test_resolved_session_db_custom(self):
        """Test resolved session db with custom path."""
        config = StorageConfig(session_db="/custom/sessions.db")

        assert config.resolved_session_db == Path("/custom/sessions.db")


class TestAriadneConfig:
    """Test main Ariadne configuration."""

    def test_default_config(self):
        """Test default configuration."""
        config = AriadneConfig()

        assert config.llm is not None
        assert config.scoring is not None
        assert config.parsers is not None
        assert config.output is not None
        assert config.web is not None
        assert config.storage is not None

    def test_config_from_dict(self):
        """Test creating config from dict."""
        data = {
            "llm": {"provider": "openai", "model": "gpt-4"},
            "web": {"port": 9000},
        }
        config = AriadneConfig(**data)

        assert config.llm.provider == "openai"
        assert config.llm.model == "gpt-4"
        assert config.web.port == 9000


class TestGetAriadneHome:
    """Test get_ariadne_home function."""

    def test_default_home(self, tmp_path):
        """Test default home is ~/.ariadne."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove ARIADNE_HOME if set
            os.environ.pop("ARIADNE_HOME", None)

            home = get_ariadne_home()

            assert home == Path.home() / ".ariadne"

    def test_custom_home_from_env(self, tmp_path):
        """Test custom home from ARIADNE_HOME env var."""
        custom_home = tmp_path / "custom_ariadne"
        with patch.dict(os.environ, {"ARIADNE_HOME": str(custom_home)}):
            home = get_ariadne_home()

            assert home == custom_home
            assert home.exists()


class TestLoadConfig:
    """Test load_config function."""

    def test_load_from_explicit_path(self, tmp_path):
        """Test loading from explicit path."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
llm:
  provider: openai
  model: gpt-4
web:
  port: 9000
""")

        config = load_config(config_file)

        assert config.llm.provider == "openai"
        assert config.llm.model == "gpt-4"
        assert config.web.port == 9000

    def test_load_from_current_dir(self, tmp_path, monkeypatch):
        """Test loading from current directory."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
llm:
  provider: local
""")

        config = load_config()

        assert config.llm.provider == "local"

    def test_load_from_ariadne_home(self, tmp_path, monkeypatch):
        """Test loading from ~/.ariadne/."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.chdir(empty_dir)

        ariadne_home = tmp_path / "ariadne_home"
        ariadne_home.mkdir()
        config_file = ariadne_home / "config.yaml"
        config_file.write_text("""
llm:
  provider: from_home
""")

        with patch.dict(os.environ, {"ARIADNE_HOME": str(ariadne_home)}):
            config = load_config()

            assert config.llm.provider == "from_home"

    def test_load_returns_default_when_no_file(self, tmp_path, monkeypatch):
        """Test loading returns defaults when no config file."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.chdir(empty_dir)

        with patch.dict(os.environ, {"ARIADNE_HOME": str(tmp_path / "nonexistent")}):
            config = load_config()

            assert config.llm.provider == "anthropic"

    def test_load_handles_empty_yaml(self, tmp_path):
        """Test loading handles empty YAML file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        config = load_config(config_file)

        # Should return default config
        assert config.llm.provider == "anthropic"


class TestConfigSingleton:
    """Test config singleton pattern."""

    def test_get_config_returns_same_instance(self):
        """Test get_config returns same instance."""
        # Reset singleton
        import ariadne.config as config_module
        config_module._config = None

        config1 = get_config()
        config2 = get_config()

        assert config1 is config2

    def test_set_config_updates_singleton(self):
        """Test set_config updates singleton."""
        import ariadne.config as config_module
        config_module._config = None

        custom = AriadneConfig(llm=LLMConfig(provider="custom"))
        set_config(custom)

        retrieved = get_config()

        assert retrieved.llm.provider == "custom"

        # Reset
        config_module._config = None
