"""Tests for LLM client."""

import json
import pytest
from unittest.mock import MagicMock, patch

from ariadne.llm.client import LLMClient
from ariadne.config import AriadneConfig, LLMConfig


class TestLLMClientInitialization:
    """Test LLM client initialization."""

    def test_initialization_with_default_config(self):
        """Test client initializes with default config."""
        with patch("ariadne.llm.client.get_config") as mock_get_config:
            mock_config = MagicMock(spec=AriadneConfig)
            mock_config.llm = MagicMock(spec=LLMConfig)
            mock_get_config.return_value = mock_config

            client = LLMClient()

            assert client.config is mock_config

    def test_initialization_with_custom_config(self):
        """Test client initializes with custom config."""
        custom_config = MagicMock(spec=AriadneConfig)
        custom_config.llm = MagicMock(spec=LLMConfig)

        client = LLMClient(config=custom_config)

        assert client.config is custom_config


class TestModelString:
    """Test model string generation."""

    @pytest.fixture
    def client_with_config(self):
        """Create client with configurable mock."""
        config = MagicMock(spec=AriadneConfig)
        config.llm = MagicMock(spec=LLMConfig)
        return LLMClient(config=config)

    def test_model_string_with_slash(self, client_with_config):
        """Test model string when model already contains provider."""
        client_with_config.config.llm.provider = "openai"
        client_with_config.config.llm.model = "anthropic/claude-3-sonnet"

        result = client_with_config._get_model_string()

        assert result == "anthropic/claude-3-sonnet"

    def test_model_string_openai(self, client_with_config):
        """Test model string for OpenAI."""
        client_with_config.config.llm.provider = "openai"
        client_with_config.config.llm.model = "gpt-4"

        result = client_with_config._get_model_string()

        assert result == "openai/gpt-4"

    def test_model_string_anthropic(self, client_with_config):
        """Test model string for Anthropic."""
        client_with_config.config.llm.provider = "anthropic"
        client_with_config.config.llm.model = "claude-3-opus"

        result = client_with_config._get_model_string()

        assert result == "anthropic/claude-3-opus"

    def test_model_string_ollama(self, client_with_config):
        """Test model string for Ollama."""
        client_with_config.config.llm.provider = "ollama"
        client_with_config.config.llm.model = "llama3"

        result = client_with_config._get_model_string()

        assert result == "ollama/llama3"

    def test_model_string_lm_studio(self, client_with_config):
        """Test model string for LM Studio."""
        client_with_config.config.llm.provider = "lm_studio"
        client_with_config.config.llm.model = "local-model"

        result = client_with_config._get_model_string()

        assert result == "openai/local-model"

    def test_model_string_unknown_provider(self, client_with_config):
        """Test model string for unknown provider."""
        client_with_config.config.llm.provider = "custom"
        client_with_config.config.llm.model = "my-model"

        result = client_with_config._get_model_string()

        assert result == "custom/my-model"


class TestCompletionKwargs:
    """Test completion kwargs generation."""

    @pytest.fixture
    def client_with_config(self):
        """Create client with configurable mock."""
        config = MagicMock(spec=AriadneConfig)
        config.llm = MagicMock(spec=LLMConfig)
        config.llm.provider = "openai"
        config.llm.model = "gpt-4"
        config.llm.temperature = 0.7
        config.llm.max_tokens = 4096
        config.llm.api_key = None
        config.llm.base_url = None
        return LLMClient(config=config)

    def test_basic_kwargs(self, client_with_config):
        """Test basic completion kwargs."""
        kwargs = client_with_config._get_completion_kwargs()

        assert kwargs["model"] == "openai/gpt-4"
        assert kwargs["temperature"] == 0.7
        assert kwargs["max_tokens"] == 4096
        assert "api_key" not in kwargs
        assert "base_url" not in kwargs

    def test_kwargs_with_api_key(self, client_with_config):
        """Test kwargs include API key when set."""
        client_with_config.config.llm.api_key = "sk-test-key"

        kwargs = client_with_config._get_completion_kwargs()

        assert kwargs["api_key"] == "sk-test-key"

    def test_kwargs_with_base_url(self, client_with_config):
        """Test kwargs include base URL when set."""
        client_with_config.config.llm.base_url = "http://localhost:1234"

        kwargs = client_with_config._get_completion_kwargs()

        assert kwargs["base_url"] == "http://localhost:1234"


class TestComplete:
    """Test complete method."""

    @pytest.fixture
    def mock_litellm(self):
        """Create mock litellm module."""
        with patch.dict("sys.modules", {"litellm": MagicMock()}):
            import sys
            mock = sys.modules["litellm"]
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "Test response"
            mock.completion.return_value = mock_response
            yield mock

    @pytest.fixture
    def client_with_config(self):
        """Create client with mock config."""
        config = MagicMock(spec=AriadneConfig)
        config.llm = MagicMock(spec=LLMConfig)
        config.llm.provider = "openai"
        config.llm.model = "gpt-4"
        config.llm.temperature = 0.7
        config.llm.max_tokens = 4096
        config.llm.api_key = "test-key"
        config.llm.base_url = None
        return LLMClient(config=config)

    def test_complete_basic(self, client_with_config, mock_litellm):
        """Test basic completion."""
        result = client_with_config.complete("Hello")

        assert result == "Test response"
        mock_litellm.completion.assert_called_once()

    def test_complete_with_system_prompt(self, client_with_config, mock_litellm):
        """Test completion with system prompt."""
        result = client_with_config.complete("Hello", system_prompt="Be helpful")

        assert result == "Test response"
        call_kwargs = mock_litellm.completion.call_args[1]
        messages = call_kwargs["messages"]
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "Be helpful"
        assert messages[1]["role"] == "user"
        assert messages[1]["content"] == "Hello"

    def test_complete_without_system_prompt(self, client_with_config, mock_litellm):
        """Test completion without system prompt."""
        result = client_with_config.complete("Hello")

        call_kwargs = mock_litellm.completion.call_args[1]
        messages = call_kwargs["messages"]
        assert len(messages) == 1
        assert messages[0]["role"] == "user"

    def test_complete_handles_empty_response(self, client_with_config, mock_litellm):
        """Test completion handles empty response."""
        mock_litellm.completion.return_value.choices[0].message.content = None

        result = client_with_config.complete("Hello")

        assert result == ""


class TestCompleteJson:
    """Test complete_json method."""

    @pytest.fixture
    def mock_litellm(self):
        """Create mock litellm module."""
        with patch.dict("sys.modules", {"litellm": MagicMock()}):
            import sys
            mock = sys.modules["litellm"]
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = '{"key": "value"}'
            mock.completion.return_value = mock_response
            yield mock

    @pytest.fixture
    def client_with_config(self):
        """Create client with mock config."""
        config = MagicMock(spec=AriadneConfig)
        config.llm = MagicMock(spec=LLMConfig)
        config.llm.provider = "openai"
        config.llm.model = "gpt-4"
        config.llm.temperature = 0.7
        config.llm.max_tokens = 4096
        config.llm.api_key = "test-key"
        config.llm.base_url = None
        return LLMClient(config=config)

    def test_complete_json_parses_response(self, client_with_config, mock_litellm):
        """Test JSON completion parses response."""
        result = client_with_config.complete_json("Give me JSON")

        assert result == {"key": "value"}

    def test_complete_json_strips_markdown(self, client_with_config, mock_litellm):
        """Test JSON completion strips markdown code blocks."""
        mock_litellm.completion.return_value.choices[0].message.content = (
            '```json\n{"key": "value"}\n```'
        )

        result = client_with_config.complete_json("Give me JSON")

        assert result == {"key": "value"}

    def test_complete_json_strips_plain_code_blocks(self, client_with_config, mock_litellm):
        """Test JSON completion strips plain code blocks."""
        mock_litellm.completion.return_value.choices[0].message.content = (
            '```\n{"key": "value"}\n```'
        )

        result = client_with_config.complete_json("Give me JSON")

        assert result == {"key": "value"}

    def test_complete_json_adds_system_prompt(self, client_with_config, mock_litellm):
        """Test JSON completion adds JSON instruction to system prompt."""
        client_with_config.complete_json("Give me JSON", system_prompt="Be helpful")

        call_kwargs = mock_litellm.completion.call_args[1]
        messages = call_kwargs["messages"]
        system_content = messages[0]["content"]
        assert "valid JSON" in system_content
        assert "Be helpful" in system_content

    def test_complete_json_creates_system_prompt_when_none(self, client_with_config, mock_litellm):
        """Test JSON completion creates system prompt when none provided."""
        client_with_config.complete_json("Give me JSON")

        call_kwargs = mock_litellm.completion.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert "valid JSON" in messages[0]["content"]

    def test_complete_json_raises_on_invalid_json(self, client_with_config, mock_litellm):
        """Test JSON completion raises on invalid JSON."""
        mock_litellm.completion.return_value.choices[0].message.content = "not valid json"

        with pytest.raises(ValueError) as excinfo:
            client_with_config.complete_json("Give me JSON")

        assert "Failed to parse LLM response as JSON" in str(excinfo.value)


class TestTestConnection:
    """Test connection testing."""

    @pytest.fixture
    def client_with_config(self):
        """Create client with mock config."""
        config = MagicMock(spec=AriadneConfig)
        config.llm = MagicMock(spec=LLMConfig)
        config.llm.provider = "openai"
        config.llm.model = "gpt-4"
        config.llm.temperature = 0.7
        config.llm.max_tokens = 4096
        config.llm.api_key = "test-key"
        config.llm.base_url = None
        return LLMClient(config=config)

    def test_connection_success(self, client_with_config):
        """Test successful connection test."""
        with patch.object(client_with_config, "complete", return_value="Connected!"):
            result = client_with_config.test_connection()

        assert result is True

    def test_connection_failure_wrong_response(self, client_with_config):
        """Test connection test fails with wrong response."""
        with patch.object(client_with_config, "complete", return_value="Something else"):
            result = client_with_config.test_connection()

        assert result is False

    def test_connection_failure_exception(self, client_with_config):
        """Test connection test fails on exception."""
        with patch.object(client_with_config, "complete", side_effect=Exception("Error")):
            result = client_with_config.test_connection()

        assert result is False


class TestErrorHandling:
    """Test error handling."""

    @pytest.fixture
    def client_with_config(self):
        """Create client with mock config."""
        config = MagicMock(spec=AriadneConfig)
        config.llm = MagicMock(spec=LLMConfig)
        config.llm.provider = "openai"
        config.llm.model = "gpt-4"
        config.llm.temperature = 0.7
        config.llm.max_tokens = 4096
        config.llm.api_key = "test-key"
        config.llm.base_url = None
        return LLMClient(config=config)

    def test_complete_raises_on_litellm_error(self, client_with_config):
        """Test complete raises RuntimeError on LiteLLM error."""
        with patch.dict("sys.modules", {"litellm": MagicMock()}) as mock_modules:
            import sys
            mock = sys.modules["litellm"]
            mock.completion.side_effect = Exception("API Error")

            with pytest.raises(RuntimeError) as excinfo:
                client_with_config.complete("Hello")

            assert "LLM completion failed" in str(excinfo.value)
