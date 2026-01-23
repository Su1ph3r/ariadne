"""LLM client wrapper using LiteLLM for multi-provider support."""

import json
from typing import Any

from ariadne.config import AriadneConfig, get_config


class LLMClient:
    """Unified LLM client supporting multiple providers via LiteLLM.

    Supports:
    - OpenAI (openai/gpt-4, etc.)
    - Anthropic (anthropic/claude-3-opus, etc.)
    - Ollama (ollama/llama3, ollama/mixtral, etc.)
    - LM Studio (openai/local-model with custom base_url)
    """

    def __init__(self, config: AriadneConfig | None = None) -> None:
        self.config = config or get_config()
        self._client = None

    def _get_model_string(self) -> str:
        """Get the LiteLLM model string."""
        provider = self.config.llm.provider.lower()
        model = self.config.llm.model

        if "/" in model:
            return model

        provider_prefixes = {
            "openai": "openai",
            "anthropic": "anthropic",
            "ollama": "ollama",
            "lm_studio": "openai",
        }

        prefix = provider_prefixes.get(provider, provider)
        return f"{prefix}/{model}"

    def _get_completion_kwargs(self) -> dict[str, Any]:
        """Get kwargs for the completion call."""
        kwargs: dict[str, Any] = {
            "model": self._get_model_string(),
            "temperature": self.config.llm.temperature,
            "max_tokens": self.config.llm.max_tokens,
        }

        if self.config.llm.api_key:
            kwargs["api_key"] = self.config.llm.api_key

        if self.config.llm.base_url:
            kwargs["base_url"] = self.config.llm.base_url

        return kwargs

    def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Get a completion from the LLM.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt

        Returns:
            The LLM's response text
        """
        try:
            import litellm

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = self._get_completion_kwargs()
            kwargs["messages"] = messages

            response = litellm.completion(**kwargs)
            return response.choices[0].message.content or ""

        except ImportError:
            raise RuntimeError(
                "LiteLLM is required for LLM integration. Install with: pip install litellm"
            )
        except Exception as e:
            raise RuntimeError(f"LLM completion failed: {e}")

    def complete_json(
        self, prompt: str, system_prompt: str | None = None
    ) -> dict[str, Any]:
        """Get a JSON-formatted completion from the LLM.

        Args:
            prompt: The user prompt (should request JSON output)
            system_prompt: Optional system prompt

        Returns:
            Parsed JSON response
        """
        if system_prompt:
            system_prompt += "\n\nIMPORTANT: Respond only with valid JSON. No markdown, no explanation."
        else:
            system_prompt = "Respond only with valid JSON. No markdown, no explanation."

        response = self.complete(prompt, system_prompt)

        response = response.strip()
        if response.startswith("```json"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        response = response.strip()

        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse LLM response as JSON: {e}\nResponse: {response[:500]}")

    async def complete_async(self, prompt: str, system_prompt: str | None = None) -> str:
        """Async version of complete."""
        try:
            import litellm

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = self._get_completion_kwargs()
            kwargs["messages"] = messages

            response = await litellm.acompletion(**kwargs)
            return response.choices[0].message.content or ""

        except ImportError:
            raise RuntimeError("LiteLLM is required for LLM integration")
        except Exception as e:
            raise RuntimeError(f"LLM completion failed: {e}")

    def test_connection(self) -> bool:
        """Test that the LLM connection works."""
        try:
            response = self.complete("Reply with just the word 'connected'.")
            return "connected" in response.lower()
        except Exception:
            return False
