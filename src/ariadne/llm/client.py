"""LLM client wrapper using LiteLLM for multi-provider support."""

import json
import logging
import time
from typing import Any, Callable, TypeVar

from ariadne.config import AriadneConfig, get_config

logger = logging.getLogger(__name__)

T = TypeVar("T")


class LLMError(Exception):
    """Base exception for LLM errors."""

    pass


class LLMTimeoutError(LLMError):
    """Raised when an LLM request times out."""

    pass


class LLMRateLimitError(LLMError):
    """Raised when LLM rate limits are exceeded."""

    pass


class LLMClient:
    """Unified LLM client supporting multiple providers via LiteLLM.

    Supports:
    - OpenAI (openai/gpt-4, etc.)
    - Anthropic (anthropic/claude-3-opus, etc.)
    - Ollama (ollama/llama3, ollama/mixtral, etc.)
    - LM Studio (openai/local-model with custom base_url)

    Features retry logic with exponential backoff and configurable timeouts.
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
            "timeout": self.config.llm.timeout,
        }

        if self.config.llm.api_key:
            kwargs["api_key"] = self.config.llm.api_key

        if self.config.llm.base_url:
            kwargs["base_url"] = self.config.llm.base_url

        return kwargs

    def _retry_with_backoff(
        self,
        operation: Callable[[], T],
        max_retries: int | None = None,
        retry_delay: float | None = None,
    ) -> T:
        """Execute an operation with exponential backoff retry.

        Args:
            operation: Callable to execute
            max_retries: Maximum retry attempts (default: from config)
            retry_delay: Base delay between retries in seconds (default: from config)

        Returns:
            Result of the operation

        Raises:
            LLMTimeoutError: If operation times out
            LLMRateLimitError: If rate limit is exceeded
            LLMError: For other LLM errors
        """
        if max_retries is None:
            max_retries = self.config.llm.max_retries
        if retry_delay is None:
            retry_delay = self.config.llm.retry_delay

        last_exception: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                return operation()
            except Exception as e:
                last_exception = e
                error_str = str(e).lower()

                # Check for timeout errors
                if "timeout" in error_str or "timed out" in error_str:
                    if attempt >= max_retries:
                        raise LLMTimeoutError(f"LLM request timed out: {e}") from e

                # Check for rate limit errors
                if "rate" in error_str and "limit" in error_str:
                    if attempt >= max_retries:
                        raise LLMRateLimitError(f"LLM rate limit exceeded: {e}") from e
                    # Longer backoff for rate limits
                    delay = retry_delay * (4 ** attempt)
                else:
                    delay = retry_delay * (2 ** attempt)

                if attempt < max_retries:
                    logger.warning(
                        "LLM request failed (attempt %d/%d): %s. Retrying in %.1fs...",
                        attempt + 1,
                        max_retries + 1,
                        e,
                        delay,
                    )
                    time.sleep(delay)

        # Should not reach here, but handle edge case
        if last_exception:
            raise LLMError(f"LLM completion failed after {max_retries + 1} attempts: {last_exception}")
        raise LLMError("LLM completion failed for unknown reason")

    def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Get a completion from the LLM.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt

        Returns:
            The LLM's response text

        Raises:
            RuntimeError: If LiteLLM is not installed
            LLMTimeoutError: If request times out
            LLMRateLimitError: If rate limit is exceeded
            LLMError: For other LLM errors
        """
        try:
            import litellm
        except ImportError:
            raise RuntimeError(
                "LiteLLM is required for LLM integration. Install with: pip install litellm"
            )

        def _do_completion() -> str:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = self._get_completion_kwargs()
            kwargs["messages"] = messages

            response = litellm.completion(**kwargs)
            return response.choices[0].message.content or ""

        return self._retry_with_backoff(_do_completion)

    def complete_json(
        self, prompt: str, system_prompt: str | None = None
    ) -> dict[str, Any]:
        """Get a JSON-formatted completion from the LLM.

        Args:
            prompt: The user prompt (should request JSON output)
            system_prompt: Optional system prompt

        Returns:
            Parsed JSON response

        Raises:
            ValueError: If response cannot be parsed as JSON
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
        """Async version of complete.

        Note: Retry logic is not yet implemented for async. Use synchronous
        complete() if retries are needed.
        """
        try:
            import litellm
        except ImportError:
            raise RuntimeError(
                "LiteLLM is required for LLM integration. Install with: pip install litellm"
            )

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = self._get_completion_kwargs()
        kwargs["messages"] = messages

        try:
            response = await litellm.acompletion(**kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            error_str = str(e).lower()
            if "timeout" in error_str or "timed out" in error_str:
                raise LLMTimeoutError(f"LLM request timed out: {e}") from e
            if "rate" in error_str and "limit" in error_str:
                raise LLMRateLimitError(f"LLM rate limit exceeded: {e}") from e
            raise LLMError(f"LLM completion failed: {e}") from e

    def test_connection(self) -> bool:
        """Test that the LLM connection works.

        Returns:
            True if connection is successful, False otherwise
        """
        try:
            response = self.complete("Reply with just the word 'connected'.")
            return "connected" in response.lower()
        except Exception as e:
            logger.debug("LLM connection test failed: %s", e)
            return False
