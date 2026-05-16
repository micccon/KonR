"""SingleCallLLMAgent — base for one-shot LLM agents (no tool loop)."""
from __future__ import annotations

import asyncio
from typing import Any

import anthropic
import tenacity

from konr.agents.utils import extract_text
from konr.core import config


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        (anthropic.APIStatusError, anthropic.RateLimitError, anthropic.APIConnectionError)
    ),
    wait=tenacity.wait_exponential(multiplier=2, min=4, max=60),
    stop=tenacity.stop_after_attempt(5),
    reraise=True,
)
def _llm_call(
    client: anthropic.Anthropic,
    model: str,
    system: list[dict[str, Any]],
    max_tokens: int,
    user_message: str,
) -> anthropic.types.Message:
    return client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,  # type: ignore[arg-type]
        messages=[{"role": "user", "content": user_message}],
    )


class SingleCallLLMAgent:
    """Base for agents that make a single LLM call and return text. No tool loop."""

    def __init__(self, model: str, system_prompt: str) -> None:
        self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        self._model = model
        self._default_system: list[dict[str, Any]] = [
            {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
        ]

    async def _call(
        self,
        user_message: str,
        max_tokens: int = 2048,
        system: list[dict[str, Any]] | None = None,
    ) -> str:
        sys = system or self._default_system
        response = await asyncio.to_thread(
            _llm_call, self._client, self._model, sys, max_tokens, user_message
        )
        return extract_text(response.content)
