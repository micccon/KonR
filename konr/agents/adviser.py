"""Adviser — single LLM call to unstick a stalled specialist agent."""
from __future__ import annotations

from konr.agents.llm_agent import SingleCallLLMAgent
from konr.core import config

_SYSTEM_PROMPT = """You are a penetration testing adviser. A specialist agent has repeated \
the same tool call multiple times without making progress.

Review what was attempted and suggest one specific alternative approach. Name the exact tool, \
flags, and target to try. Do not repeat what was already attempted.

Be concrete and concise — respond with 2-3 sentences maximum. One actionable suggestion only."""


class Adviser(SingleCallLLMAgent):
    """Single-call LLM adviser. Not a BaseAgent — no tool loop."""

    def __init__(self) -> None:
        super().__init__(model=config.HAIKU_MODEL, system_prompt=_SYSTEM_PROMPT)

    async def generate(
        self,
        agent_name: str,
        task: str,
        recent_calls: list[tuple[str, dict]],
        findings_summary: str = "",
    ) -> str:
        user_message = _build_user_message(agent_name, task, recent_calls, findings_summary)
        return await self._call(user_message, max_tokens=256)


def _build_user_message(
    agent_name: str,
    task: str,
    recent_calls: list[tuple[str, dict]],
    findings_summary: str,
) -> str:
    parts = [
        f"Agent: {agent_name}",
        f"Task: {task}",
    ]
    if recent_calls:
        parts.append("Recent repeated calls:")
        for tool, args in recent_calls:
            parts.append(f"  - {tool}({args})")
    if findings_summary:
        parts.append(f"Relevant findings so far:\n{findings_summary}")
    parts.append("Suggest one specific alternative approach.")
    return "\n".join(parts)
