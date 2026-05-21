"""SummarizerAgent — extracts findings from a specialist's run into a structured summary file."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from konr.agents.llm_agent import SingleCallLLMAgent
from konr.core import config

_SYSTEM_PROMPT = """\
You are a findings extractor. You will receive a log of tool calls and results from a \
penetration testing specialist agent. Your job is to extract every finding into a \
structured markdown summary file.

Extract everything the specialist discovered:
- Every live host and service (ip, port, protocol, version, banner)
- Every vulnerability or weakness confirmed with evidence
- Every credential or secret found
- Every flag captured — list under a `## Flags captured` section header
- Every intelligence lead, CVE match, or version string worth investigating
- Everything attempted and what the outcome was (success or failure)

For each finding that was confirmed by command output, include the evidence in this format:
`<exact command>` → `<key part of output confirming the finding>`

Only mark something as a confirmed vulnerability if there is command output showing it worked.
Mark unverified leads, version matches, and candidates separately.

Write the summary in clean markdown. Be thorough — do not omit findings. \
The verifier will store only what you include here.\
"""


class SummarizerAgent(SingleCallLLMAgent):
    """One-shot Haiku agent that reads a specialist's message log and writes a summary file."""

    def __init__(self) -> None:
        super().__init__(model=config.HAIKU_MODEL, system_prompt=_SYSTEM_PROMPT)

    async def summarize(self, specialist_name: str, messages: list[dict[str, Any]]) -> str:
        """
        Summarize a specialist's run into /work/<name>_summary.md.
        Returns the summary content written.
        """
        log = _format_messages(messages)
        user_message = (
            f"Specialist: {specialist_name}\n\n"
            f"Tool call log:\n{log}\n\n"
            f"Write a complete findings summary for this {specialist_name} run."
        )
        summary = await self._call(user_message, max_tokens=4096)

        out_path = config.WORK_DIR / f"{specialist_name}_summary.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(summary, encoding="utf-8")

        return summary


def _format_messages(messages: list[dict[str, Any]]) -> str:
    """Flatten specialist messages into readable text for the summarizer."""
    parts: list[str] = []

    for msg in messages:
        role = msg.get("role", "?")
        content = msg.get("content", "")

        if isinstance(content, str):
            if content.strip():
                parts.append(f"[{role.upper()}] {content[:1500]}")
            continue

        if not isinstance(content, list):
            continue

        for block in content:
            btype = _get(block, "type")

            if btype == "text":
                text = _get(block, "text") or ""
                if text.strip():
                    parts.append(f"[THINKING] {text[:800]}")

            elif btype == "tool_use":
                name = _get(block, "name") or "?"
                inp = _get(block, "input") or {}
                inp_str = json.dumps(inp, default=str)[:600]
                parts.append(f"[TOOL] {name}({inp_str})")

            elif btype == "tool_result":
                result = _get(block, "content") or ""
                if isinstance(result, list):
                    result = " ".join(
                        _get(b, "text") or "" for b in result if _get(b, "type") == "text"
                    )
                r = str(result)
                if len(r) > 1500:
                    r = r[:750] + "\n...[truncated]...\n" + r[-750:]
                parts.append(f"[RESULT] {r}")

    return "\n".join(parts)


def _get(block: Any, key: str) -> Any:
    """Get attribute from either a dict or an SDK object."""
    if isinstance(block, dict):
        return block.get(key)
    return getattr(block, key, None)
