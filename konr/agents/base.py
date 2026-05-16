"""BaseAgent — shared LLM loop, tool dispatch, stuck detection, prompt caching."""
from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from dataclasses import dataclass
from typing import Any

import anthropic
import tenacity

from konr.agents.definitions import SPECIALIST_TOOLS
from konr.agents.tool_handlers import ToolHandlerMixin
from konr.agents.utils import extract_text
from konr.container.executor import CommandExecutor
from konr.core import config
from konr.core.approvals import ScopeChecker
from konr.core.errors import ApprovalDeniedError
from konr.core.events import EventBus, EventType
from konr.core.session import Session, SessionState
from konr.storage.db import FindingsDB
from konr.storage.memory import VectorMemory


@dataclass
class AgentResult:
    success: bool
    summary: str
    findings_count: int = 0
    error: str | None = None


class BaseAgent(ToolHandlerMixin):
    """
    Async LLM agent loop using the Anthropic tool_use API.

    Subclasses must implement:
      - system_prompt() -> str
      - tools() -> list[dict]   (defaults to SPECIALIST_TOOLS)
    """

    name: str = "base"
    model: str = config.SONNET_MODEL

    def __init__(
        self,
        engagement_id: int,
        session: Session,
        bus: EventBus,
        db: FindingsDB,
        executor: CommandExecutor | None = None,
        ctf_mode: bool = False,
        scope: ScopeChecker | None = None,
        memory: VectorMemory | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.session = session
        self.bus = bus
        self.db = db
        self.executor = executor
        self.ctf_mode = ctf_mode
        self.scope = scope
        self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        self._memory: VectorMemory | None = memory
        self._tool_call_count = 0
        self._recent_calls: deque[str] = deque(maxlen=config.STUCK_THRESHOLD)
        self._findings_count = 0

    # ── Subclass interface ────────────────────────────────────────────────────

    def system_prompt(self) -> str:
        """Return the system prompt string for this specialist. Must be overridden."""
        raise NotImplementedError(f"{self.__class__.__name__} must implement system_prompt()")

    def tools(self) -> list[dict[str, Any]]:
        """Return the tool schemas passed to the API. Subclasses may override to restrict the tool set."""
        return SPECIALIST_TOOLS

    @property
    def _max_tool_calls(self) -> int:
        """CTF engagements use a lower cap to keep runs fast and focused."""
        return config.MAX_TOOL_CALLS_CTF if self.ctf_mode else config.MAX_TOOL_CALLS

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run(self, task: str, context: dict[str, Any] | None = None) -> AgentResult:
        self.session.agent_started(self.name)
        await self.bus.publish(
            EventBus.make(EventType.AGENT_STARTED, agent=self.name, task=task)
        )

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": self._build_initial_message(task, context or {})}
        ]

        try:
            result = await self._loop(messages)
            await self.bus.publish(
                EventBus.make(EventType.AGENT_FINISHED, agent=self.name, summary=result.summary)
            )
            self.db.log_action(
                self.engagement_id, self.name, "task_complete", summary=result.summary
            )
            return result

        except ApprovalDeniedError as exc:
            if exc.decision == "stopped":
                await self.session.stop()
            return AgentResult(
                success=False,
                summary="",
                error=f"Approval {exc.decision} by user",
            )

        except Exception as exc:
            await self.bus.publish(
                EventBus.make(EventType.AGENT_ERROR, agent=self.name, reason=str(exc))
            )
            return AgentResult(success=False, summary="", error=str(exc))

        finally:
            self.session.agent_finished(self.name)

    async def _loop(self, messages: list[dict[str, Any]]) -> AgentResult:
        """Core tool-use loop: call the API, dispatch tools, repeat until done or limit hit."""
        while self._tool_call_count < self._max_tool_calls:
            await self.session.wait_if_paused()
            if self.session.state in (SessionState.STOPPING, SessionState.DONE):
                return AgentResult(
                    success=True,
                    summary="Stopped by user",
                    findings_count=self._findings_count,
                )

            if self.session.skip_event.is_set():
                self.session.skip_event.clear()
                return AgentResult(
                    success=True,
                    summary="Skipped by user request",
                    findings_count=self._findings_count,
                )

            self._drain_user_messages(messages)
            messages = self._trim_history(messages)

            # Rebuild system each iteration so pinned context is always current
            system: list[dict[str, Any]] = [
                {"type": "text", "text": self.system_prompt(),
                 "cache_control": {"type": "ephemeral"}}
            ]
            if self.session.pinned_context:
                pins = "\n".join(f"- {p}" for p in self.session.pinned_context)
                system.append({
                    "type": "text",
                    "text": f"\nUser constraints (always follow):\n{pins}",
                })

            response = await asyncio.to_thread(
                _api_call_with_retry,
                self._client, self.model, system, self.tools(), messages,
            )

            await self.session.record_cost(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                # Field names changed across SDK versions; getattr avoids AttributeError
                cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
                cache_write_tokens=getattr(response.usage, "cache_creation_input_tokens", 0),
                agent=self.name,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                return AgentResult(
                    success=True,
                    summary=extract_text(response.content),
                    findings_count=self._findings_count,
                )

            if response.stop_reason != "tool_use":
                return AgentResult(
                    success=False,
                    summary="",
                    error=f"Unexpected stop_reason: {response.stop_reason}",
                )

            for block in response.content:
                if getattr(block, "type", None) == "text" and block.text.strip():
                    await self.bus.publish(
                        EventBus.make(EventType.AGENT_THINKING, agent=self.name,
                                      text=block.text.strip())
                    )

            tool_results = await self._dispatch_all(response.content)

            for result in tool_results:
                if result.get("_task_complete"):
                    return AgentResult(
                        success=True,
                        summary=result["_summary"],
                        findings_count=result.get("_findings_count", self._findings_count),
                    )

            messages.append({"role": "user", "content": tool_results})

        return AgentResult(
            success=False,
            summary="",
            error=f"Hit max tool calls ({self._max_tool_calls})",
        )

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    async def _dispatch_all(self, content: list[Any]) -> list[dict[str, Any]]:
        """Execute all tool_use blocks in the response sequentially, respecting pause/stop state."""
        results = []
        for block in content:
            if block.type != "tool_use":
                continue

            await self.session.wait_if_paused()
            if self.session.state in (SessionState.STOPPING, SessionState.DONE):
                break

            self._tool_call_count += 1

            if self._check_stuck(block.name, block.input):
                self.bus.publish_sync(EventBus.make(
                    EventType.AGENT_STUCK, agent=self.name,
                    reason=(
                        f"Repeated '{block.name}' {config.STUCK_THRESHOLD}×"
                        " with identical inputs"
                    ),
                ))
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": (
                        f"[stuck] You've called '{block.name}' with identical inputs "
                        f"{config.STUCK_THRESHOLD} times. Change your approach — "
                        "try a different tool, different flags, or a different target."
                    ),
                })
                continue

            await self.bus.publish(
                EventBus.make(
                    EventType.TOOL_CALLED,
                    agent=self.name,
                    tool=block.name,
                    input=block.input,
                )
            )

            output = await self._dispatch(block.name, block.input)

            await self.bus.publish(
                EventBus.make(
                    EventType.TOOL_RESULT,
                    agent=self.name,
                    tool=block.name,
                    output=output if isinstance(output, str) else json.dumps(output),
                )
            )

            if isinstance(output, dict) and output.get("_task_complete"):
                results.append(output)
            else:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output if isinstance(output, str) else json.dumps(output),
                })

        return results

    async def _dispatch(self, name: str, inputs: dict[str, Any]) -> Any:
        """Route a tool call by name to the appropriate handler method."""
        match name:
            case "execute_command":
                return await self._handle_execute_command(inputs)
            case "read_file":
                return await self._handle_read_file(inputs)
            case "write_file":
                return await self._handle_write_file(inputs)
            case "store_finding":
                return await self._handle_store_finding(inputs)
            case "request_approval":
                return await self._handle_request_approval(inputs)
            case "search_memory":
                return await self._handle_search_memory(inputs)
            case "delegate_to_coder":
                return await self._handle_delegate_to_coder(inputs)
            case "task_complete":
                return self._handle_task_complete(inputs)
            case _:
                return f"Unknown tool: {name}"

    # ── Stuck detection ───────────────────────────────────────────────────────

    def _check_stuck(self, tool_name: str, inputs: dict[str, Any]) -> bool:
        sig = _call_signature(tool_name, inputs)
        self._recent_calls.append(sig)
        if (
            len(self._recent_calls) == self._recent_calls.maxlen
            and len(set(self._recent_calls)) == 1
        ):
            # Clear so the next N calls start a fresh window rather than
            # immediately retriggering on the first different call.
            self._recent_calls.clear()
            return True
        return False

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_initial_message(self, task: str, context: dict[str, Any]) -> str:
        """Build the first user message, injecting dependency results and confirmed DB findings."""
        parts = [f"Task: {task}"]
        if context:
            deps = context.get("dependency_results", [])
            if deps:
                # Emit structured findings from prior agents so this agent can act on them
                # without re-discovering what was already found.
                structured: list[dict[str, Any]] = []
                for d in deps:
                    entry: dict[str, Any] = {
                        "from": d["task_id"],
                        "status": d["status"],
                        "findings_count": d["findings_count"],
                        "summary": d["summary"],
                    }
                    # Pull confirmed credentials and vulns out of the DB for direct use
                    try:
                        creds = self.db.get_credentials(self.engagement_id)
                        if creds:
                            entry["confirmed_credentials"] = [
                                {"username": c.get("username"), "secret": c.get("secret"),
                                 "secret_type": c.get("secret_type"), "domain": c.get("domain")}
                                for c in creds
                            ]
                        vulns = self.db.get_vulnerabilities(self.engagement_id)
                        if vulns:
                            entry["confirmed_vulnerabilities"] = [
                                {"title": v.get("title"), "severity": v.get("severity"),
                                 "description": v.get("description", "")[:200]}
                                for v in vulns
                            ]
                    except Exception:
                        pass
                    structured.append(entry)
                parts.append(
                    "Prior agent findings (use these directly — do not rediscover):\n"
                    + json.dumps(structured, indent=2)
                )
            parts.append(f"Full context:\n{json.dumps(context, indent=2)}")
        return "\n\n".join(parts)

    def _drain_user_messages(self, messages: list) -> None:
        """Inject any pending user guidance into the last message."""
        pending: list[str] = []
        while not self.session.user_messages.empty():
            try:
                pending.append(self.session.user_messages.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not pending:
            return
        note = "User guidance (adjust your approach):\n" + "\n".join(f"- {m}" for m in pending)
        last = messages[-1]
        if isinstance(last["content"], list):
            messages[-1] = {
                "role": "user",
                "content": last["content"] + [{"type": "text", "text": note}],
            }
        else:
            messages[-1] = {"role": "user", "content": f"{last['content']}\n\n{note}"}

    def _trim_history(self, messages: list) -> list:
        """Keep only the last MAX_HISTORY_PAIRS tool exchanges to bound context growth."""
        max_len = config.MAX_HISTORY_PAIRS * 2
        if len(messages) - 1 > max_len:
            # messages[0] is the original task prompt — always preserved outside the sliding window
            return [messages[0]] + messages[-max_len:]
        return messages


# ── Module-level helpers ──────────────────────────────────────────────────────

@tenacity.retry(
    retry=tenacity.retry_if_exception_type(
        (anthropic.APIStatusError, anthropic.RateLimitError, anthropic.APIConnectionError)
    ),
    wait=tenacity.wait_exponential(multiplier=2, min=4, max=60),
    stop=tenacity.stop_after_attempt(5),
    reraise=True,
)
def _api_call_with_retry(
    client: anthropic.Anthropic,
    model: str,
    system: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> Any:
    return client.messages.create(
        model=model,
        max_tokens=8096,
        system=system,  # type: ignore[arg-type]
        tools=tools,    # type: ignore[arg-type]
        messages=messages,
    )


def _call_signature(tool_name: str, inputs: dict[str, Any]) -> str:
    # MD5 used purely for compact identity comparison, not cryptographic security.
    canonical = json.dumps(inputs, sort_keys=True)
    return hashlib.md5(f"{tool_name}:{canonical}".encode()).hexdigest()
