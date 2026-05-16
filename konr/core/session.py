"""Session state machine for a single engagement run."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from konr.core import config
from konr.core.events import Event, EventBus, EventType

_STOP_KEYWORDS = frozenset({"stop", "halt", "abort", "exit", "quit", "!stop"})


class SessionState(StrEnum):
    IDLE     = "idle"
    RUNNING  = "running"
    PAUSED   = "paused"
    STOPPING = "stopping"
    DONE     = "done"
    ERROR    = "error"


# Allowed transitions: state -> set of states it may move to
_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.IDLE:     {SessionState.RUNNING},
    SessionState.RUNNING:  {
        SessionState.PAUSED, SessionState.STOPPING, SessionState.DONE, SessionState.ERROR
    },
    SessionState.PAUSED:   {SessionState.RUNNING, SessionState.STOPPING},
    SessionState.STOPPING: {SessionState.DONE},
    SessionState.DONE:     set(),
    SessionState.ERROR:    set(),
}


class InvalidTransitionError(Exception):
    pass


@dataclass
class CostTracker:
    input_tokens: int  = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    _INPUT_PRICE  = config.SONNET_INPUT_PRICE
    _OUTPUT_PRICE = config.SONNET_OUTPUT_PRICE
    _CACHE_READ   = config.CACHE_READ_PRICE
    _CACHE_WRITE  = config.CACHE_WRITE_PRICE

    def add(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        """Accumulate token counts from a single API response."""
        self.input_tokens       += input_tokens
        self.output_tokens      += output_tokens
        self.cache_read_tokens  += cache_read_tokens
        self.cache_write_tokens += cache_write_tokens

    @property
    def total_usd(self) -> float:
        return (
            self.input_tokens       * self._INPUT_PRICE
            + self.output_tokens    * self._OUTPUT_PRICE
            + self.cache_read_tokens  * self._CACHE_READ
            + self.cache_write_tokens * self._CACHE_WRITE
        )

    def as_dict(self) -> dict[str, Any]:
        """Serialisable snapshot of all counters plus computed total_usd."""
        return {
            "input_tokens":       self.input_tokens,
            "output_tokens":      self.output_tokens,
            "cache_read_tokens":  self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_usd":          round(self.total_usd, 4),
        }


class Session:
    def __init__(self, engagement_id: int, bus: EventBus) -> None:
        self.engagement_id = engagement_id
        self.bus = bus
        self._state = SessionState.IDLE
        self._started_at: datetime | None = None
        self._ended_at: datetime | None = None
        self.cost = CostTracker()
        self.agent_costs: dict[str, CostTracker] = {}
        self._phase: str = ""
        self._active_agents: set[str] = set()
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # not paused initially
        # User interaction
        self.user_messages: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        self.pinned_context: list[str] = []
        self.skip_event: asyncio.Event = asyncio.Event()  # set by TUI "Skip" button; cleared after each agent reads it

    # ── State ─────────────────────────────────────────────────────────────

    @property
    def state(self) -> SessionState:
        return self._state

    def _transition(self, new_state: SessionState) -> None:
        """Move to a new state, raising if the transition is not allowed."""
        allowed = _TRANSITIONS[self._state]
        if new_state not in allowed:
            raise InvalidTransitionError(
                f"Cannot move from {self._state} to {new_state}"
            )
        self._state = new_state

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Transition to RUNNING and record start time."""
        self._transition(SessionState.RUNNING)
        self._started_at = datetime.now(UTC)
        await self.bus.publish(
            Event(type=EventType.PHASE_STARTED, data={"phase": "start"})
        )

    async def pause(self) -> None:
        """Pause execution; agents block on wait_if_paused() until resumed."""
        self._transition(SessionState.PAUSED)
        self._pause_event.clear()
        await self.bus.publish(Event(type=EventType.SESSION_PAUSED))

    async def resume(self) -> None:
        """Unblock paused agents and return to RUNNING."""
        self._transition(SessionState.RUNNING)
        self._pause_event.set()
        await self.bus.publish(Event(type=EventType.SESSION_RESUMED))

    async def stop(self) -> None:
        """Gracefully stop the engagement, unblocking any paused agents first."""
        if self._state == SessionState.PAUSED:
            self._pause_event.set()  # unblock any waiting agents
        self._transition(SessionState.STOPPING)
        await self.bus.publish(Event(type=EventType.SESSION_STOPPED))
        self._finish(SessionState.DONE)

    async def finish(self) -> None:
        """Mark the engagement complete and publish the final summary event."""
        self._transition(SessionState.DONE)
        self._finish(SessionState.DONE)
        await self.bus.publish(Event(type=EventType.ENGAGEMENT_DONE, data=self.summary()))

    async def error(self, reason: str) -> None:
        """Force the session into the ERROR state and publish the reason."""
        self._state = SessionState.ERROR
        self._ended_at = datetime.now(UTC)
        await self.bus.publish(
            Event(type=EventType.AGENT_ERROR, data={"reason": reason})
        )

    def _finish(self, final: SessionState) -> None:
        """Record end time and release the pause lock so no agent hangs on shutdown."""
        self._state = final
        self._ended_at = datetime.now(UTC)
        self._pause_event.set()

    # ── User interaction ──────────────────────────────────────────────────

    async def send_user_message(self, text: str) -> None:
        """Called from TUI when user submits the input bar."""
        text = text.strip()
        if not text:
            return
        if text.lower() in _STOP_KEYWORDS or text.lower().startswith("stop "):
            try:
                await self.stop()
            except Exception:
                pass
            await self.bus.publish(
                Event(type=EventType.USER_INPUT,
                      data={"text": "[stopping engagement]", "pinned": False})
            )
            return
        if text.startswith("!pin:"):
            pin = text[5:].strip()
            self.pinned_context.append(pin)
            await self.bus.publish(
                Event(type=EventType.USER_INPUT, data={"text": f"[pinned] {pin}", "pinned": True})
            )
        else:
            await self.user_messages.put(text)
            await self.bus.publish(
                Event(type=EventType.USER_INPUT, data={"text": text, "pinned": False})
            )

    def request_skip(self) -> None:
        """Signal the currently running agent to stop its current task."""
        self.skip_event.set()

    # ── Pause gate (agents await this before each tool call) ──────────────

    async def wait_if_paused(self) -> None:
        """Agents call this before executing any tool. Blocks while paused."""
        await self._pause_event.wait()

    # ── Agent tracking ────────────────────────────────────────────────────

    def agent_started(self, agent_name: str) -> None:
        """Register an agent as active."""
        self._active_agents.add(agent_name)

    def agent_finished(self, agent_name: str) -> None:
        """Remove an agent from the active set."""
        self._active_agents.discard(agent_name)

    @property
    def active_agents(self) -> frozenset[str]:
        """Snapshot of currently running agent names."""
        return frozenset(self._active_agents)

    # ── Phase tracking ────────────────────────────────────────────────────

    async def set_phase(self, phase: str) -> None:
        """Update the current phase label and publish a PHASE_STARTED event."""
        self._phase = phase
        await self.bus.publish(
            Event(type=EventType.PHASE_STARTED, data={"phase": phase})
        )

    @property
    def current_phase(self) -> str:
        """The phase string last set by the orchestrator (e.g. 'phase_1')."""
        return self._phase

    # ── Cost tracking ─────────────────────────────────────────────────────

    async def record_cost(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        agent: str | None = None,
    ) -> None:
        self.cost.add(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
        )
        if agent:
            if agent not in self.agent_costs:
                self.agent_costs[agent] = CostTracker()
            self.agent_costs[agent].add(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=cache_read_tokens,
                cache_write_tokens=cache_write_tokens,
            )
        agent_costs_snapshot = {
            k: round(v.total_usd, 4) for k, v in self.agent_costs.items()
        }
        await self.bus.publish(
            Event(type=EventType.COST_UPDATE,
                  data={**self.cost.as_dict(), "agent_costs": agent_costs_snapshot})
        )
        if config.MAX_COST_USD and self.cost.total_usd >= config.MAX_COST_USD:
            await self.bus.publish(Event(
                type=EventType.AGENT_ERROR,
                data={"reason": (
                    f"Spending cap ${config.MAX_COST_USD:.2f} reached"
                    f" (${self.cost.total_usd:.4f} spent)"
                )}
            ))
            if self._state == SessionState.RUNNING:
                await self.stop()

    # ── Summary ───────────────────────────────────────────────────────────

    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since start. Uses current time if not yet finished."""
        if self._started_at is None:
            return 0.0
        end = self._ended_at or datetime.now(UTC)
        return (end - self._started_at).total_seconds()

    def summary(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "state":         self._state,
            "phase":         self._phase,
            "elapsed_s":     round(self.elapsed_seconds(), 1),
            "cost":          self.cost.as_dict(),
            "agent_costs":   {
                name: tracker.as_dict() for name, tracker in self.agent_costs.items()
            },
            "active_agents": list(self._active_agents),
        }
