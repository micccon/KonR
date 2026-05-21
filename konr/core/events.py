"""Async pub/sub event bus — decouples agents from the TUI."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EventType(StrEnum):
    # Agent lifecycle
    AGENT_STARTED    = "agent.started"
    AGENT_FINISHED   = "agent.finished"
    AGENT_ERROR      = "agent.error"
    AGENT_STUCK      = "agent.stuck"
    AGENT_THINKING   = "agent.thinking"
    USER_INPUT       = "user.input"

    # Tool execution
    TOOL_CALLED      = "tool.called"
    TOOL_RESULT      = "tool.result"

    # Approval gate
    APPROVAL_NEEDED  = "approval.needed"
    APPROVAL_DECIDED = "approval.decided"

    # Findings
    HOST_FOUND       = "finding.host"
    SERVICE_FOUND    = "finding.service"
    VULN_FOUND       = "finding.vuln"
    CRED_FOUND       = "finding.cred"
    FLAG_FOUND       = "finding.flag"

    # Summarizer lifecycle
    SUMMARIZER_STARTED  = "summarizer.started"
    SUMMARIZER_FINISHED = "summarizer.finished"

    # Verifier lifecycle
    VERIFIER_STARTED = "verifier.started"
    VERIFIER_FINISHED = "verifier.finished"

    # Engagement lifecycle
    PHASE_STARTED    = "phase.started"
    PHASE_FINISHED   = "phase.finished"
    ENGAGEMENT_DONE  = "engagement.done"

    # Scope enforcement
    SCOPE_VIOLATION  = "scope.violation"

    # Session control
    SESSION_PAUSED   = "session.paused"
    SESSION_RESUMED  = "session.resumed"
    SESSION_STOPPED  = "session.stopped"

    # Cost tracking
    COST_UPDATE      = "cost.update"


@dataclass
class Event:
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    agent: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


AsyncHandler = Callable[[Event], Coroutine[Any, Any, None]]
SyncHandler  = Callable[[Event], None]
Handler      = AsyncHandler | SyncHandler


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Handler]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False

    # ── Subscription ──────────────────────────────────────────────────────

    def subscribe(self, event_type: EventType, handler: Handler) -> None:
        """Register a handler for the given event type."""
        self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType, handler: Handler) -> None:
        """Remove a previously registered handler. Silently ignores missing handlers."""
        try:
            self._subscribers[event_type].remove(handler)
        except ValueError:
            pass

    # ── Publishing ────────────────────────────────────────────────────────

    async def publish(self, event: Event) -> None:
        """Dispatch an event immediately to all subscribers."""
        for handler in list(self._subscribers[event.type]):
            if asyncio.iscoroutinefunction(handler):
                await handler(event)  # type: ignore[arg-type]
            else:
                handler(event)

    def publish_sync(self, event: Event) -> None:
        """Non-async publish — queues the event for the dispatch loop."""
        self._queue.put_nowait(event)

    # ── Background dispatch loop ──────────────────────────────────────────

    async def run(self) -> None:
        """Drain the queue and dispatch events. Run as a background task."""
        self._running = True
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                await self.publish(event)
                self._queue.task_done()
            except TimeoutError:
                continue

    def stop(self) -> None:
        """Signal the dispatch loop to exit on the next iteration."""
        self._running = False

    # ── Convenience factories ─────────────────────────────────────────────

    @staticmethod
    def make(
        event_type: EventType,
        agent: str | None = None,
        **data: Any,
    ) -> Event:
        """Construct an Event from keyword arguments without importing the Event dataclass."""
        return Event(type=event_type, agent=agent, data=data)
