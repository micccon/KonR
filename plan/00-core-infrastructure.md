# Core Infrastructure

Two foundational components used by every other layer of the system. Neither has LLM logic — they are pure Python infrastructure that agents, the TUI, and the Orchestrator all depend on.

**Files:**
- `konr/core/events.py` — EventBus pub/sub
- `konr/core/session.py` — Session state machine, CostTracker

---

## EventBus

**Purpose:** Decouples agents from the TUI. Agents publish events; the TUI subscribes to them. Neither side has a direct reference to the other.

### Event

```python
@dataclass
class Event:
    type:      EventType
    data:      dict[str, Any]   # arbitrary payload, varies by event type
    agent:     str | None       # which agent fired it (None for system events)
    timestamp: datetime         # UTC, auto-set at creation
```

### EventType

All 20 event types, grouped by concern:

| Group | EventType | Fired by |
|-------|-----------|----------|
| Agent lifecycle | `agent.started`, `agent.finished`, `agent.error`, `agent.stuck` | `BaseAgent.run()` |
| Agent reasoning | `agent.thinking` | `BaseAgent._loop()` — text block before tool calls |
| Tool execution | `tool.called`, `tool.result` | `BaseAgent._dispatch_all()` |
| Approval gate | `approval.needed`, `approval.decided` | `BaseAgent._handle_request_approval()` / TUI |
| Findings | `finding.host`, `finding.service`, `finding.vuln`, `finding.cred`, `finding.flag` | `BaseAgent._handle_store_finding()` |
| Engagement lifecycle | `phase.started`, `phase.finished`, `engagement.done` | Orchestrator / Session |
| Session control | `session.paused`, `session.resumed`, `session.stopped` | Session |
| Cost tracking | `cost.update` | `Session.record_cost()` |
| User interaction | `user.input` | `Session.send_user_message()` |

### Publishing

```python
# Async publish — dispatches immediately to all subscribers in the current event loop
await bus.publish(event)

# Sync publish — queues for the background dispatch loop (use from sync contexts)
bus.publish_sync(event)
```

`publish()` calls handlers one at a time in subscription order. Both async and sync handlers are supported:

```python
async def async_handler(event: Event) -> None: ...  # awaited
def sync_handler(event: Event) -> None: ...          # called directly
```

### Subscription

```python
bus.subscribe(EventType.HOST_FOUND, handler)
bus.unsubscribe(EventType.HOST_FOUND, handler)  # safe even if not subscribed
```

Handlers are stored per `EventType` in a `defaultdict(list)`. A handler only receives events of the exact type it subscribed to.

### Background Dispatch Loop

For sync contexts (e.g. Textual widget callbacks that can't `await`), events are queued via `publish_sync()` and dispatched by a background task:

```python
# Start once at app startup:
asyncio.create_task(bus.run())

# Stop at shutdown:
bus.stop()
```

The loop drains the queue with a 100ms timeout, so latency from `publish_sync` to handler delivery is at most ~100ms.

### Convenience Factory

```python
# Instead of: Event(type=EventType.HOST_FOUND, agent="recon", data={"ip": "10.0.1.5"})
EventBus.make(EventType.HOST_FOUND, agent="recon", ip="10.0.1.5")
```

`make()` is a static method that accepts `**data` kwargs and wraps them into the `data` dict.

### Approval Gate Pattern

The approval gate uses the EventBus as a one-shot async rendezvous between the agent and the TUI. The agent subscribes to `APPROVAL_DECIDED` before publishing `APPROVAL_NEEDED`, then blocks on an `asyncio.Event` until the TUI fires back:

```python
decision_event = asyncio.Event()
decision_holder = {}

async def on_decided(event: Event) -> None:
    decision_holder.update(event.data)
    decision_event.set()

bus.subscribe(EventType.APPROVAL_DECIDED, on_decided)
await bus.publish(EventBus.make(EventType.APPROVAL_NEEDED, command=cmd, ...))
await decision_event.wait()          # blocks here until TUI responds
bus.unsubscribe(EventType.APPROVAL_DECIDED, on_decided)
```

---

## Session

**Purpose:** Single source of truth for the state of one engagement run. Shared across all agents for that engagement. Manages pause/resume, cost accumulation, and agent/phase tracking.

### SessionState

```
IDLE → RUNNING → PAUSED → RUNNING   (resume)
                        → STOPPING → DONE
              → STOPPING → DONE
              → DONE               (finish)
              → ERROR
```

Transitions are enforced by `_transition()`. Any illegal move raises `InvalidTransitionError`. Terminal states (`DONE`, `ERROR`) have no outgoing transitions.

### Lifecycle Methods

| Method | Transition | Side effects |
|--------|-----------|--------------|
| `await session.start()` | IDLE → RUNNING | Records `_started_at`, emits `PHASE_STARTED` |
| `await session.pause()` | RUNNING → PAUSED | Clears `_pause_event` (blocks agents) |
| `await session.resume()` | PAUSED → RUNNING | Sets `_pause_event` (unblocks agents) |
| `await session.stop()` | RUNNING/PAUSED → STOPPING → DONE | Sets `_pause_event` if paused, emits `SESSION_STOPPED` |
| `await session.finish()` | RUNNING → DONE | Records `_ended_at`, emits `ENGAGEMENT_DONE` with summary |
| `await session.error(reason)` | any → ERROR | Sets state directly (bypasses transition table), emits `AGENT_ERROR` |

### Pause Gate

Every agent calls `await session.wait_if_paused()` at the top of each iteration of its LLM loop. This blocks on an `asyncio.Event` that is cleared by `pause()` and set by `resume()` or `stop()`.

```python
# In BaseAgent._loop():
while self._tool_call_count < config.MAX_TOOL_CALLS:
    await self.session.wait_if_paused()   # blocks here while paused
    response = await llm_call(...)
```

When the user presses Ctrl+P in the TUI, `session.pause()` is called and all running agents freeze at this checkpoint. `resume()` unblocks them simultaneously.

### User Interaction

Session exposes three mechanisms for runtime user control:

```python
# Send a message — injected into the next LLM turn as guidance
await session.send_user_message("focus on port 443 first")

# Pin a permanent constraint — prepended to system prompt every iteration
# TUI: user types "!pin: only run tools against 10.0.1.0/24"
session.pinned_context               # list[str] of accumulated pins

# Skip the current task — agent checks this at the top of each loop
session.request_skip()               # sets skip_event
session.skip_event                   # asyncio.Event, cleared after agent honours it
```

### Agent Tracking

```python
session.agent_started("recon")      # adds to _active_agents set
session.agent_finished("recon")     # removes (safe if never added)
session.active_agents               # frozenset — snapshot of current runners
```

Called by `BaseAgent.run()` in its try/finally block to ensure cleanup even on error.

### Phase Tracking

```python
await session.set_phase("recon")    # sets _phase, emits PHASE_STARTED
session.current_phase               # str — current phase name
```

The TUI reads this to update the task tree header.

### Cost Tracking

```python
@dataclass
class CostTracker:
    input_tokens:       int = 0
    output_tokens:      int = 0
    cache_read_tokens:  int = 0
    cache_write_tokens: int = 0

    # Sonnet 4.6 pricing ($/M tokens)
    _INPUT_PRICE  = 3.00 / 1_000_000
    _OUTPUT_PRICE = 15.00 / 1_000_000
    _CACHE_READ   = 0.30 / 1_000_000   # 10× cheaper than input
    _CACHE_WRITE  = 3.75 / 1_000_000   # 1.25× input (amortised over cache hits)

    total_usd: float    # computed property
    as_dict() -> dict   # serialised for events and summary
```

`Session` holds one global `CostTracker` and a `dict[str, CostTracker]` per agent:

```python
await session.record_cost(
    input_tokens=100,
    output_tokens=50,
    cache_read_tokens=0,
    cache_write_tokens=0,
    agent="recon",          # optional — omit for non-agent costs
)
```

Every `record_cost()` call:
1. Adds to `session.cost` (global total)
2. Adds to `session.agent_costs[agent]` if `agent` is provided
3. Publishes `COST_UPDATE` event with the current global cost dict

### Summary

`session.summary()` returns a snapshot dict consumed by `ENGAGEMENT_DONE` and the Reporter:

```python
{
    "engagement_id": 1,
    "state":         "running",
    "phase":         "recon",
    "elapsed_s":     142.3,
    "cost": {
        "input_tokens": 45000,
        "output_tokens": 12000,
        "cache_read_tokens": 38000,
        "cache_write_tokens": 2000,
        "total_usd": 0.3214,
    },
    "agent_costs": {
        "recon": {"input_tokens": 20000, ..., "total_usd": 0.14},
        "web":   {"input_tokens": 25000, ..., "total_usd": 0.18},
    },
    "active_agents": ["recon"],
}
```

---

## How They Fit Together

```
Session ──────────────────────── owns ──────────────────────── EventBus
   │                                                               │
   │  session.pause()                          bus.publish(...)   │
   │  → clears asyncio.Event                  → dispatches to    │
   │  → agents block at wait_if_paused()        all subscribers  │
   │                                                               │
BaseAgent                                                        TUI
   │  await session.wait_if_paused()          subscribes to:     │
   │  await session.record_cost(..., agent)   - AGENT_STARTED    │
   │  await bus.publish(TOOL_CALLED)          - TOOL_RESULT      │
   │  await bus.publish(APPROVAL_NEEDED)      - APPROVAL_NEEDED  │
   │  ← awaits APPROVAL_DECIDED               → publishes        │
   │                                            APPROVAL_DECIDED  │
```

One `Session` and one `EventBus` instance are created per engagement and passed down to every agent and the TUI at startup.
