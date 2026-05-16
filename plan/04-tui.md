# Terminal UI Design

## Overview

Built with **Textual** (Python async TUI framework). Decoupled from agent logic via the EventBus — the TUI subscribes to events and emits user input back; it has no direct reference to agents.

---

## Layout

```
╔══════════════════════════════════════════════════════════════════════╗
║ AI Pentest System v1.0 | Engagement: ACME Corp | RUNNING | $1.24   ║  ← Header
╠═══════════════════╦══════════════════════════════════════════════════╣
║                   ║                                                  ║
║  TASK TREE        ║  ACTIVITY FEED                                   ║
║  ─────────────    ║  ──────────────────────────────────────────────  ║
║  ▶ Recon [done]  ║  12:34:01  [recon]  nmap -sV -p- 10.0.1.0/24   ║
║    ├ Port scan ✓  ║  12:34:45  [recon]  Discovered 12 live hosts    ║
║    ├ DNS enum  ✓  ║  12:34:46  [recon]  10.0.1.5 — ports 22,80,443 ║
║    └ OSINT     ✓  ║  12:35:10  [web]   ffuf on http://10.0.1.5/     ║
║                   ║  12:35:44  [web]   Found: /admin /api /upload    ║
║  ▶ Web [active]  ║  12:36:02  [web]   Testing /login form...        ║
║    ├ Enum      ✓  ║                                                  ║
║    └ Exploit  ... ║  ┌─── ⚠  APPROVAL REQUIRED ───────────────────┐ ║
║                   ║  │                                              │ ║
║  ○ AD [waiting]  ║  │  Agent:    Web                               │ ║
║  ○ PostExp[wait] ║  │  Risk:     MEDIUM                            │ ║
║  ○ Report [wait] ║  │  Command:  sqlmap -u http://10.0.1.5/login   │ ║
║                   ║  │            --forms --dbs --batch             │ ║
║                   ║  │  Reason:   /login returns SQL error on ' ;  │ ║
║                   ║  │            indicates injectable parameter    │ ║
║                   ║  │                                              │ ║
║                   ║  │  [y] Approve  [n] Skip  [m] Modify  [s]Stop │ ║
║                   ║  └──────────────────────────────────────────────┘ ║
╠═══════════════════╩══════════════════════════════════════════════════╣
║  F1: Help   Ctrl+P: Pause   Ctrl+Q: Quit   Elapsed: 00:12:34        ║  ← Status bar
╚══════════════════════════════════════════════════════════════════════╝
```

---

## File Structure

```
konr/interface/
├── tui.py                    # Main Textual App class (KonrApp), layout, keybindings
└── components/
    ├── task_tree.py          # Left panel: phase/task hierarchy with status icons
    ├── activity_feed.py      # Right panel: live agent output, verbose toggle, agent filter
    ├── approval_panel.py     # Full-screen modal (push_screen) for approval requests
    ├── findings_panel.py     # Full-screen modal (push_screen) for live DB findings view
    └── status_bar.py         # Bottom: elapsed time, cost, active status, filter label
```

## Additional TUI Features (beyond original plan)

| Feature | Key | Description |
|---------|-----|-------------|
| Skip task | Ctrl+X | Stops current agent iteration cleanly; engagement continues |
| Verbose mode | v | Toggle full tool output vs. first-line summary per event |
| Agent filter | f | Cycle: show all → recon → osint → web → … → all |
| Findings panel | Tab | Push full-screen modal with live SQLite findings table |
| Agent thinking | — | `AGENT_THINKING` events shown as dim lines before tool calls |
| Input bar | — | Live input: freetext messages injected into next LLM turn |
| Pin constraints | !pin: | Type `!pin: only target 10.0.1.5` — permanent system prompt addition |
| Ready state | — | Shows target/mode info; user presses Enter to start engagement |

### Textual Message Bridge Pattern

EventBus handlers run in arbitrary async contexts and cannot safely call Textual widget methods directly. The TUI uses a bridge:

```
EventBus handler (any thread/task)
  → self.post_message(_ActivityLine(...))   # thread-safe Textual Message

Textual event handler (main loop)
  → on__activity_line(msg)
  → self.query_one("#feed").add_line(...)   # safe — runs on Textual's event loop
```

All internal messages (`_ActivityLine`, `_PhaseStarted`, `_ApprovalNeeded`, etc.) are private dataclasses defined at the top of `tui.py`. This pattern is required; do not call widget methods directly from EventBus handlers.

---

## Main App — tui.py (KonrApp)

```python
from textual.app import App, ComposeResult

class KonrApp(App[None]):
    BINDINGS = [
        Binding("enter",          "start_engagement", "Start",        priority=True),
        Binding("ctrl+backslash", "toggle_pause",     "Pause/Resume"),
        Binding("ctrl+x",         "skip_task",        "Skip Task"),
        Binding("ctrl+c",         "request_quit",     "Quit",         priority=True),
        Binding("v",              "toggle_verbose",   "Verbose",      show=False),
        Binding("f",              "cycle_filter",     "Filter",       show=False),
        Binding("tab",            "toggle_findings",  "Findings",     show=False),
    ]

    def __init__(self, session: Session, bus: EventBus, engagement_name: str,
                 engagement_coro=None, target: str = "", mode: str = "pentest",
                 log_file=None, db=None):
        ...

    def compose(self) -> ComposeResult:
        # Chrome borders rendered as explicit ╔══╗ strings (no CSS borders)
        # Achieves pixel-perfect intersections at any terminal size

    def compose(self) -> ComposeResult:
        yield EngagementHeader(self.engagement_name)
        with Horizontal():
            yield TaskTree(id="task-tree")
            yield ActivityFeed(id="activity-feed")
        yield StatusBar()

    def on_mount(self):
        # Subscribe to EventBus events using actual EventType names
        self.bus.subscribe(EventType.TOOL_CALLED, self._on_tool_called)
        self.bus.subscribe(EventType.TOOL_RESULT, self._on_tool_result)
        self.bus.subscribe(EventType.AGENT_STARTED, self._on_agent_started)
        self.bus.subscribe(EventType.AGENT_FINISHED, self._on_agent_finished)
        self.bus.subscribe(EventType.AGENT_STUCK, self._on_agent_stuck)
        self.bus.subscribe(EventType.APPROVAL_NEEDED, self._on_approval_needed)
        self.bus.subscribe(EventType.FLAG_FOUND, self._on_flag_found)
        self.bus.subscribe(EventType.COST_UPDATE, self._on_cost_update)
        self.bus.subscribe(EventType.PHASE_STARTED, self._on_phase_started)
        self.bus.subscribe(EventType.PHASE_FINISHED, self._on_phase_finished)

        asyncio.create_task(self.bus.run())  # start background dispatch loop

    # --- Event handlers — all receive an Event object (event.data has payload) ---

    def _on_tool_called(self, event: Event):
        self.query_one("#activity-feed", ActivityFeed).add_entry(
            agent=event.agent or "?",
            content=event.data.get("tool", "") + ": " + event.data.get("command", ""),
            entry_type="output",
        )

    def _on_tool_result(self, event: Event):
        self.query_one("#activity-feed", ActivityFeed).add_entry(
            agent=event.agent or "?",
            content=event.data.get("result", ""),
            entry_type="output",
        )

    def _on_agent_started(self, event: Event):
        self.query_one("#task-tree", TaskTree).set_task_active(event.agent)

    def _on_agent_finished(self, event: Event):
        self.query_one("#task-tree", TaskTree).set_task_done(event.agent)

    def _on_approval_needed(self, event: Event):
        self.mount(ApprovalPanel(event, self.bus), after="#activity-feed")
        self.query_one(ApprovalPanel).focus()

    def _on_flag_found(self, event: Event):
        self.query_one("#activity-feed", ActivityFeed).add_entry(
            agent="system",
            content=f"FLAG: {event.data.get('value', '')}",
            entry_type="flag",
        )

    def _on_cost_update(self, event: Event):
        self.query_one(StatusBar).set_cost(event.data.get("total_usd", 0.0))

    def _on_phase_started(self, event: Event):
        self.query_one("#task-tree", TaskTree).set_phase_active(event.data.get("phase", ""))

    def _on_phase_finished(self, event: Event):
        self.query_one("#task-tree", TaskTree).set_phase_done(event.data.get("phase", 0))

    def _on_agent_stuck(self, event: Event):
        self.query_one("#activity-feed", ActivityFeed).add_entry(
            agent=event.agent or "system",
            content=f"⚠ Agent stuck: {event.data.get('reason', '')}",
            entry_type="error",
        )

    # --- Key action handlers ---

    async def action_toggle_pause(self):
        if self.session.state == SessionState.PAUSED:
            await self.session.resume()
            self.query_one(StatusBar).set_status("RUNNING")
        else:
            await self.session.pause()
            self.query_one(StatusBar).set_status("PAUSED")

    def action_approve(self):
        if panel := self.query_one(ApprovalPanel, expect_type=ApprovalPanel):
            panel.respond("approved")
            panel.remove()

    def action_skip(self):
        if panel := self.query_one(ApprovalPanel, expect_type=ApprovalPanel):
            panel.respond("skipped")
            panel.remove()

    def action_quit_confirm(self):
        self.push_screen(QuitConfirmScreen())
```

---

## Components

### ActivityFeed — `components/activity_feed.py`

Right panel. Displays a scrollable, color-coded log of all agent activity.

```python
class ActivityFeed(ScrollableContainer):
    def add_entry(self, timestamp, agent, content, entry_type):
        colors = {
            "output": "white",
            "finding": "yellow",
            "flag": "bright_green bold",
            "error": "red",
            "system": "dim",
        }
        agent_colors = {
            "recon": "cyan", "web": "blue",
            "ad": "magenta", "postexploit": "red",
            "system": "dim",
        }
        self.mount(ActivityEntry(timestamp, agent, content, entry_type))
        self.scroll_end(animate=False)
```

Entry format: `12:34:01  [recon]  nmap discovered 10.0.1.5`

### TaskTree — `components/task_tree.py`

Left panel. Shows engagement → tasks → subtasks with status icons.

```
▶ Recon          [done]    ✓
  ├ Port scan              ✓
  ├ DNS enum               ✓
  └ OSINT                  ✓

▶ Web            [active]  ⟳
  ├ Enumeration            ✓
  └ Exploitation           ...

○ AD             [waiting]
○ Post-Exploit   [waiting]
○ Reporting      [waiting]
```

Status icons: `✓` done, `⟳` running, `...` pending, `✗` failed, `⏸` paused

### ApprovalPanel — `components/approval_panel.py`

Floating overlay rendered on top of the activity feed when an approval is requested.

```python
class ApprovalPanel(Widget):
    def compose(self):
        yield Label(f"Agent: {self.request.agent}")
        yield Label(f"Risk: {self.request.risk_level}", classes=f"risk-{self.request.risk_level}")
        yield Label(f"Command:\n  {self.request.command}", classes="command")
        yield Label(f"Reason: {self.request.reason}")
        yield Label("[y] Approve  [n] Skip  [m] Modify  [s] Stop")

    def respond(self, decision: str, modified_cmd: str | None = None):
        # Publish APPROVAL_DECIDED — BaseAgent is waiting on this via asyncio.Event
        self.bus.publish_sync(EventBus.make(
            EventType.APPROVAL_DECIDED,
            decision=decision,
            modified_command=modified_cmd,
        ))
```

For **[m] Modify**: TUI opens an inline input field pre-filled with the command; user edits and submits.

### StatusBar — `components/status_bar.py`

Bottom bar. Shows elapsed time, current status, active agent, and keybinds.

```
F1: Help   Ctrl+P: Pause   Ctrl+Q: Quit   [recon agent]   Elapsed: 00:12:34
```

---

## TUI CSS (Textual CSS)

```css
/* tui.css */

Screen {
    background: $surface;
}

#task-tree {
    width: 22;
    border-right: solid $primary;
    padding: 0 1;
}

#activity-feed {
    width: 1fr;
    padding: 0 1;
}

ApprovalPanel {
    width: 70%;
    height: auto;
    border: double $warning;
    background: $surface-darken-1;
    padding: 1 2;
    margin: 1 2;
    layer: dialog;
}

.risk-critical { color: $error; }
.risk-high     { color: $warning; }
.risk-medium   { color: $accent; }
.risk-low      { color: $success; }

.command {
    background: $surface-darken-2;
    padding: 0 1;
    color: $text-muted;
}

ActivityEntry.flag {
    color: bright_green;
    text-style: bold;
}
```

---

## EventBus — `core/events.py`

Decouples TUI from agent logic. Agents publish events; TUI subscribes and updates.

No singleton — one `EventBus` instance is created at startup and passed to all agents and the TUI.

### EventType enum (actual values)

```python
class EventType(str, Enum):
    # Agent lifecycle
    AGENT_STARTED    = "agent.started"
    AGENT_FINISHED   = "agent.finished"
    AGENT_ERROR      = "agent.error"
    AGENT_STUCK      = "agent.stuck"

    # Tool execution
    TOOL_CALLED      = "tool.called"
    TOOL_RESULT      = "tool.result"

    # Approval gate
    APPROVAL_NEEDED  = "approval.needed"
    APPROVAL_DECIDED = "approval.decided"   # TUI publishes this in response

    # Findings
    HOST_FOUND       = "finding.host"
    SERVICE_FOUND    = "finding.service"
    VULN_FOUND       = "finding.vuln"
    CRED_FOUND       = "finding.cred"
    FLAG_FOUND       = "finding.flag"

    # Engagement lifecycle
    PHASE_STARTED    = "phase.started"
    PHASE_FINISHED   = "phase.finished"
    ENGAGEMENT_DONE  = "engagement.done"

    # Session control
    SESSION_PAUSED   = "session.paused"
    SESSION_RESUMED  = "session.resumed"
    SESSION_STOPPED  = "session.stopped"

    # Cost tracking
    COST_UPDATE      = "cost.update"
```

### Key API

```python
# Handlers receive an Event object — extract data from event.data dict
bus.subscribe(EventType.TOOL_CALLED, handler)      # async or sync handler
bus.unsubscribe(EventType.TOOL_CALLED, handler)

await bus.publish(event)        # async — dispatches immediately
bus.publish_sync(event)         # sync — queues for background dispatch loop

asyncio.create_task(bus.run())  # start background dispatch loop (call once at startup)
bus.stop()                      # stop the loop at shutdown

# Factory for building events cleanly
EventBus.make(EventType.HOST_FOUND, agent="recon", ip="10.0.1.5")
# → Event(type=EventType.HOST_FOUND, agent="recon", data={"ip": "10.0.1.5"})
```

### Approval gate rendezvous

Agent publishes `APPROVAL_NEEDED`, blocks on `asyncio.Event`. TUI shows panel, user responds, TUI calls `bus.publish_sync(EventBus.make(EventType.APPROVAL_DECIDED, decision="approved"))`. Agent's handler sets the asyncio.Event and resumes.

---

## Session — `core/session.py`

See `plan/00-core-infrastructure.md` for full Session documentation. TUI-relevant summary:

```python
# States: IDLE → RUNNING → PAUSED → RUNNING | STOPPING → DONE | ERROR
session.state        # current SessionState enum value
session.cost         # CostTracker (total_usd, input_tokens, ...)
session.agent_costs  # dict[str, CostTracker] per agent name

# Pause gate — agents call this at the top of each LLM loop iteration
await session.wait_if_paused()   # blocks while PAUSED, resumes on resume() or stop()

# TUI calls these on Ctrl+P
await session.pause()    # RUNNING → PAUSED
await session.resume()   # PAUSED → RUNNING
await session.stop()     # any → STOPPING → DONE

# Cost is tracked automatically via record_cost() inside BaseAgent
# TUI reads it from COST_UPDATE events or directly from session.cost.total_usd
```

---

## CLI Entry Point — `cli.py`

TUI is launched from `konr/cli.py`. The CLI creates the shared infrastructure (DB, EventBus, Session, ContainerManager) and passes them to both the Orchestrator and the TUI. The Orchestrator runs as a Textual background worker.

```python
# konr/cli.py (sketch — actual implementation may differ)
from konr.core.events import EventBus
from konr.core.session import Session
from konr.storage.db import FindingsDB
from konr.agents.orchestrator import Orchestrator
from konr.container.manager import ContainerManager
from konr.interface.tui import KonrApp

def main():
    bus = EventBus()
    db = FindingsDB()
    mgr = ContainerManager()
    mgr.start(work_dir="./work")
    engagement_id = db.create_engagement(name=engagement, target_scope=target)
    session = Session(engagement_id=engagement_id, bus=bus)
    orc = Orchestrator(session=session, bus=bus, db=db,
                       executor=CommandExecutor(mgr.require_running()),
                       ctf_mode=ctf, agent_registry=build_registry())
    app = KonrApp(session=session, bus=bus, orc=orc, engagement_name=engagement)
    app.run()
```

Usage:
```bash
# Real-world pentest
konr --target 10.0.1.0/24 --engagement "ACME Q2 2026" --client "ACME Corp"

# CTF mode
konr --ctf --target 10.10.11.23 --vpn ./hackthebox.ovpn --engagement "MonitorsTwo"
```

Usage:
```bash
# Real-world pentest
pentest-ai --target 10.0.1.0/24 --engagement "ACME Q2 2026" --client "ACME Corp"

# CTF mode
pentest-ai --ctf --target 10.10.11.23 --vpn ./hackthebox.ovpn --engagement "MonitorsTwo"

# Resume paused engagement
pentest-ai --resume 3
```
