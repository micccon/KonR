"""KonrApp — main Textual TUI for the KonR penetration testing system."""
from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, Static

from konr.core.events import Event, EventBus, EventType
from konr.core.session import Session, SessionState
from konr.interface.activity_feed import ActivityFeed
from konr.interface.approval_panel import ApprovalPanel
from konr.interface.findings_panel import FindingsPanel
from konr.interface.status_bar import StatusBar
from konr.interface.task_tree import TaskTree, _phase_num

# ── Chrome geometry ────────────────────────────────────────────────────────────

# Width of the TaskTree content column (not counting the ║ border widgets).
# The ╩ in the sep1 separator lands at column _LEFT_W + 1 (after the left ║).
_LEFT_W = 20


# ── Internal messages (EventBus → Textual message bridge) ─────────────────────

class _ActivityLine(Message):
    def __init__(self, agent: str, content: str, entry_type: str) -> None:
        super().__init__()
        self.agent      = agent
        self.content    = content
        self.entry_type = entry_type


class _PhaseStarted(Message):
    def __init__(self, phase: str | int) -> None:
        super().__init__()
        self.phase = phase


class _PhaseFinished(Message):
    def __init__(self, phase: int) -> None:
        super().__init__()
        self.phase = phase


class _AgentStarted(Message):
    def __init__(self, agent: str) -> None:
        super().__init__()
        self.agent = agent


class _AgentFinished(Message):
    def __init__(self, agent: str) -> None:
        super().__init__()
        self.agent = agent


class _CostUpdated(Message):
    def __init__(self, total_usd: float, agent_costs: dict[str, float] | None = None) -> None:
        super().__init__()
        self.total_usd = total_usd
        self.agent_costs = agent_costs or {}


class _AgentError(Message):
    def __init__(self, agent: str) -> None:
        super().__init__()
        self.agent = agent


class _ApprovalNeeded(Message):
    def __init__(self, event: Event) -> None:
        super().__init__()
        self.event = event


# ── Manual chrome widgets ──────────────────────────────────────────────────────

class _VertBar(Widget):
    """1-char-wide column of ║ that fills its allocated height."""

    DEFAULT_CSS = "_VertBar { width: 1; background: #000000; }"

    def render(self) -> Text:
        h = max(self.size.height, 1)
        return Text("║\n" * (h - 1) + "║", style="#003311", no_wrap=True)


class _ChromeTop(Static):
    """Full-width top border: ╔══ Title ════╗"""

    DEFAULT_CSS = "_ChromeTop { height: 1; background: #000000; }"

    def __init__(self, title: str, **kwargs) -> None:
        super().__init__("", markup=True, **kwargs)
        self._title = title

    def on_mount(self) -> None:
        self._draw()

    def on_resize(self, event) -> None:
        self._draw()

    def _draw(self) -> None:
        w = self.size.width
        prefix = f"══ {self._title} "
        fill = max(0, w - 2 - len(prefix))
        line = f"╔{prefix}{'═' * fill}╗"
        self.update(f"[#003311]{line}[/#003311]")


class _ChromeSep1(Static):
    """╠════╩════════════╣ separator between panels and input bar."""

    DEFAULT_CSS = "_ChromeSep1 { height: 1; background: #000000; }"

    def on_mount(self) -> None:
        self._draw()

    def on_resize(self, event) -> None:
        self._draw()

    def _draw(self) -> None:
        w = self.size.width
        # left of ╩: one ║ col + _LEFT_W TaskTree cols = _LEFT_W chars after ╠
        left  = "═" * _LEFT_W
        right = "═" * max(0, w - _LEFT_W - 3)  # -3 for ╠, ╩, ╣
        self.update(f"[#003311]╠{left}╩{right}╣[/#003311]")


class _ChromeSep2(Static):
    """╠═══════════════════╣ separator between input bar and status bar."""

    DEFAULT_CSS = "_ChromeSep2 { height: 1; background: #000000; }"

    def on_mount(self) -> None:
        self._draw()

    def on_resize(self, event) -> None:
        self._draw()

    def _draw(self) -> None:
        w = self.size.width
        self.update(f"[#003311]╠{'═' * max(0, w - 2)}╣[/#003311]")


class _ChromeBot(Static):
    """╚═══════════════════╝ bottom border."""

    DEFAULT_CSS = "_ChromeBot { height: 1; background: #000000; }"

    def on_mount(self) -> None:
        self._draw()

    def on_resize(self, event) -> None:
        self._draw()

    def _draw(self) -> None:
        w = self.size.width
        self.update(f"[#003311]╚{'═' * max(0, w - 2)}╝[/#003311]")


# ── Info panel (shown before engagement starts) ───────────────────────────────

class _InfoPanel(Static):
    """Right-side panel shown in READY state with engagement details."""

    DEFAULT_CSS = """
    _InfoPanel {
        width: 1fr;
        background: #000000;
        padding: 1 2;
        color: #00ff41;
    }
    """

    _LOGO = (
        "  [#00ff41]██╗  ██╗ ██████╗ ███╗   ██╗██████╗[/#00ff41]\n"
        "  [#00ff41]██║ ██╔╝██╔═══██╗████╗  ██║██╔══██╗[/#00ff41]\n"
        "  [#00ff41]█████╔╝ ██║   ██║██╔██╗ ██║██████╔╝[/#00ff41]\n"
        "  [#00ff41]██╔═██╗ ██║   ██║██║╚██╗██║██╔══██╗[/#00ff41]\n"
        "  [#00ff41]██║  ██╗╚██████╔╝██║ ╚████║██║  ██║[/#00ff41]\n"
        "  [#00ff41]╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝[/#00ff41]\n"
    )

    def __init__(self, info: dict[str, str], **kwargs) -> None:
        label_w = max((len(k) for k in info), default=6) + 2
        lines = ["\n", self._LOGO, "\n"]
        for label, value in info.items():
            pad = " " * (label_w - len(label))
            wrapped = _wrap(value, 60)
            lines.append(
                f"  [#007733]{label}[/#007733]{pad}[#00ff41]{wrapped[0]}[/#00ff41]\n"
            )
            for part in wrapped[1:]:
                lines.append(f"  {' ' * label_w}[#00ff41]{part}[/#00ff41]\n")
        lines += ["\n", "  Press [bold #00ff41]Enter[/bold #00ff41] to begin\n"]
        super().__init__("".join(lines), markup=True, **kwargs)


# ── Filter cycle ───────────────────────────────────────────────────────────────

_FILTER_CYCLE = [None, "recon", "osint", "web", "network_exploit", "ad", "postexploit", "system"]


# ── Main App ──────────────────────────────────────────────────────────────────

class KonrApp(App[None]):
    """
    Textual TUI for KonR.

    All chrome (borders, dividers) is rendered as explicit character strings
    inside Static widgets — zero CSS borders. This produces pixel-perfect
    ╔══╦══╗ / ╠══╩══╣ intersections at every terminal size.

    When engagement_coro is provided, READY state is shown first; the user
    presses Enter to start. When session/bus are injected without a coro
    (tests), the start gate is skipped.
    """

    TITLE = "KonR"

    CSS = """
    Screen {
        background: #000000;
    }

    #root {
        height: 1fr;
    }

    #panels-row {
        height: 1fr;
    }

    #input-row {
        height: 1;
    }

    #status-row {
        height: 1;
    }

    TaskTree {
        width: 20;
        background: #000000;
        padding: 0 1;
    }

    ActivityFeed {
        height: 1fr;
        background: #000000;
    }

    #input-bar {
        width: 1fr;
        background: #000000;
        color: #00ff41;
        border: none;
        padding: 0 1;
    }

    StatusBar {
        width: 1fr;
        height: 1;
        background: #000000;
    }
    """

    BINDINGS = [
        Binding("enter",          "start_engagement", "Start",        show=True,  priority=True),
        Binding("ctrl+backslash", "toggle_pause",     "Pause/Resume", show=True),
        Binding("ctrl+x",         "skip_task",        "Skip Task",    show=True),
        Binding("ctrl+c",         "request_quit",     "Quit",         show=True,  priority=True),
        Binding("v",              "toggle_verbose",   "Verbose",      show=False),
        Binding("f",              "cycle_filter",     "Filter",       show=False),
        Binding("tab",            "toggle_findings",  "Findings",     show=False),
    ]

    def __init__(
        self,
        session: Session,
        bus: EventBus,
        engagement_name: str = "Engagement",
        engagement_coro: Coroutine[Any, Any, Any] | None = None,
        info: dict[str, str] | None = None,
        log_file: Path | None = None,
        db=None,
    ) -> None:
        super().__init__()
        self.session             = session
        self.bus                 = bus
        self.engagement_name     = engagement_name
        self._coro               = engagement_coro
        self._info               = info or {}
        self._log_file           = log_file
        self._db                 = db
        self._approval_open      = False
        self._engagement_started = False
        self._findings_open      = False
        self._verbose            = False
        self._filter_idx         = 0

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "start_engagement":
            return not self._engagement_started and self._coro is not None
        return True

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield _ChromeTop(self.engagement_name, id="chrome-top")
            with Horizontal(id="panels-row"):
                yield _VertBar(id="lb1")
                yield TaskTree(id="task-tree")
                yield _VertBar(id="divider")
                if self._coro is not None and self._info:
                    yield _InfoPanel(self._info, id="info-panel")
                yield ActivityFeed(id="feed", max_lines=2000, log_file=self._log_file)
                yield _VertBar(id="rb1")
            yield _ChromeSep1(id="chrome-sep1")
            with Horizontal(id="input-row"):
                yield _VertBar(id="lb2")
                yield Input(
                    placeholder="> message agents, or !pin: add a permanent constraint...",
                    id="input-bar",
                )
                yield _VertBar(id="rb2")
            yield _ChromeSep2(id="chrome-sep2")
            with Horizontal(id="status-row"):
                yield _VertBar(id="lb3")
                yield StatusBar()
                yield _VertBar(id="rb3")
            yield _ChromeBot(id="chrome-bot")

    # ── Startup ───────────────────────────────────────────────────────────────

    def on_unmount(self) -> None:
        if not self._engagement_started and self._coro is not None:
            self._coro.close()  # suppress "never awaited" warning when app exits before engagement starts

    def on_mount(self) -> None:
        self._subscribe_bus()
        asyncio.get_event_loop().create_task(self.bus.run())
        if self._coro is not None and self._info:
            # READY state: hide feed; input stays visible but unfocused
            try:
                self.query_one("#feed").display = False
            except Exception:
                pass
        else:
            self._activate_running_layout()
            if self._coro is not None:
                self.run_worker(self._coro, exclusive=True, thread=False)

    def _activate_running_layout(self) -> None:
        try:
            self.query_one("#info-panel").display = False
        except Exception:
            pass
        self.query_one("#feed").display = True
        self.query_one("#input-bar", Input).focus()

    def _subscribe_bus(self) -> None:
        sub = self.bus.subscribe
        sub(EventType.TOOL_CALLED,     self._on_tool_called)
        sub(EventType.TOOL_RESULT,     self._on_tool_result)
        sub(EventType.AGENT_STARTED,   self._on_agent_started)
        sub(EventType.AGENT_FINISHED,  self._on_agent_finished)
        sub(EventType.AGENT_ERROR,     self._on_agent_error)
        sub(EventType.AGENT_STUCK,     self._on_agent_stuck)
        sub(EventType.AGENT_THINKING,  self._on_agent_thinking)
        sub(EventType.PHASE_STARTED,   self._on_phase_started)
        sub(EventType.PHASE_FINISHED,  self._on_phase_finished)
        sub(EventType.HOST_FOUND,      self._on_finding)
        sub(EventType.SERVICE_FOUND,   self._on_finding)
        sub(EventType.VULN_FOUND,      self._on_finding)
        sub(EventType.CRED_FOUND,      self._on_finding)
        sub(EventType.FLAG_FOUND,      self._on_flag_found)
        sub(EventType.APPROVAL_NEEDED, self._on_approval_needed)
        sub(EventType.COST_UPDATE,     self._on_cost_update)
        sub(EventType.ENGAGEMENT_DONE, self._on_engagement_done)
        sub(EventType.SESSION_STOPPED, self._on_session_stopped)
        sub(EventType.USER_INPUT,      self._on_user_input)

    # ── EventBus handlers ─────────────────────────────────────────────────────

    def _on_agent_thinking(self, event: Event) -> None:
        if not self._verbose:
            return
        text       = event.data.get("text", "")
        first_line = text.splitlines()[0][:140] if text else ""
        if first_line:
            self.post_message(_ActivityLine(event.agent or "?", first_line, "thinking"))

    def _on_tool_called(self, event: Event) -> None:
        tool = event.data.get("tool", "")
        inp  = event.data.get("input", {})
        self.post_message(_ActivityLine(event.agent or "?", _format_tool_call(tool, inp), "output"))

    def _on_tool_result(self, event: Event) -> None:
        result = event.data.get("output", event.data.get("result", ""))
        if not result:
            return
        lines = result.splitlines()
        # Strip the [exit N] metadata prefix — not display content and breaks Rich markup
        if lines and lines[0].startswith("[exit "):
            lines = lines[1:]
        if self._verbose:
            display = "\n".join(lines[:20])
        else:
            display = lines[0][:120] if lines else ""
        if display and display.strip():
            self.post_message(_ActivityLine(event.agent or "?", display, "output"))

    def _on_agent_started(self, event: Event) -> None:
        self.post_message(_AgentStarted(event.agent or "?"))
        self.post_message(_ActivityLine(
            event.agent or "?", f"started — {event.data.get('task', '')}", "system"))

    def _on_agent_finished(self, event: Event) -> None:
        self.post_message(_AgentFinished(event.agent or "?"))
        summary = event.data.get("summary", "")
        if summary:
            self.post_message(_ActivityLine(
                event.agent or "?", f"done — {summary[:120]}", "system"))

    def _on_agent_error(self, event: Event) -> None:
        self.post_message(_AgentError(event.agent or "?"))
        self.post_message(_ActivityLine(
            event.agent or "?", f"error: {event.data.get('reason', '')}", "error"))

    def _on_agent_stuck(self, event: Event) -> None:
        self.post_message(_ActivityLine(
            event.agent or "?", f"STUCK: {event.data.get('reason', '')}", "error"))

    def _on_phase_started(self, event: Event) -> None:
        self.post_message(_PhaseStarted(event.data.get("phase", 0)))

    def _on_phase_finished(self, event: Event) -> None:
        self.post_message(_PhaseFinished(int(event.data.get("phase", 0))))

    def _on_finding(self, event: Event) -> None:
        kind   = event.type.value.split(".")[-1]
        detail = _summarise_finding(kind, event.data)
        self.post_message(_ActivityLine(event.agent or "system", detail, "finding"))

    def _on_flag_found(self, event: Event) -> None:
        flag = event.data.get("value", event.data.get("flag", ""))
        agent = event.agent or "system"
        self.post_message(_ActivityLine(agent, f"FLAG: {flag}", "flag"))

    def _on_approval_needed(self, event: Event) -> None:
        self.post_message(_ApprovalNeeded(event))

    def _on_cost_update(self, event: Event) -> None:
        self.post_message(_CostUpdated(
            total_usd=float(event.data.get("total_usd", 0.0)),
            agent_costs=event.data.get("agent_costs", {}),
        ))

    def _on_engagement_done(self, event: Event) -> None:
        self.post_message(_ActivityLine("system", "Engagement complete.", "system"))

    def _on_session_stopped(self, event: Event) -> None:
        self.query_one(StatusBar).set_status("STOPPING")
        self.post_message(_ActivityLine("system", "Stopping...", "system"))

    def _on_user_input(self, event: Event) -> None:
        text   = event.data.get("text", "")
        pinned = event.data.get("pinned", False)
        etype  = "system" if pinned else "user"
        self.post_message(_ActivityLine("you", text, etype))

    # ── Textual message handlers ──────────────────────────────────────────────

    def on__activity_line(self, msg: _ActivityLine) -> None:
        self.query_one("#feed", ActivityFeed).add_line(msg.agent, msg.content, msg.entry_type)

    def on__phase_started(self, msg: _PhaseStarted) -> None:
        num = _phase_num(msg.phase) if isinstance(msg.phase, str) else int(msg.phase)
        if num > 0:  # skip the "start" pseudo-phase emitted by session.start()
            self.query_one("#task-tree", TaskTree).set_phase_active(msg.phase)
            self.query_one("#feed", ActivityFeed).add_separator(f"Phase {num}")
        sb = self.query_one(StatusBar)
        sb.mark_started()
        sb.set_status("RUNNING")

    def on__phase_finished(self, msg: _PhaseFinished) -> None:
        self.query_one("#task-tree", TaskTree).set_phase_done(msg.phase)

    def on__agent_started(self, msg: _AgentStarted) -> None:
        self.query_one("#task-tree", TaskTree).set_task_active(msg.agent)

    def on__agent_finished(self, msg: _AgentFinished) -> None:
        self.query_one("#task-tree", TaskTree).set_task_done(msg.agent)

    def on__agent_error(self, msg: _AgentError) -> None:
        self.query_one("#task-tree", TaskTree).set_task_error(msg.agent)

    def on__cost_updated(self, msg: _CostUpdated) -> None:
        sb = self.query_one(StatusBar)
        sb.set_cost(msg.total_usd, msg.agent_costs)

    def on__approval_needed(self, msg: _ApprovalNeeded) -> None:
        if not self._approval_open:
            self._approval_open = True
            self.push_screen(ApprovalPanel(msg.event, self.bus),
                             callback=self._on_approval_dismissed)

    def _on_approval_dismissed(self, decision: str) -> None:
        self._approval_open = False

    # ── Input bar ─────────────────────────────────────────────────────────────

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.clear()
        if text:
            await self.session.send_user_message(text)

    # ── Key actions ───────────────────────────────────────────────────────────

    async def action_start_engagement(self) -> None:
        if self._engagement_started or self._coro is None:
            return
        self._engagement_started = True
        self._activate_running_layout()
        self.run_worker(self._coro, exclusive=True, thread=False)

    async def action_toggle_pause(self) -> None:
        self.query_one(StatusBar).flash_hint("^\\")
        if self.session.state == SessionState.PAUSED:
            await self.session.resume()
            self.query_one(StatusBar).set_status("RUNNING")
            self.query_one("#feed", ActivityFeed).add_line("system", "Resumed.", "system")
        elif self.session.state == SessionState.RUNNING:
            await self.session.pause()
            self.query_one(StatusBar).set_status("PAUSED")
            self.query_one("#feed", ActivityFeed).add_line(
                "system", "Paused — Ctrl+P to resume.", "system")

    async def action_skip_task(self) -> None:
        self.query_one(StatusBar).flash_hint("^X")
        if self.session.state == SessionState.RUNNING:
            self.session.request_skip()
            self.query_one("#feed", ActivityFeed).add_line(
                "system", "Skip requested — current task will stop after this iteration.", "system")

    def action_toggle_verbose(self) -> None:
        self.query_one(StatusBar).flash_hint("v")
        self._verbose = not self._verbose
        self.query_one("#feed", ActivityFeed).set_verbose(self._verbose)
        label = "ON" if self._verbose else "OFF"
        self.query_one("#feed", ActivityFeed).add_line(
            "system", f"Verbose output {label}.", "system")

    def action_cycle_filter(self) -> None:
        self.query_one(StatusBar).flash_hint("f")
        self._filter_idx = (self._filter_idx + 1) % len(_FILTER_CYCLE)
        agent = _FILTER_CYCLE[self._filter_idx]
        self.query_one("#feed", ActivityFeed).set_filter(agent)
        self.query_one(StatusBar).set_filter(agent)

    def action_toggle_findings(self) -> None:
        if self._findings_open:
            return
        self._findings_open = True
        db = self._db or _get_db()
        self.push_screen(
            FindingsPanel(db, self.session.engagement_id),
            callback=lambda _: setattr(self, "_findings_open", False),
        )

    async def action_request_quit(self) -> None:
        self.query_one(StatusBar).flash_hint("^C")
        if self.session.state in (SessionState.RUNNING, SessionState.PAUSED):
            await self.session.stop()
        self.exit()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_db():
    from konr.core import config
    from konr.storage.db import FindingsDB
    return FindingsDB(config.WORK_DIR / "findings.db")


def _format_tool_call(tool: str, inp: dict) -> str:
    if tool == "execute_command":
        return f"$ {inp.get('command', '')}"
    if tool == "store_finding":
        ftype = inp.get("type", "?")
        data  = inp.get("data", {})
        label = data.get("ip", data.get("title", str(data)[:60]))
        return f"[store:{ftype}] {label}"
    if tool == "request_approval":
        return f"[approval] {inp.get('command', '')}"
    if tool == "task_complete":
        return f"[complete] {inp.get('summary', '')[:100]}"
    if tool == "read_file":
        return f"[read] {inp.get('path', '')}"
    if tool == "write_file":
        return f"[write] {inp.get('path', '')}"
    if tool == "search_memory":
        return f"[memory] {inp.get('query', '')}"
    return f"[{tool}]"


def _wrap(text: str, width: int) -> list[str]:
    """Split text into lines of at most `width` chars, breaking on spaces."""
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def _summarise_finding(kind: str, data: dict) -> str:
    if kind == "host":
        return f"Host: {data.get('ip', '?')} ({data.get('os', 'unknown OS')})"
    if kind == "service":
        ip   = data.get('ip', '?')
        port = data.get('port', '?')
        svc  = data.get('service_name', '')
        return f"Service: {ip}:{port} {svc}"
    if kind == "vuln":
        sev = data.get("severity", "?").upper()
        return f"Vuln [{sev}]: {data.get('title', '?')}"
    if kind == "cred":
        user = data.get("username", "?")
        location = data.get("ip") or data.get("domain") or data.get("access_level") or "unknown"
        return f"Cred: {user} @ {location}"
    return str(data)
