"""ActivityFeed — scrolling log of agent actions and findings."""
from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from pathlib import Path

from rich.markup import escape
from textual.widgets import RichLog

_STRIP_MARKUP = re.compile(r"\[/?[^\[\]]*\]")
_INSTANCE_SUFFIX = re.compile(r'_\d+$')

_ENTRY_STYLE: dict[str, tuple[str, str]] = {
    "thinking": ("italic", "> "),
    "flag":     ("bold",   "★ "),
    "error":    ("bold",   ""),
    "user":     ("bold",   "> "),
}


def _agent_base_name(agent: str) -> str:
    """Strip _1/_2 instance suffix and verifier specialist suffix for color lookup."""
    name = _INSTANCE_SUFFIX.sub('', agent)
    if name.startswith("verifier_"):
        return "verifier"
    return name

AGENT_COLORS: dict[str, str] = {
    "recon":           "#00ff41",
    "osint":           "#00ffcc",
    "web":             "#ffff00",
    "network_exploit": "#ff9900",
    "ad":              "#aaaaaa",
    "postexploit":     "#ff3300",
    "coder":           "#00aaff",
    "summarizer":      "#ff69b4",
    "verifier":        "#cc44ff",
    "orchestrator":    "#ff00ff",
    "you":             "#ffffff",
    "system":          "#004422",
}

ENTRY_COLORS: dict[str, str] = {
    "output":   "#00ff41",
    "thinking": "#005522",
    "system":   "#007733",
    "user":     "#ffffff",
    "finding":  "#00ffcc",
    "flag":     "#ffff00",
    "error":    "#ff3333",
}


class ActivityFeed(RichLog):
    """Right panel: scrolling stream of agent actions and findings."""

    DEFAULT_CSS = """
    ActivityFeed {
        background: #000000;
        color: #00ff41;
        padding: 0 1;
        scrollbar-color: #003311;
        scrollbar-background: #000000;
    }
    """

    def __init__(self, *, log_file: Path | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._log_file  = log_file
        self._log_fh    = None
        self._verbose   = False
        self._filter: str | None = None
        self._last_write_time: float = 0.0
        self._idle_active = True
        # (agent, content, entry_type) — kept for filter re-renders
        self._all_lines: list[tuple[str, str, str]] = []

    def on_mount(self) -> None:
        self.wrap      = True
        self.highlight = False
        self.markup    = True
        self._last_write_time = time.monotonic()
        self.set_interval(15, self._check_idle)
        if self._log_file:
            try:
                self._log_file.parent.mkdir(parents=True, exist_ok=True)
                self._log_fh = open(self._log_file, "a", encoding="utf-8")  # noqa: SIM115
            except OSError:
                pass

    def on_unmount(self) -> None:
        if self._log_fh:
            self._log_fh.close()

    # ── Public API ────────────────────────────────────────────────────────

    def stop_idle_check(self) -> None:
        """Call when engagement finishes so idle heartbeat stops."""
        self._idle_active = False

    def set_paused(self, paused: bool) -> None:
        """Suppress idle heartbeat while session is paused."""
        self._idle_active = not paused

    def _check_idle(self) -> None:
        if self._idle_active and self._all_lines and time.monotonic() - self._last_write_time >= 15:
            self.add_line("system", "Still working...", "system")

    def add_line(self, agent: str, content: str, entry_type: str = "output") -> None:
        self._last_write_time = time.monotonic()
        self._all_lines.append((agent, content, entry_type))
        if self._filter is None or agent == self._filter:
            self._write_line(agent, content, entry_type)
        if self._log_fh:
            ts = datetime.now(UTC).strftime("%H:%M:%S")
            plain = _STRIP_MARKUP.sub("", content)
            self._log_fh.write(f"{ts}  [{agent}]  {plain}\n")
            self._log_fh.flush()

    def add_separator(self, label: str = "") -> None:
        bar = "─" * 28
        self.write(f"[#003311]{bar}  {label}  {bar}[/#003311]")
        self.scroll_end(animate=False)

    def set_verbose(self, verbose: bool) -> None:
        self._verbose = verbose

    def set_filter(self, agent: str | None) -> None:
        self._filter = agent
        self.clear()
        for ag, content, entry_type in self._all_lines:
            if agent is None or ag == agent:
                self._write_line(ag, content, entry_type)
        self.scroll_end(animate=False)

    # ── Internal ──────────────────────────────────────────────────────────

    def _write_line(self, agent: str, content: str, entry_type: str) -> None:
        ts     = datetime.now(UTC).strftime("%H:%M:%S")
        acolor = AGENT_COLORS.get(_agent_base_name(agent), "#00ff41")
        ecolor = ENTRY_COLORS.get(entry_type, "#00ff41")

        ts_tag    = f"[#003311]{ts}[/#003311]"
        agent_tag = f"[bold {acolor}]{escape(f'[{agent}]')}[/bold {acolor}]"

        style, pfx = _ENTRY_STYLE.get(entry_type, ("", ""))
        safe = escape(content)
        if style:
            content_tag = f"[{style} {ecolor}]{pfx}{safe}[/{style} {ecolor}]"
        else:
            content_tag = f"[{ecolor}]{safe}[/{ecolor}]"

        self.write(f"{ts_tag}  {agent_tag}  {content_tag}")
        self.scroll_end(animate=False)
