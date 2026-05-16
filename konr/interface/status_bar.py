"""StatusBar — bottom bar showing elapsed time, cost, and status."""
from __future__ import annotations

from datetime import UTC, datetime

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Label


class StatusBar(Widget):
    """Bottom bar: pipe-separated status | time | cost | key hints."""

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        background: #000000;
        layout: horizontal;
        padding: 0 1;
    }

    StatusBar Label { height: 1; }

    #status-left  { width: 1fr; color: #00ff41; }
    #status-right { color: #003311; }
    """

    status:    reactive[str]   = reactive("READY")
    cost:      reactive[float] = reactive(0.0)
    _start_at:   datetime | None = None
    _filter:     str | None      = None
    _agent_costs: dict[str, float]
    _flash_key:  str | None      = None

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._agent_costs = {}

    def compose(self) -> ComposeResult:
        yield Label("", id="status-left",  markup=True)
        yield Label("", id="status-right", markup=True)

    def set_status(self, status: str) -> None:
        self.status = status
        self._update_left()

    def set_cost(self, total_usd: float, agent_costs: dict[str, float] | None = None) -> None:
        self.cost = total_usd
        if agent_costs is not None:
            self._agent_costs = agent_costs
        self._update_left()

    def mark_started(self) -> None:
        self._start_at = datetime.now(UTC)

    def _tick(self) -> None:
        self._update_left()

    def _elapsed(self) -> str:
        if self._start_at is None:
            return "--:--:--"
        delta = datetime.now(UTC) - self._start_at
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _status_color(self) -> str:
        return {
            "RUNNING":  "#00ff41",
            "PAUSED":   "#ffff00",
            "STOPPING": "#ff8800",
            "DONE":     "#007722",
            "ERROR":    "#ff3333",
        }.get(self.status, "#00ff41")

    def set_filter(self, agent: str | None) -> None:
        self._filter = agent
        self._update_left()
        self._update_right()

    _PIPE = " [#003311]|[/#003311] "

    def _update_left(self) -> None:
        color  = self._status_color()
        # Show per-agent cost when a filter is active, otherwise total
        if self._filter:
            cost_val = self._agent_costs.get(self._filter, 0.0)
            cost_str = f"[#00ff41]${cost_val:.4f} ({self._filter})[/#00ff41]"
        else:
            cost_str = f"[#00ff41]${self.cost:.4f}[/#00ff41]"
        parts  = [
            f"[{color}]{self.status}[/{color}]",
            f"[#003311]{self._elapsed()}[/#003311]",
            cost_str,
        ]
        if self._filter:
            parts.append(f"[#00ff41]F:{self._filter}[/#00ff41]")
        self.query_one("#status-left", Label).update(self._PIPE.join(parts))

    _HINTS: list[tuple[str, str]] = [
        ("^\\", "pause"),
        ("^X",  "skip"),
        ("v",   "verbose"),
        ("f",   "filter"),
        ("^C",  "quit"),
    ]

    def flash_hint(self, key: str) -> None:
        self._flash_key = key
        self._update_right()
        self.set_timer(0.2, self._clear_flash)

    def _clear_flash(self) -> None:
        self._flash_key = None
        self._update_right()

    def _update_right(self) -> None:
        p = " [#003311]|[/#003311] "
        parts = []
        for key, label in self._HINTS:
            color = "#00ff41" if key == self._flash_key else "#003311"
            parts.append(f"[{color}]{key} {label}[/{color}]")
        self.query_one("#status-right", Label).update(p.join(parts))

    def on_mount(self) -> None:
        self.set_interval(1.0, self._tick)
        self._update_left()
        self._update_right()
