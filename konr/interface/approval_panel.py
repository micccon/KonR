"""ApprovalPanel — modal screen for approval gate requests."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Label, Static

from konr.core.events import Event, EventBus, EventType

RISK_COLORS = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "yellow",
    "low":      "green",
}


class ApprovalPanel(ModalScreen[str]):
    """
    Modal overlay shown when an agent calls request_approval.

    Publishes APPROVAL_DECIDED to the EventBus when the user responds.
    Returns the decision string to dismiss the screen.
    """

    BINDINGS = [
        Binding("y", "approve",  "Approve",          show=True),
        Binding("n", "skip",     "Skip",              show=True),
        Binding("s", "stop_eng", "Stop engagement",   show=True),
    ]

    DEFAULT_CSS = """
    ApprovalPanel {
        align: center middle;
    }

    #approval-box {
        width: 72;
        height: auto;
        border: double $warning;
        background: $surface-darken-1;
        padding: 1 2;
    }

    #approval-title {
        text-align: center;
        color: $warning;
        text-style: bold;
        margin-bottom: 1;
    }

    #approval-command {
        background: $surface-darken-2;
        padding: 0 1;
        margin: 1 0;
        color: $text;
    }

    .risk-critical { color: red; text-style: bold; }
    .risk-high     { color: yellow; text-style: bold; }
    .risk-medium   { color: yellow; }
    .risk-low      { color: green; }

    #approval-hint {
        margin-top: 1;
        text-align: center;
        color: $text-muted;
    }
    """

    def __init__(self, event: Event, bus: EventBus) -> None:
        super().__init__()
        self._event = event
        self._bus   = bus

    def compose(self) -> ComposeResult:
        data       = self._event.data
        agent      = self._event.agent or "?"
        command    = data.get("command", "")
        reason     = data.get("reason", "")
        risk_level = data.get("risk_level", "medium")
        risk_color = RISK_COLORS.get(risk_level, "yellow")

        with Static(id="approval-box"):
            yield Label("⚠  APPROVAL REQUIRED", id="approval-title")
            yield Label(f"Agent:   [bold]{agent}[/bold]")
            yield Label(
                f"Risk:    [{risk_color}]{risk_level.upper()}[/{risk_color}]"
            )
            yield Label("Command:", markup=False)
            yield Label(f"  {command}", id="approval-command", markup=False)
            yield Label(f"Reason:  {reason}", markup=False)
            yield Label(
                "\n[y] Approve   [n] Skip   [s] Stop engagement",
                id="approval-hint",
            )

    def _respond(self, decision: str, modified_command: str | None = None) -> None:
        self._bus.publish_sync(
            EventBus.make(
                EventType.APPROVAL_DECIDED,
                decision=decision,
                modified_command=modified_command,
            )
        )
        self.dismiss(decision)

    def action_approve(self) -> None:
        self._respond("approved")

    def action_skip(self) -> None:
        self._respond("skipped")

    def action_stop_eng(self) -> None:
        self._respond("stopped")
