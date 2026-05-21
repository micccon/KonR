"""TaskTree — left panel showing phase/agent hierarchy with status icons."""
from __future__ import annotations

import re

from textual.widget import Widget
from textual.widgets import Static

_INSTANCE_SUFFIX = re.compile(r'_\d+$')

PHASE_LABELS: dict[int, str] = {
    1: "Recon & OSINT",
    2: "Exploitation",
    3: "Post-Exploit",
}

AGENT_DISPLAY_NAMES: dict[str, str] = {
    "network_exploit": "network",
}

ICONS = {
    "waiting": "○",
    "active":  "⟳",
    "done":    "✓",
    "error":   "✗",
    "paused":  "⏸",
}


class TaskTree(Widget):
    """Left panel: phase and agent status hierarchy."""

    DEFAULT_CSS = """
    TaskTree {
        background: #000000;
        padding: 1 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # phase_num → {"status": str, "agents": {name: status}}
        self._phases: dict[int, dict] = {}
        self._agent_counts: dict[str, int] = {}
        # specialist_name → summarizer status ("active" | "done" | "error")
        self._summarizers: dict[str, str] = {}
        # specialist_name → verifier status ("active" | "done" | "error")
        self._verifiers: dict[str, str] = {}

    def compose(self):
        yield Static("", id="tree-content", markup=True)

    def _render_tree(self) -> str:
        if not self._phases:
            return "[#003311]Waiting for plan...[/#003311]"

        lines: list[str] = []
        for phase_num in sorted(self._phases):
            info   = self._phases[phase_num]
            status = info["status"]
            label  = PHASE_LABELS.get(phase_num, f"Phase {phase_num}")
            icon   = ICONS.get(status, "○")

            if status == "active":
                lines.append(f"[bold #00ff41]{icon} {label}[/bold #00ff41]")
            elif status == "done":
                lines.append(f"[#007722]{icon} {label}[/#007722]")
            elif status == "error":
                lines.append(f"[#ff3333]{icon} {label}[/#ff3333]")
            else:
                lines.append(f"[#003311]{icon} {label}[/#003311]")

            for agent_name, agent_status in info.get("agents", {}).items():
                a_icon = ICONS.get(agent_status, "○")
                display = _resolve_display_name(agent_name)
                if len(display) > 13:
                    display = display[:12] + "…"
                if agent_status == "active":
                    lines.append(f"  [#00ff41]├ {a_icon} {display}[/#00ff41]")
                elif agent_status == "done":
                    lines.append(f"  [#007722]├ {a_icon} {display}[/#007722]")
                elif agent_status == "error":
                    lines.append(f"  [#ff3333]├ {a_icon} {display}[/#ff3333]")
                else:
                    lines.append(f"  [#003311]├ {a_icon} {display}[/#003311]")

                s_status = self._summarizers.get(agent_name)
                v_status = self._verifiers.get(agent_name)
                if s_status:
                    s_icon = ICONS.get(s_status, "○")
                    connector = "├" if v_status else "└"
                    if s_status == "active":
                        lines.append(f"  [#ff69b4]│  {connector} {s_icon} summarizer[/#ff69b4]")
                    elif s_status == "done":
                        lines.append(f"  [#99334d]│  {connector} {s_icon} summarizer[/#99334d]")
                    else:
                        lines.append(f"  [#ff3333]│  {connector} {s_icon} summarizer[/#ff3333]")
                if v_status:
                    v_icon = ICONS.get(v_status, "○")
                    if v_status == "active":
                        lines.append(f"  [#00ff41]│  └ {v_icon} verifier[/#00ff41]")
                    elif v_status == "done":
                        lines.append(f"  [#007722]│  └ {v_icon} verifier[/#007722]")
                    else:
                        lines.append(f"  [#ff3333]│  └ {v_icon} verifier[/#ff3333]")

        return "\n".join(lines)

    def _refresh_content(self) -> None:
        try:
            self.query_one("#tree-content", Static).update(self._render_tree())
        except Exception:
            pass

    def set_phase_active(self, phase: str | int) -> None:
        """Called when a phase starts. phase may be int or 'phase_1' string."""
        num = _phase_num(phase)
        if num not in self._phases:
            self._phases[num] = {"status": "waiting", "agents": {}}
        self._phases[num]["status"] = "active"
        self._refresh_content()

    def set_phase_done(self, phase: str | int) -> None:
        num = _phase_num(phase)
        if num in self._phases:
            self._phases[num]["status"] = "done"
        self._refresh_content()

    def set_task_active(self, agent: str) -> None:
        """Mark an agent as running within its current phase."""
        phase_num = _find_agent_phase(self._phases, agent)
        if phase_num is None:
            # Put it in the first active phase or create phase 1
            phase_num = _active_phase(self._phases) or 1
            if phase_num not in self._phases:
                self._phases[phase_num] = {"status": "active", "agents": {}}
        self._agent_counts[agent] = self._agent_counts.get(agent, 0) + 1
        self._phases[phase_num]["agents"][agent] = "active"
        self._refresh_content()

    def _set_task_status(self, agent: str, status: str) -> None:
        count = max(0, self._agent_counts.get(agent, 1) - 1)
        if count == 0:
            self._agent_counts.pop(agent, None)
            for info in self._phases.values():
                if agent in info.get("agents", {}):
                    info["agents"][agent] = status
                    break
        else:
            self._agent_counts[agent] = count
        self._refresh_content()

    def set_task_done(self, agent: str) -> None:
        self._set_task_status(agent, "done")

    def set_task_error(self, agent: str) -> None:
        self._set_task_status(agent, "error")

    def set_summarizer_active(self, specialist: str) -> None:
        self._summarizers[specialist] = "active"
        self._refresh_content()

    def set_summarizer_done(self, specialist: str) -> None:
        self._summarizers[specialist] = "done"
        self._refresh_content()

    def set_summarizer_error(self, specialist: str) -> None:
        self._summarizers[specialist] = "error"
        self._refresh_content()

    def set_verifier_active(self, specialist: str) -> None:
        self._verifiers[specialist] = "active"
        self._refresh_content()

    def set_verifier_done(self, specialist: str) -> None:
        self._verifiers[specialist] = "done"
        self._refresh_content()

    def set_verifier_error(self, specialist: str) -> None:
        self._verifiers[specialist] = "error"
        self._refresh_content()


def _resolve_display_name(agent_name: str) -> str:
    """Resolve display name, handling _N suffixes for parallel instances."""
    if agent_name in AGENT_DISPLAY_NAMES:
        return AGENT_DISPLAY_NAMES[agent_name]
    base = _INSTANCE_SUFFIX.sub('', agent_name)
    if base in AGENT_DISPLAY_NAMES:
        return AGENT_DISPLAY_NAMES[base] + agent_name[len(base):]
    return agent_name


def _phase_num(phase: str | int) -> int:
    if isinstance(phase, int):
        return phase
    # "phase_1" → 1
    try:
        return int(str(phase).split("_")[-1])
    except (ValueError, IndexError):
        return 0


def _find_agent_phase(phases: dict, agent: str) -> int | None:
    for num, info in phases.items():
        if agent in info.get("agents", {}):
            return num
    return None


def _active_phase(phases: dict) -> int | None:
    for num, info in phases.items():
        if info.get("status") == "active":
            return num
    return None
