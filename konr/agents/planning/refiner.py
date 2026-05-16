"""Refiner — single LLM call to adapt the remaining task list after each phase."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from konr.agents.llm_agent import SingleCallLLMAgent
from konr.agents.planning.generator import _PHASE_MAP, VALID_TYPES, Task, TaskPlan, _extract_json
from konr.core import config
from konr.storage.db import FindingsDB

if TYPE_CHECKING:
    from konr.agents.orchestrator import TaskOutcome

_SYSTEM_PROMPT = """You are a penetration test task refiner. Given completed phase results \
and remaining planned tasks, return an updated task list.

You may:
- Add new tasks based on findings (e.g. a new service was discovered)
- Remove tasks that findings make irrelevant (e.g. no web server found, drop web tasks)
- Reorder tasks by adjusting priority

Preserve task IDs where possible. Only make changes that findings justify.
If the current task list is already appropriate, return it unchanged.

Output ONLY valid JSON, no prose:
{"tasks": [{"id": "...", "type": "...", "description": "...", "target": "...", \
"depends_on": [], "priority": 1}]}"""


class Refiner(SingleCallLLMAgent):
    """Single-call LLM task refiner. Not a BaseAgent — no tool loop."""

    def __init__(self, db: FindingsDB) -> None:
        super().__init__(model=config.HAIKU_MODEL, system_prompt=_SYSTEM_PROMPT)
        self._db = db

    async def adapt(
        self,
        plan: TaskPlan,
        phase_outcomes: list[TaskOutcome],
        remaining: list[Task],
    ) -> list[Task]:
        """Return an updated task list adjusted to phase findings. Falls back to the original list on parse failure."""
        if not remaining:
            return remaining

        findings_summary = _get_findings_summary(self._db, plan.engagement_id)
        user_message = _build_user_message(phase_outcomes, remaining, findings_summary)

        raw_json = await self._call(user_message)

        try:
            updated = _parse_tasks(raw_json)
        except (ValueError, KeyError):
            return remaining
        return updated or remaining


def _get_findings_summary(db: FindingsDB, engagement_id: int) -> str:
    """Produce a short text summary of current hosts and vulns for the refiner prompt."""
    try:
        hosts = db.get_hosts(engagement_id)
        vulns = db.get_vulnerabilities(engagement_id)

        parts = []
        if hosts:
            host_list = ", ".join(
                f"{h['ip']}({h.get('hostname') or '?'})" for h in hosts[:10]
            )
            parts.append(f"Hosts: {host_list}")
        if vulns:
            vuln_list = ", ".join(
                f"{v['title']}[{v['severity']}]" for v in vulns[:10]
            )
            parts.append(f"Vulnerabilities: {vuln_list}")
        return "; ".join(parts) if parts else "No findings yet."
    except Exception:
        return "Findings unavailable."


def _build_user_message(
    phase_outcomes: list[TaskOutcome],
    remaining: list[Task],
    findings_summary: str,
) -> str:
    """Build the refiner prompt with completed outcomes, current findings, and the task list to adapt."""
    completed_section = json.dumps(
        [
            {
                "task_id": o.task.id,
                "type": o.task.type,
                "description": o.task.description,
                "target": o.task.target,
                "status": o.status,
                "summary": o.agent_result.summary[:300] if o.agent_result.summary else "",
                "findings_count": o.agent_result.findings_count,
            }
            for o in phase_outcomes
        ],
        indent=2,
    )
    remaining_section = json.dumps(
        [
            {
                "id": t.id,
                "type": t.type,
                "description": t.description,
                "target": t.target,
                "depends_on": t.depends_on,
                "priority": t.priority,
            }
            for t in remaining
        ],
        indent=2,
    )
    return (
        f"Completed phase results:\n{completed_section}\n\n"
        f"Findings so far: {findings_summary}\n\n"
        f"Remaining tasks:\n{remaining_section}\n\n"
        "Return the updated task list."
    )


def _parse_tasks(raw: str) -> list[Task]:
    """Parse LLM JSON output into Task objects. Does not enforce a recon guarantee — that's Generator's job."""
    data = _extract_json(raw)
    raw_tasks: list[dict] = data.get("tasks", [])
    tasks: list[Task] = []
    for t in raw_tasks:
        task_type = str(t.get("type", "")).strip().lower()
        if task_type not in VALID_TYPES:
            continue
        tasks.append(Task(
            id=str(t.get("id", f"{task_type}_{len(tasks)}")).strip(),
            type=task_type,
            description=str(t.get("description", "")).strip(),
            target=str(t.get("target", "all")).strip(),
            depends_on=list(t.get("depends_on", [])),
            priority=max(1, min(10, int(t.get("priority", 5)))),
            phase=_PHASE_MAP[task_type],
        ))
    return tasks
