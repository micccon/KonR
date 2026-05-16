"""Task plan generator — single LLM call, no tool loop."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from konr.agents.llm_agent import SingleCallLLMAgent
from konr.core import config

# ── Data model ────────────────────────────────────────────────────────────────

VALID_TYPES = frozenset(["osint", "recon", "web", "network_exploit", "ad", "postexploit"])

_PHASE_MAP: dict[str, int] = {
    "osint": 1,
    "recon": 1,
    "web": 2,
    "network_exploit": 2,
    "ad": 3,
    "postexploit": 3,
}


@dataclass
class Task:
    id: str
    type: str
    description: str
    target: str
    depends_on: list[str] = field(default_factory=list)
    priority: int = 5
    phase: int = 1


@dataclass
class TaskPlan:
    tasks: list[Task]
    engagement_id: int
    mode: str

    def by_phase(self) -> dict[int, list[Task]]:
        """Group tasks by phase number, preserving task order within each phase."""
        phases: dict[int, list[Task]] = {}
        for task in self.tasks:
            phases.setdefault(task.phase, []).append(task)
        return phases


# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a penetration testing task planner. Given an engagement description, \
produce a structured JSON task plan.

## Task types and their phases
- Phase 1 (parallel, free): osint, recon
- Phase 2 (parallel, gated): web, network_exploit
- Phase 3 (sequential, gated): ad, postexploit

## Output format — respond with ONLY valid JSON, no prose:
{
  "tasks": [
    {
      "id": "unique_snake_case_id",
      "type": "osint|recon|web|network_exploit|ad|postexploit",
      "description": "Concise description of what to do",
      "target": "specific target (IP, CIDR, domain, or 'all')",
      "depends_on": [],
      "priority": 1
    }
  ]
}

## Rules
- Always include at least one recon task
- depends_on must reference valid ids within the plan
- priority: 1=highest, 10=lowest
- Do not include phase — it is derived from type
- CTF mode: be aggressive, include network_exploit and postexploit
- Pentest mode: be thorough, cover osint + recon before exploitation
- Only generate tasks relevant to the stated target and objectives
- Effort distribution per agent: ~10% setup/recon reading, ~30% broad probing,
  ~30% evaluating results and selecting the most promising path, ~30% exploitation"""


# ── Generator ─────────────────────────────────────────────────────────────────

class Generator(SingleCallLLMAgent):
    """Single-call LLM task planner. Not a BaseAgent — no tool loop."""

    def __init__(self) -> None:
        super().__init__(model=config.SONNET_MODEL, system_prompt=_SYSTEM_PROMPT)

    async def generate(
        self,
        engagement_id: int,
        target_scope: str,
        mode: str,
        client_name: str = "",
        objectives: str = "",
    ) -> TaskPlan:
        """Return a TaskPlan — from a playbook if one matches, otherwise from the LLM."""
        from konr.agents.planning.playbooks import apply_target, select_playbook
        playbook = select_playbook(mode, target_scope)
        if playbook is not None:
            return apply_target(playbook, engagement_id, target_scope, mode)

        user_message = _build_user_message(target_scope, mode, client_name, objectives)
        raw_json = await self._call(user_message, max_tokens=4096)
        tasks = _parse_and_validate(raw_json, engagement_id)
        return TaskPlan(tasks=tasks, engagement_id=engagement_id, mode=mode)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_user_message(
    target_scope: str, mode: str, client_name: str, objectives: str
) -> str:
    """Assemble the LLM user message for plan generation."""
    task_cap = (
        "Generate at most 8 tasks total" if mode == "ctf"
        else "Generate at most 12 tasks total"
    )
    parts = [
        f"Mode: {mode}",
        f"Target scope: {target_scope}",
    ]
    if client_name:
        parts.append(f"Client: {client_name}")
    if objectives:
        parts.append(f"Objectives: {objectives}")
    parts.append(task_cap)
    parts.append("Generate the task plan.")
    return "\n".join(parts)


def _extract_json(text: str) -> dict[str, Any]:
    """Extract JSON from model output using 3 fallback strategies."""
    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown code fence
    stripped = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.MULTILINE)
    stripped = re.sub(r"\s*```$", "", stripped.strip(), flags=re.MULTILINE)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # 3. Extract outermost {...}
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract JSON from generator output:\n{text[:500]}")


def _parse_and_validate(raw: str, engagement_id: int) -> list[Task]:
    """Parse and validate LLM JSON output into Task objects, guaranteeing at least one recon task."""
    data = _extract_json(raw)
    raw_tasks: list[dict[str, Any]] = data.get("tasks", [])

    valid_ids: set[str] = {t.get("id", "") for t in raw_tasks if t.get("id")}

    tasks: list[Task] = []
    seen_types: set[str] = set()

    for t in raw_tasks:
        task_type = str(t.get("type", "")).strip().lower()
        if task_type not in VALID_TYPES:
            continue

        task_id = str(t.get("id", f"{task_type}_{len(tasks)}")).strip()
        description = str(t.get("description", "")).strip()
        target = str(t.get("target", "all")).strip()
        priority = max(1, min(10, int(t.get("priority", 5))))
        depends_on = [d for d in t.get("depends_on", []) if d in valid_ids]
        phase = _PHASE_MAP[task_type]

        tasks.append(Task(
            id=task_id,
            type=task_type,
            description=description,
            target=target,
            depends_on=depends_on,
            priority=priority,
            phase=phase,
        ))
        seen_types.add(task_type)

    # Ensure at least one recon task
    if "recon" not in seen_types:
        tasks.insert(0, Task(
            id="recon_default",
            type="recon",
            description="Network reconnaissance — discover hosts, open ports, and services",
            target="all",
            phase=1,
        ))

    return tasks
