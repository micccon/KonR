"""Orchestrator — coordinates Generator + specialist agents across phases."""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from konr.agents.adviser import Adviser
from konr.agents.base import AgentResult, BaseAgent
from konr.agents.planning.generator import Generator, Task
from konr.agents.planning.refiner import Refiner
from konr.agents.reporter import Reporter
from konr.container.executor import CommandExecutor
from konr.core import config
from konr.core.approvals import EngagementScope, ScopeChecker
from konr.core.events import Event, EventBus, EventType
from konr.core.session import Session, SessionState
from konr.storage.db import FindingsDB

# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class TaskOutcome:
    task: Task
    agent_result: AgentResult

    @property
    def status(self) -> str:
        """Derived status string used by the refiner and TUI to assess phase outcomes."""
        if not self.agent_result.success:
            return "error"
        if self.agent_result.findings_count == 0:
            return "empty"
        return "success"


@dataclass
class EngagementResult:
    success: bool
    phases_completed: int
    task_results: list[TaskOutcome] = field(default_factory=list)
    error: str | None = None


# ── Orchestrator ──────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Runs a full engagement lifecycle:
      1. Generate TaskPlan
      2. Execute phases in order, respecting depends_on within each phase
      3. Emit phase and engagement events throughout

    Specialist agents are injected via `agent_registry` so that:
    - Tests can pass fake agents without touching unimplemented specialists
    - Specialists can be registered incrementally as they're built

    Usage:
        orc = Orchestrator(session, bus, db, executor, ctf_mode=True,
                           agent_registry={"recon": ReconAgent, ...})
        result = await orc.run(engagement_id=1, target_scope="10.0.0.1", mode="ctf")
    """

    def __init__(
        self,
        session: Session,
        bus: EventBus,
        db: FindingsDB,
        executor: CommandExecutor | None = None,
        ctf_mode: bool = False,
        agent_registry: dict[str, type[BaseAgent]] | None = None,
    ) -> None:
        self.session = session
        self.bus = bus
        self.db = db
        self.executor = executor
        self.ctf_mode = ctf_mode
        self._registry: dict[str, type[BaseAgent]] = agent_registry or {}
        self._generator = Generator()
        self._adviser = Adviser()
        self._refiner = Refiner(db)
        self._reporter = Reporter(db)
        self._refiner_cycles = 0
        self._scope: ScopeChecker | None = None
        # Shared across all child agents — avoids one ChromaDB client per agent
        # and the SQLite WAL lock contention that would cause.
        try:
            from konr.storage.memory import VectorMemory
            self._memory: VectorMemory | None = VectorMemory()
            self._knowledge_empty = self._memory.count("knowledge") == 0
        except Exception:
            self._memory = None
            self._knowledge_empty = False
        self.bus.subscribe(EventType.AGENT_STUCK, self._on_agent_stuck)

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(
        self,
        engagement_id: int,
        target_scope: str,
        mode: str,
        client_name: str = "",
        objectives: str = "",
    ) -> EngagementResult:
        """Generate a plan and execute it phase by phase."""
        self._scope = ScopeChecker(EngagementScope.from_target_scope(target_scope))

        if self._knowledge_empty:
            await self.bus.publish(
                EventBus.make(
                    EventType.AGENT_ERROR, agent="orchestrator",
                    reason="Knowledge base is empty — run 'make seed-knowledge' for better recall",
                )
            )

        await self.bus.publish(
            EventBus.make(EventType.AGENT_STARTED, agent="orchestrator",
                          task=f"Generating engagement plan for {target_scope}")
        )

        # Keep the TUI alive during plan generation — without this, the UI goes
        # silent for several seconds and looks frozen.
        async def _planning_heartbeat() -> None:
            dots = 0
            while True:
                await asyncio.sleep(4)
                dots = (dots % 3) + 1
                await self.bus.publish(EventBus.make(
                    EventType.AGENT_THINKING, agent="orchestrator",
                    text=f"Generating task plan{'.' * dots}",
                ))

        heartbeat = asyncio.create_task(_planning_heartbeat())
        try:
            plan = await self._generator.generate(
                engagement_id=engagement_id,
                target_scope=target_scope,
                mode=mode,
                client_name=client_name,
                objectives=objectives,
            )
        finally:
            heartbeat.cancel()

        self.db.log_action(
            engagement_id, "orchestrator", "plan_generated",
            summary=f"{len(plan.tasks)} tasks across {len(plan.by_phase())} phases",
        )
        n_tasks  = len(plan.tasks)
        n_phases = len(plan.by_phase())
        await self.bus.publish(
            EventBus.make(EventType.AGENT_FINISHED, agent="orchestrator",
                          summary=f"Plan ready: {n_tasks} tasks across {n_phases} phases")
        )

        all_outcomes: list[TaskOutcome] = []
        phases_completed = 0

        for phase_num, phase_tasks in sorted(plan.by_phase().items()):
            if self.session.state == SessionState.DONE:
                break

            await self.session.set_phase(f"phase_{phase_num}")

            outcomes = await self._run_phase(phase_num, phase_tasks, all_outcomes)
            all_outcomes.extend(outcomes)
            phases_completed += 1

            await self.bus.publish(
                EventBus.make(EventType.PHASE_FINISHED, agent="orchestrator",
                              phase=phase_num,
                              succeeded=sum(1 for o in outcomes if o.status == "success"),
                              total=len(outcomes))
            )

            # Refiner: adapt remaining tasks based on phase outcomes
            if self._refiner_cycles < config.MAX_REFINER_CYCLES:
                remaining = [
                    t for ph, tasks in sorted(plan.by_phase().items())
                    for t in tasks if ph > phase_num
                ]
                if remaining:
                    updated = await self._refiner.adapt(plan, outcomes, remaining)
                    updated_ids = {t.id for t in updated}
                    # t.phase <= phase_num keeps completed tasks even if refiner echoes their IDs
                    plan.tasks = (
                        [t for t in plan.tasks if t.id not in updated_ids or t.phase <= phase_num]
                        + updated
                    )
                    self._refiner_cycles += 1

        await self.session.finish()

        try:
            report_path = await self._reporter.generate(engagement_id)
            await self.bus.publish(
                EventBus.make(EventType.AGENT_FINISHED, agent="reporter",
                              summary=f"Report written: {report_path}")
            )
        except Exception as exc:
            await self.bus.publish(
                EventBus.make(EventType.AGENT_ERROR, agent="reporter", reason=str(exc))
            )

        return EngagementResult(
            success=True,
            phases_completed=phases_completed,
            task_results=all_outcomes,
        )

    # ── Adviser (stuck handling) ──────────────────────────────────────────────

    def _on_agent_stuck(self, event: Event) -> None:
        """Sync event handler — schedules the async adviser call without blocking the bus."""
        asyncio.ensure_future(self._handle_stuck(event))

    async def _handle_stuck(self, event: Event) -> None:
        """Ask the Adviser for a concrete alternative and inject it as a user message."""
        try:
            hint = await self._adviser.generate(
                agent_name=event.agent or "?",
                task=event.data.get("reason", ""),
            )
            await self.session.user_messages.put(f"[adviser] {hint}")
        except Exception:
            pass  # adviser failure should never crash the engagement

    # ── Phase execution ───────────────────────────────────────────────────────

    async def _run_phase(
        self,
        phase_num: int,
        tasks: list[Task],
        prior_outcomes: list[TaskOutcome],
    ) -> list[TaskOutcome]:
        """
        Execute tasks in a phase respecting depends_on ordering.

        Tasks are sorted into dependency layers via topological sort. Each layer
        is run concurrently with asyncio.gather, bounded by MAX_CONCURRENT_AGENTS.
        Layers are executed in sequence.
        """
        sem = asyncio.Semaphore(config.MAX_CONCURRENT_AGENTS)

        async def _guarded(
            task: Task,
            completed: dict[str, TaskOutcome],
            name: str,
            peers: set[str],
        ) -> TaskOutcome:
            async with sem:
                return await self._run_task(task, completed, agent_name=name, peer_types=peers)

        completed: dict[str, TaskOutcome] = {o.task.id: o for o in prior_outcomes}
        layers = _topo_layers(tasks, completed_ids=set(completed.keys()))
        phase_outcomes: list[TaskOutcome] = []

        for layer in layers:
            if self.session.state == SessionState.DONE:
                break

            # Assign per-instance names when multiple tasks of the same type run in parallel
            type_counts = Counter(t.type for t in layer)
            type_idx: dict[str, int] = {}
            task_names: dict[str, str] = {}
            for t in layer:
                if type_counts[t.type] > 1:
                    type_idx[t.type] = type_idx.get(t.type, 0) + 1
                    task_names[t.id] = f"{t.type}_{type_idx[t.type]}"
                else:
                    task_names[t.id] = t.type

            layer_peer_types = {t.type for t in layer}
            layer_outcomes = await asyncio.gather(
                *[
                    _guarded(task, completed, task_names[task.id],
                             layer_peer_types - {task.type})
                    for task in layer
                ],
                return_exceptions=False,
            )
            for outcome in layer_outcomes:
                completed[outcome.task.id] = outcome
                phase_outcomes.append(outcome)

        return phase_outcomes

    # ── Task execution ────────────────────────────────────────────────────────

    async def _run_task(
        self,
        task: Task,
        completed: dict[str, TaskOutcome],
        agent_name: str | None = None,
        peer_types: set[str] | None = None,
    ) -> TaskOutcome:
        """Instantiate the appropriate specialist agent and run a single task."""
        agent_cls = self._registry.get(task.type)
        if agent_cls is None:
            result = AgentResult(
                success=False,
                summary="",
                error=f"No agent registered for task type '{task.type}'",
            )
            return TaskOutcome(task=task, agent_result=result)

        agent = agent_cls(
            engagement_id=self.session.engagement_id,
            session=self.session,
            bus=self.bus,
            db=self.db,
            executor=self.executor,
            ctf_mode=self.ctf_mode,
            scope=self._scope,
            memory=self._memory,
        )
        if agent_name:
            agent.name = agent_name

        task_prompt = f"{task.description}\nTarget: {task.target}"
        context = _build_context(task, completed, self.ctf_mode, peer_types or set())

        result = await agent.run(task_prompt, context)
        if await self._run_summarizer(agent):
            await self._run_verifier(agent, task)
        return TaskOutcome(task=task, agent_result=result)

    async def _run_summarizer(self, specialist: BaseAgent) -> bool:
        """Generate a structured summary of the specialist's run using Haiku. Returns True on success."""
        from konr.agents.summarizer import SummarizerAgent
        await self.bus.publish(
            EventBus.make(EventType.SUMMARIZER_STARTED, agent="summarizer", specialist=specialist.name)
        )
        try:
            summarizer = SummarizerAgent()
            await summarizer.summarize(specialist.name, specialist._messages)
            await self.bus.publish(
                EventBus.make(EventType.SUMMARIZER_FINISHED, agent="summarizer", specialist=specialist.name)
            )
            return True
        except Exception as exc:
            await self.bus.publish(
                EventBus.make(
                    EventType.AGENT_ERROR, agent="summarizer",
                    reason=f"Summary generation failed for {specialist.name}: {exc}",
                )
            )
            return False

    async def _run_verifier(self, specialist: BaseAgent, task: Task) -> None:
        """Run VerifierAgent after a specialist completes, injecting the specialist's summary."""
        from konr.agents.specialists.verifier import VerifierAgent

        summary_path = config.WORK_DIR / f"{specialist.name}_summary.md"
        if not summary_path.exists():
            await self.bus.publish(
                EventBus.make(
                    EventType.AGENT_ERROR, agent="verifier",
                    reason=f"No summary file for {specialist.name} — skipping verification",
                )
            )
            return

        summary_content = summary_path.read_text(encoding="utf-8")
        verifier = VerifierAgent(
            engagement_id=self.session.engagement_id,
            session=self.session,
            bus=self.bus,
            db=self.db,
            executor=self.executor,
            memory=self._memory,
            specialist_name=specialist.name,
        )
        await self.bus.publish(
            EventBus.make(EventType.VERIFIER_STARTED, agent="verifier", specialist=specialist.name)
        )
        await verifier.run(
            task=f"Store all findings from the {specialist.name} summary for {task.target}",
            context={"specialist_summary": summary_content},
        )
        await self.bus.publish(
            EventBus.make(EventType.VERIFIER_FINISHED, agent="verifier", specialist=specialist.name)
        )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _topo_layers(
    tasks: list[Task],
    completed_ids: set[str],
) -> list[list[Task]]:
    """
    Group tasks into ordered layers where each layer's depends_on are
    satisfied by prior layers or already-completed tasks.

    Cycles are broken by treating unresolvable tasks as independent.
    """
    remaining = list(tasks)
    layers: list[list[Task]] = []
    satisfied = set(completed_ids)

    while remaining:
        ready = [t for t in remaining if all(d in satisfied for d in t.depends_on)]

        if not ready:
            # Cycle or external dep — treat all remaining as ready to avoid deadlock
            ready = remaining

        layers.append(sorted(ready, key=lambda t: t.priority))
        satisfied.update(t.id for t in ready)
        remaining = [t for t in remaining if t not in ready]

    return layers


def _build_context(
    task: Task,
    completed: dict[str, TaskOutcome],
    ctf_mode: bool,
    peer_types: set[str] | None = None,
) -> dict[str, Any]:
    """Build the context dict passed to agent.run(), including dependency summaries and peer agent names."""
    dep_summaries = []
    for dep_id in task.depends_on:
        if dep_id in completed:
            outcome = completed[dep_id]
            dep_summaries.append({
                "task_id": dep_id,
                "status": outcome.status,
                "summary": outcome.agent_result.summary,
                "findings_count": outcome.agent_result.findings_count,
            })

    return {
        "task_id": task.id,
        "task_type": task.type,
        "target": task.target,
        "ctf_mode": ctf_mode,
        "dependency_results": dep_summaries,
        "peer_agents": sorted(peer_types or []),
    }
