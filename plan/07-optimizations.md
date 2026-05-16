# Cost & Performance Optimizations

## Overview

Three key optimizations informed by extended research across 15+ AI pentesting systems:
1. **Prompt caching** — cuts API cost 30-50% on long-running agents
2. **Context management** — prevents context overflow from massive tool outputs
3. **Parallel phase execution** — cuts total engagement time roughly in half

---

## 1. Prompt Caching

### Problem
Every agent makes dozens to hundreds of API calls per task. Each call re-sends the full system prompt (1000-3000 tokens). At Sonnet pricing, this adds up fast across a multi-hour engagement.

### Solution: Anthropic `cache_control`

Mark the system prompt as cacheable. Anthropic caches it for 5 minutes (refreshed on each use). Cache reads cost ~10% of normal input token price.

```python
# pentest_ai/agents/base.py

def _build_messages(self, task: Task, context: AgentContext) -> list[dict]:
    return [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": self.system_prompt,
                    "cache_control": {"type": "ephemeral"},  # ← cache this block
                },
                {
                    "type": "text",
                    "text": self._format_task_context(task, context),
                    # No cache_control on dynamic content — changes every call
                },
            ],
        }
    ]
```

**Important:** Anthropic requires `messages` API to use `cache_control` on the `system` parameter or within content blocks. Use the `system` parameter approach for cleaner code:

```python
response = await self.client.messages.create(
    model=self.model,
    max_tokens=8192,
    system=[
        {
            "type": "text",
            "text": self.system_prompt,
            "cache_control": {"type": "ephemeral"},
        }
    ],
    tools=self.tool_definitions,
    messages=messages,
)
```

### Expected Savings

For an agent with a 2000-token system prompt making 50 tool calls:
- Without caching: 50 × 2000 = 100,000 input tokens for system prompt alone
- With caching: 1 cache write (2000 tokens × 1.25 = 2500 tokens cost) + 49 cache reads (2000 × 0.1 = 200 tokens cost each)
- **Reduction: ~90% on system prompt tokens** → ~30-50% total cost reduction

### Cache Warm-up

First call in each agent session pays full price (cache write). All subsequent calls within 5 minutes pay cache-read price. For agents that run for hours, the cache is refreshed automatically on each use.

---

## 2. Context Management (Output Truncation)

### Problem

Security tools produce massive outputs:
- `nmap -sV -p- 10.0.1.0/24` on a /24 subnet: 50-200KB
- BloodHound JSON collection: 10-100MB (never send this to agent)
- `theHarvester` on a large org: 20-50KB
- `linpeas.sh`: 500KB+ on a complex system

Sending these directly to the agent blows up the context window and wastes tokens.

### Solution: 8KB Threshold + Haiku Summarization

The 8KB truncation happens in `CommandExecutor.run()` (inside `konr/container/executor.py`). When `result.truncated = True`, `BaseAgent._handle_execute_command()` passes the already-truncated output to `_haiku_summarize()` for further compression before returning to the agent.

```python
# konr/agents/base.py

async def _handle_execute_command(self, inputs: dict) -> str:
    result = executor.run(command, timeout=timeout, ctf_mode=self.ctf_mode)

    output = result.output
    if result.truncated:
        output = await self._haiku_summarize(output, command)

    prefix = f"[exit {result.exit_code}]"
    if result.truncated:
        prefix += " [summarized]"
    return f"{prefix}\n{output}"

async def _haiku_summarize(self, output: str, command: str) -> str:
    tool_name = command.split()[0] if command else "tool"
    prompt = (
        f"Summarize this pentest tool output from `{tool_name}`. "
        "Preserve all IPs, ports, CVEs, usernames, credentials, service versions, and flags. "
        "Remove repetitive lines and verbose boilerplate. Be concise.\n\n"
        f"{output}"
    )
    try:
        response = self._client.messages.create(
            model=config.HAIKU_MODEL,  # claude-haiku-4-5-20251001
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return _extract_text(response.content)
    except Exception:
        return output  # fall back to raw truncated output if Haiku fails
```

The agent sees `[exit 0] [summarized]` in the prefix so it knows summarization occurred. The raw truncated output (8KB slice) is what Haiku works on — the full untruncated output is not re-fetched.

### Special Case: BloodHound JSON

BloodHound collection produces JSON files too large to even pass to Haiku. Handle differently:

```python
# BloodHound agent runs: bloodhound-python -c All -d domain -u user -p pass
# Output: *.json files in /work/ad/bloodhound/
# Agent uses searchable CLI queries instead of reading raw JSON:
#   bloodhound-cli query "MATCH (n:User) WHERE n.enabled=true RETURN n.name LIMIT 50"
# Or: upload to a local Neo4j instance and query via Cypher
```

---

## 3. Parallel Phase Execution

### Problem

The original sequential design runs phases one at a time:
OSINT → Recon → Web → NetworkExploit → AD → PostExploit

Total time: sum of all phases. An engagement with 6 phases averaging 20 min each = 2 hours.

### Solution: asyncio.gather for Phase Groups

```python
# pentest_ai/agents/orchestrator.py

PHASE_GROUPS = [
    ["osint", "recon"],           # Phase 1: run in parallel, both free
    ["web", "network_exploit"],   # Phase 2: run in parallel, both gated
    ["ad"],                       # Phase 3a: AD (if applicable)
    ["postexploit"],              # Phase 3b: post-exploit after AD
]

async def run_engagement(self, plan: TaskPlan, session: Session):
    for phase_idx, task_types in enumerate(PHASE_GROUPS):
        phase_tasks = [t for t in plan.tasks if t.type in task_types]

        if not phase_tasks:
            continue  # e.g., skip AD phase if no Windows hosts

        # Check pause before each phase
        await session.check_pause()

        # Run phase tasks concurrently
        results = await asyncio.gather(
            *[self._run_task(task, session) for task in phase_tasks],
            return_exceptions=True,
        )

        # Log any exceptions without killing the engagement
        for task, result in zip(phase_tasks, results):
            if isinstance(result, Exception):
                await self.db.log_action(
                    engagement_id=session.engagement_id,
                    agent="orchestrator",
                    action=f"Task {task.id} failed",
                    summary=str(result),
                )

        # Refiner adapts remaining plan after each phase
        remaining = [t for t in plan.tasks if t.type not in task_types]
        if remaining:
            plan.tasks = await self.refiner.adapt(plan, results, remaining)
```

### Approval Gate with Parallel Agents

When two agents run in parallel and both hit approval gates simultaneously, the TUI queues them:

```python
# EventBus approval queue handles concurrent requests gracefully
# TUI shows one approval at a time; second agent waits in asyncio queue

class ApprovalGate:
    def __init__(self):
        self._semaphore = asyncio.Semaphore(1)  # one approval dialog at a time

    async def check(self, agent, tool, tool_input, reasoning, engagement_id):
        async with self._semaphore:  # queues additional approval requests
            # ... existing approval logic
```

### Time Savings

| Approach | Estimated Time |
|----------|---------------|
| Sequential (original) | ~2-3 hours |
| Parallel Phase 1 (OSINT+Recon together) | ~1.5-2 hours |
| Parallel Phase 1 + 2 (Web+NetExploit together) | ~1-1.5 hours |

Phase 1 is the biggest win — OSINT and active recon take similar time and share no dependencies.

---

## 4. Cost Tracking Per Agent

Track spend by agent to identify which are expensive and optimize over time.

Per-agent tracking reuses the existing `CostTracker` dataclass. `record_cost()` accepts an optional `agent` parameter — when provided, it updates both the global total and the per-agent tracker.

```python
# konr/core/session.py

class Session:
    def __init__(self, engagement_id: int, bus: EventBus):
        self.cost = CostTracker()                    # global total
        self.agent_costs: dict[str, CostTracker] = {}  # per-agent breakdown

    async def record_cost(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        agent: str | None = None,   # ← pass agent name to get per-agent breakdown
    ) -> None:
        self.cost.add(...)          # always accumulates into global total
        if agent:
            if agent not in self.agent_costs:
                self.agent_costs[agent] = CostTracker()
            self.agent_costs[agent].add(...)
        await self.bus.publish(Event(type=EventType.COST_UPDATE, data=self.cost.as_dict()))

    def summary(self) -> dict:
        return {
            ...
            "cost": self.cost.as_dict(),
            "agent_costs": {name: t.as_dict() for name, t in self.agent_costs.items()},
        }
```

`BaseAgent._loop()` passes `agent=self.name` on every `record_cost()` call:

```python
await self.session.record_cost(
    input_tokens=response.usage.input_tokens,
    output_tokens=response.usage.output_tokens,
    cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
    cache_write_tokens=getattr(response.usage, "cache_creation_input_tokens", 0),
    agent=self.name,
)
```

The TUI status bar shows live `$X.XX` total cost. `session.summary()["agent_costs"]` provides the per-agent breakdown for the end-of-engagement report.

---

## 5. Model Selection Strategy

| Task | Model | Reason |
|------|-------|--------|
| All specialist agents (tool use loops) | `claude-sonnet-4-6` | Best tool use, reasoning |
| Generator (plan decomposition) | `claude-sonnet-4-6` | One-shot, quality matters |
| Refiner (plan adaptation) | `claude-sonnet-4-6` | Reasoning over findings |
| Adviser (stuck recovery) | `claude-sonnet-4-6` | Creative problem solving |
| Output truncation/summarization | `claude-haiku-4-5-20251001` | Fast, cheap, adequate for parsing |
| Knowledge base seeding (classification) | `claude-haiku-4-5-20251001` | Batch processing, not reasoning |
| Reporter (report generation) | `claude-sonnet-4-6` | Quality writing matters |

**Rule:** Haiku for parsing/compression tasks; Sonnet for anything requiring security reasoning.
