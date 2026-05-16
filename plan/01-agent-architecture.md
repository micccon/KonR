# Agent Architecture

## Overview

The system uses a **hierarchical multi-agent pattern** where a top-level Orchestrator coordinates specialized agents through a structured task lifecycle. Agents communicate via a shared SQLite findings database and an in-process EventBus — never directly calling each other.

---

## Agent Hierarchy

```
Orchestrator
├── Generator          → creates TaskPlan from engagement context
├── Refiner            → adapts remaining tasks after each phase
├── Adviser            → provides alternative strategies when agent is stuck
├── Reporter           → generates final Markdown report
└── Specialists
    │
    │  Phase 1 — PARALLEL
    ├── OSINTAgent         → theHarvester, Shodan API, Recon-ng, breach lookups (passive)
    ├── ReconAgent         → nmap, masscan, amass, subfinder, httpx (active)
    │
    │  Phase 2 — PARALLEL (after Phase 1 complete)
    ├── WebAgent           → ffuf, nikto → sqlmap, XSS, IDOR, API testing
    ├── NetworkExploitAgent→ Metasploit, searchsploit, nuclei CVE templates
    │   └── CoderAgent     → support: custom exploits, payload crafting (on-demand)
    │
    │  Phase 3 — SEQUENTIAL (after initial access)
    ├── ADAgent            → BloodHound, ldap → Impacket, CrackMapExec
    └── PostExploitAgent   → linpeas → privesc, lateral movement, persistence
        └── CoderAgent     → support: custom exploits, payload crafting (on-demand)
```

---

## BaseAgent

All agents inherit from `BaseAgent` in `konr/agents/base.py`.

### Responsibilities
- Manages the Claude API message loop with prompt caching (`cache_control` on system prompt)
- Dispatches tool calls to the correct handler
- Detects stuck state (5+ identical tool calls → notify Orchestrator → Adviser intervenes)
- Enforces hard tool call limit (100 per task)
- Truncates large tool outputs (> 8KB → Haiku summarization before returning to agent)
- Emits events to EventBus on key state changes
- Tracks token usage per call → accumulates cost in session
- Checks `session.skip_event` at loop top — if set, exits the task cleanly
- Injects pending `session.user_messages` into the last user turn each iteration
- Prepends `session.pinned_context` items to the system prompt every iteration

### API Retry Policy

The Anthropic API call is wrapped with `tenacity` retry logic (`_api_call_with_retry` in `base.py`):
- Retries up to 3 times on `APIStatusError`, `RateLimitError`, `APIConnectionError`
- Exponential backoff: 1s → 4s → 16s
- After 3 consecutive failures the exception propagates, task is marked failed, engagement continues

### Output Truncation

When `CommandExecutor.run()` returns `result.truncated = True` (output exceeded 8KB), `_handle_execute_command` calls `_haiku_summarize` before returning to the agent. The agent receives a compact summary instead of raw noise.

```python
# konr/agents/base.py

async def _handle_execute_command(self, inputs: dict) -> str:
    result = executor.run(command, timeout=timeout, ctf_mode=self.ctf_mode)
    ...
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

Note: the 8KB truncation happens inside `CommandExecutor` (in `konr/container/executor.py`). `_haiku_summarize` receives the already-truncated 8KB slice and further compresses it for the agent context.

### LLM Loop Design
```python
class BaseAgent:
    model = "claude-sonnet-4-6"
    max_tool_calls = 100
    stuck_threshold = 5

    async def run(self, task: Task, context: AgentContext) -> AgentResult:
        messages = self._build_initial_messages(task, context)
        tool_call_history = []

        while True:
            response = await self.client.messages.create(
                model=self.model,
                tools=TOOL_DEFINITIONS,
                messages=messages,
            )

            if response.stop_reason == "end_turn":
                return AgentResult(success=True, summary=self._extract_summary(response))

            for block in response.content:
                if block.type == "tool_use":
                    # Stuck detection
                    tool_call_history.append((block.name, block.input))
                    if self._is_stuck(tool_call_history):
                        await self.event_bus.emit(Event.AGENT_STUCK, agent=self.name)
                        # Adviser will inject a hint into context

                    # Approval gate check
                    if self.tool_registry.requires_approval(block.name, block.input):
                        approved = await self.approval_gate.request(
                            command=self._format_command(block.name, block.input),
                            reason=self._extract_reasoning(messages),
                            risk_level=self.tool_registry.risk_level(block.name),
                        )
                        if not approved:
                            result = ToolResult(output="[skipped by user]", success=False)
                        else:
                            result = await self.dispatch_tool(block.name, block.input)
                    else:
                        result = await self.dispatch_tool(block.name, block.input)

                    messages = self._append_tool_result(messages, block.id, result)

            if len(tool_call_history) >= self.max_tool_calls:
                return AgentResult(success=False, summary="Hit tool call limit")
```

### Stuck Detection
```python
def _is_stuck(self, history: list[tuple]) -> bool:
    if len(history) < self.stuck_threshold:
        return False
    last_n = history[-self.stuck_threshold:]
    return len(set(str(h) for h in last_n)) == 1  # all identical
```

---

## Orchestrator

**File:** `konr/agents/orchestrator.py`

Manages the full engagement lifecycle. Does not run its own LLM loop — it coordinates the other agents.

### Responsibilities
1. Initialize engagement in SQLite
2. Call Generator to produce TaskPlan
3. Execute tasks sequentially, routing to specialist agents
4. After each task: call Refiner to adapt remaining plan
5. On AGENT_STUCK event: call Adviser, inject hint into specialist context
6. On all tasks complete: call Reporter
7. Handle user pause/resume/stop signals

### Task Routing

Specialist agents are injected at construction via `agent_registry` — a `dict[str, type[BaseAgent]]`. This avoids importing unimplemented stubs and makes the orchestrator trivially testable with fake agents.

```python
# At startup, build the registry from implemented specialists:
from konr.agents.specialists.recon import ReconAgent
# ... other specialists as they're implemented

orc = Orchestrator(
    session=session, bus=bus, db=db, executor=executor, ctf_mode=ctf,
    agent_registry={
        "recon": ReconAgent,
        # "osint": OSINTAgent,  # add as each is built
        # "web": WebAgent,
        # ...
    },
)
```

If a task type has no registered agent, the orchestrator returns a `TaskOutcome` with `status="error"` and continues — it does not abort the engagement.

### Parallel Execution Design

```python
async def run_phase(self, tasks: list[Task]) -> list[AgentResult]:
    """Run tasks in a phase concurrently using asyncio.gather."""
    return await asyncio.gather(
        *[self._run_task(task) for task in tasks],
        return_exceptions=True,
    )

async def run_engagement(self, plan: TaskPlan):
    for phase_tasks in self._group_by_phase(plan.tasks):
        results = await self.run_phase(phase_tasks)
        # Merge all findings into SQLite before next phase
        await self.refiner.adapt(plan, results)
        # Check if next phase should be skipped (e.g., no AD environment found)
```

### Dependency Semantics

`depends_on` means **"run after"**, not **"only run if this succeeded"**.

A task completes in one of three states: `success`, `empty` (ran but found nothing), or `error`. All three count as "done" for the purposes of unblocking dependents. The orchestrator must never hard-block a task because a dependency returned `empty` or `error` — it should proceed and let the downstream agent decide whether it has enough context to act.

**Why this matters:** The Generator sometimes emits plans where `postexploit_privesc` depends on `ad_enum`. On a non-AD target `ad_enum` will complete with zero findings. If dependencies were treated as success gates, privilege escalation would never run on the majority of CTF boxes. The right behaviour is: unblock the dependent, pass it the (empty) context, and let it adapt.

### State Machine
```
IDLE → PLANNING → RUNNING → [PAUSED] → COMPLETE
                              ↑    ↓
                            (user Ctrl+P)
```

---

## Generator

**File:** `konr/agents/generator.py`

Single LLM call (no tool loop) that produces a structured TaskPlan from the engagement context.

### Input
- Engagement scope (targets, client, objectives)
- Mode (pentest / ctf)

### Output
```python
@dataclass
class TaskPlan:
    tasks: list[Task]  # ordered

@dataclass
class Task:
    id: str
    type: str          # recon | web | ad | postexploit
    description: str
    target: str
    depends_on: list[str]
    priority: int
```

### Task Schema (updated)
```python
@dataclass
class Task:
    id: str
    type: str          # osint | recon | web | network_exploit | ad | postexploit
    description: str
    target: str
    depends_on: list[str]
    priority: int
    phase: int         # 1=parallel-free, 2=parallel-gated, 3=sequential-gated
```

### System Prompt (key excerpt)
```
You are a penetration testing task planner. Given an engagement scope, produce
an ordered TaskPlan organized into three phases:
- Phase 1 (parallel, free): osint + recon tasks
- Phase 2 (parallel, gated): web + network_exploit tasks
- Phase 3 (sequential, gated): ad tasks (only if Windows/AD in scope), then postexploit

Rules:
- Always include both osint and recon in Phase 1
- Only include ad tasks if scope indicates Windows/Active Directory environment
- Maximum 15 tasks per plan
- Each task must have a clear, measurable objective
- Output ONLY valid JSON matching the TaskPlan schema
```

---

## Refiner

**File:** `konr/agents/refiner.py`

Called after each task completes. Single LLM call that reviews remaining tasks against new findings and returns an updated (pruned/reordered/augmented) task list.

### Input
- Completed task + its findings summary
- Remaining tasks in plan
- Current findings from SQLite

### Output
- Updated `list[Task]` (may add, remove, or reorder tasks)

### Limits
- Max 3 refinements per plan to prevent endless replanning
- If no changes needed, returns original list unchanged

---

## Adviser

**File:** `konr/agents/adviser.py`

Called when Orchestrator receives `AGENT_STUCK` event. Produces a hint that gets injected into the stuck agent's next message.

### Input
- Agent name
- Last 10 tool calls + results (the repeated pattern)
- Current task description
- Relevant findings from SQLite

### Output
- `str` hint injected as a system message: "You appear to be stuck. Consider: [alternative approach]..."

### System Prompt (key excerpt)
```
A specialist agent has repeated the same tool call 5 times without progress.
Review the execution history and suggest a specific alternative approach.
Be concrete: name the tool, flags, and target they should try instead.
Do not repeat what was already attempted.
```

---

## Specialist Agents

### OSINTAgent — `konr/agents/specialists/osint.py`
- **Autonomy:** Fully free (passive only — no packets sent to target)
- **Tools used:** theHarvester, recon-ng, amass (passive mode), whois, dnsrecon, curl (Shodan/Censys/Hunter/VirusTotal APIs)
- **API integrations:** Shodan, Censys, Hunter.io, VirusTotal (keys from config — graceful degradation if missing)
- **Outputs stored:** `osint_data` ChromaDB collection, hosts table (discovered IPs/domains), session_log
- **System prompt focus:**
  - Map the target organization: subsidiaries, domains, IP ranges, employees
  - Discover email addresses and naming conventions
  - Identify technologies in use (BuiltWith/Shodan data) → feed to NetworkExploitAgent for CVE research
  - Search breach databases for credential exposure
  - Research known CVEs for discovered services/versions

### ReconAgent — `konr/agents/specialists/recon.py`
- **Autonomy:** Fully free (no approval gates)
- **Tools used:** nmap, masscan, amass, theHarvester, dnsrecon, dig, whois, subfinder, httpx
- **Outputs stored:** hosts table, services table, session_log, vector memory
- **System prompt focus:** Comprehensive coverage before moving on. Map all hosts, ports, services, DNS records, and any OSINT (emails, subdomains, tech stack).

### WebAgent — `konr/agents/specialists/web.py`
- **Autonomy:** Enumeration free; exploitation gated
- **Free tools:** ffuf, gobuster, nikto, httpx, curl, feroxbuster
- **Gated tools:** sqlmap, dalfox, commix, nuclei (exploit templates)
- **Outputs stored:** vulnerabilities table, attack_chains
- **System prompt focus:** Systematically test OWASP Top 10. Start with content discovery, then test each endpoint.

### ADAgent — `konr/agents/specialists/ad.py`
- **Autonomy:** Enumeration free; attacks gated
- **Free tools:** bloodhound-python (collection), ldapsearch, ldapdomaindump, kerbrute (user enum)
- **Gated tools:** impacket (GetNPUsers, secretsdump, psexec), crackmapexec (password spraying), evil-winrm
- **Outputs stored:** hosts, credentials, attack_chains
- **System prompt focus:** Enumerate before attacking. Map the domain, find misconfigurations (unconstrained delegation, ASREP roasting, Kerberoasting), then attack.

### NetworkExploitAgent — `konr/agents/specialists/network_exploit.py`
- **Autonomy:** All actions gated (CVE exploitation = high risk)
- **Gated tools:** msfconsole, msfvenom, nuclei (CVE exploit templates), custom python exploits via Coder Agent
- **Free tools:** searchsploit (research only, no execution), curl (PoC validation)
- **Workflow:**
  1. Read Recon + OSINT findings from SQLite (services, versions, tech stack)
  2. `searchsploit` each discovered service version → identify candidate exploits
  3. Query `knowledge` ChromaDB for CVE details on discovered services
  4. Request approval before launching any exploit
  5. If Metasploit module exists: use it; if not, delegate to CoderAgent for custom PoC
  6. Validate exploitation (shell, RCE, auth bypass) → store credential/chain finding
- **Outputs stored:** vulnerabilities (with CVE), credentials (if auth bypass), attack_chains

### CoderAgent — `konr/agents/specialists/coder.py`
- **Autonomy:** Called by other agents via `delegate_to` tool; not a phase agent
- **Gated:** Yes — executing any code it writes requires approval
- **Tools used:** python3, gcc, go, msfvenom, pwntools (all inside Docker container)
- **When called:**
  - NetworkExploitAgent: "No Metasploit module for this CVE — write a PoC"
  - WebAgent: "Need a custom SQLi payload to bypass this WAF"
  - PostExploitAgent: "Write a privilege escalation script for this SUID misconfiguration"
  - ADAgent: "Modify this Impacket script to handle this edge case"
- **Outputs stored:** `code_artifacts` ChromaDB collection (reusable across engagements), evidence_file in `/work/`
- **System prompt focus:** Write minimal, targeted exploit code. Always explain what the code does before requesting execution approval. No unnecessary complexity.

### PostExploitAgent — `konr/agents/specialists/postexploit.py`
- **Autonomy:** All actions gated
- **Gated tools:** linpeas, winpeas, pspy, john, hashcat, all privesc exploits, persistence mechanisms
- **Outputs stored:** credentials, attack_chains, session_log
- **System prompt focus:** Methodical escalation. Gather info → identify path → get approval → execute → document.

---

## Reporter

**File:** `konr/agents/reporter.py`

Does not execute tools. Queries SQLite, formats findings, and writes a Markdown report.

### Process
1. `SELECT * FROM vulnerabilities WHERE engagement_id = ?` ordered by CVSS
2. `SELECT * FROM attack_chains WHERE engagement_id = ?`
3. `SELECT * FROM credentials WHERE engagement_id = ?`
4. `SELECT * FROM approvals WHERE engagement_id = ?` (command log)
5. Pass structured data to Claude with report template
6. Write output to `reports/{engagement_name}_{date}.md`

---

## Agent Communication Summary

| From → To | Mechanism |
|-----------|-----------|
| Orchestrator → Generator | Direct function call |
| Orchestrator → Specialist | Direct function call with Task |
| Orchestrator → Refiner | Direct function call after task done |
| Orchestrator → Adviser | Direct function call on STUCK event |
| Specialist → SQLite | `store_finding` tool call |
| Specialist → ChromaDB | `search_memory` / auto-stored tool outputs |
| Specialist → Approval Gate | `request_approval` tool call |
| Approval Gate → TUI | EventBus `APPROVAL_NEEDED` event |
| TUI → Approval Gate | User response via EventBus `APPROVAL_DECIDED` |
| Orchestrator → Reporter | Direct function call at end |

---

## System Prompt Templates

Each agent has a dedicated system prompt file in `pentest_ai/agents/prompts/`.

Common sections in every specialist prompt:
1. **Role** — who the agent is and what it's responsible for
2. **Target** — the specific task and target provided at runtime
3. **Methodology** — ordered steps to follow
4. **Scope declaration** — "Only act against targets in: {scope}"
5. **Hard limits** — never DoS, never destroy data, never act outside scope
6. **Tool guidance** — specific flags and usage patterns for each tool
7. **Output format** — how to structure findings for `store_finding` calls

---

## Error Handling

| Condition | Response |
|-----------|----------|
| LLM API error | Retry up to 3 times with exponential backoff |
| 3 consecutive LLM failures | Mark task failed, continue to next task |
| Tool execution timeout | Return timeout error to agent, agent decides next step |
| Docker container crash | Orchestrator restarts container, resumes current task |
| User stops engagement | Save state, mark engagement as paused |
