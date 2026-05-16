# Approval Gate & Safety Design

## Overview

Two distinct safety layers:
1. **Approval Gate** — human-in-the-loop pausing before risky tool executions
2. **Scope Enforcement** — hard checks preventing execution outside declared scope
3. **Hard Refusal List** — things agents must never do regardless of instructions

---

## Approval Gate

### Decision Model

Before any gated tool call, the agent calls `request_approval`. This blocks execution until the user responds via TUI.

```
Agent → request_approval(command, reason, risk_level)
    ↓
EventBus.emit(APPROVAL_NEEDED)
    ↓
TUI shows ApprovalPanel
    ↓
User: [y] Approve / [n] Skip / [m] Modify / [s] Stop
    ↓
EventBus.respond_approval(decision)
    ↓
Agent receives decision, proceeds or skips
    ↓
Decision logged to SQLite approvals table
```

### Gating Rules — `tools/registry.py`

```python
# Gating rules: tool name → (requires_approval, risk_level)
TOOL_RULES: dict[str, tuple[bool, str]] = {
    # ── FREE (no approval) ────────────────────────────────────────────
    "nmap":           (False, "low"),
    "masscan":        (False, "low"),
    "amass":          (False, "low"),
    "subfinder":      (False, "low"),
    "theHarvester":   (False, "low"),
    "dig":            (False, "low"),
    "whois":          (False, "low"),
    "dnsrecon":       (False, "low"),
    "ffuf":           (False, "low"),
    "gobuster":       (False, "low"),
    "feroxbuster":    (False, "low"),
    "httpx":          (False, "low"),
    "nikto":          (False, "low"),
    "curl":           (False, "low"),
    "bloodhound-python": (False, "low"),   # collection only
    "ldapsearch":     (False, "low"),
    "ldapdomaindump": (False, "low"),
    "kerbrute":       (False, "low"),      # user enumeration only
    "linpeas.sh":     (False, "low"),      # info gathering
    "winpeas.exe":    (False, "low"),

    # ── GATED (approval required) ────────────────────────────────────
    "sqlmap":         (True, "medium"),
    "dalfox":         (True, "medium"),
    "commix":         (True, "high"),
    "nuclei":         (True, "medium"),    # only exploit templates
    # NetworkExploit Agent tools
    "metasploit":     (True, "critical"),
    "msfconsole":     (True, "critical"),
    "msfvenom":       (True, "high"),      # payload generation
    "searchsploit":   (False, "low"),      # research only, no execution
    "python":         (True, "medium"),    # Coder Agent: executing custom scripts
    "impacket-GetNPUsers":  (True, "medium"),
    "impacket-GetUserSPNs": (True, "medium"),
    "impacket-secretsdump": (True, "critical"),
    "impacket-psexec":      (True, "critical"),
    "impacket-wmiexec":     (True, "critical"),
    "impacket-smbexec":     (True, "critical"),
    "crackmapexec":   (True, "high"),
    "netexec":        (True, "high"),
    "evil-winrm":     (True, "high"),
    "john":           (True, "low"),       # offline cracking, low risk but log it
    "hashcat":        (True, "low"),
    "hydra":          (True, "high"),      # online brute force
    "medusa":         (True, "high"),
}

# CTF mode: all tools free (challenge environment expects aggressive testing)
CTF_MODE_ALL_FREE = True
```

### Context-Aware Gating

Some tools are free for certain flags but gated for others:

```python
def requires_approval(self, tool: str, args: dict) -> bool:
    if self.ctf_mode:
        return False

    rule = TOOL_RULES.get(tool)
    if rule is None:
        return True  # unknown tools → gated by default

    gated, risk = rule

    # Special cases
    if tool == "nmap" and "--script" in str(args):
        return True   # nmap scripts can be intrusive
    if tool == "kerbrute" and "bruteuser" in str(args):
        return True   # password spraying, not user enum

    return gated
```

---

## Scope Enforcement

### Engagement Scope Declaration

When creating an engagement, user provides scope as IP ranges and/or domains:

```python
@dataclass
class EngagementScope:
    ip_ranges: list[str]    # e.g. ["10.0.1.0/24", "192.168.5.10"]
    domains: list[str]      # e.g. ["acme.com", "*.acme.com"]
    excluded: list[str]     # explicitly out of scope
```

### Scope Checker — `core/approvals.py`

Before every `execute_command` call, the scope checker validates the target:

```python
class ScopeChecker:
    def __init__(self, scope: EngagementScope):
        self.networks = [ip_network(r, strict=False) for r in scope.ip_ranges]
        self.domains = scope.domains
        self.excluded = [ip_network(e, strict=False) for e in scope.excluded
                         if self._is_ip(e)]

    def is_in_scope(self, target: str) -> bool:
        """Check if a target IP or hostname is within declared scope."""
        # Exclude first
        if self._matches_excluded(target):
            return False

        # Check IP ranges
        if self._is_ip(target):
            addr = ip_address(target)
            return any(addr in net for net in self.networks)

        # Check domain wildcards
        for domain in self.domains:
            if domain.startswith("*."):
                if target.endswith(domain[1:]):
                    return True
            elif target == domain or target.endswith(f".{domain}"):
                return True

        return False

    def extract_target_from_command(self, command: str) -> str | None:
        """Best-effort extraction of target from common tool commands."""
        # nmap 10.0.1.5, nmap 10.0.1.0/24
        # sqlmap -u http://10.0.1.5/...
        # ffuf -u http://acme.com/...
        # crackmapexec smb 10.0.1.5
        ...
```

### Enforcement Point

In `BaseAgent.dispatch_tool()`:

```python
async def dispatch_tool(self, tool_name: str, tool_input: dict) -> ToolResult:
    if tool_name == "execute_command":
        command = tool_input["command"]
        target = self.scope_checker.extract_target_from_command(command)

        if target and not self.scope_checker.is_in_scope(target):
            await self.event_bus.emit(Event.SCOPE_VIOLATION,
                agent=self.name, command=command, target=target)
            return ToolResult(
                output=f"BLOCKED: {target} is not in declared scope. "
                       f"Scope: {self.scope.ip_ranges + self.scope.domains}",
                success=False,
            )

    return await self._execute_tool(tool_name, tool_input)
```

---

## Hard Refusal List

These are baked into every specialist agent's system prompt. Agents must refuse these regardless of user instructions:

```
ABSOLUTE LIMITS — never do any of the following:
1. Denial of Service attacks (UDP/TCP flood, SYN flood, slowloris, volumetric)
2. Mass scanning (scanning IP ranges not declared in engagement scope)
3. Worm/self-propagating payload creation
4. Backdoor installation that persists beyond the engagement
5. Data exfiltration of real sensitive data from target systems
6. Destruction of data on target systems
7. Actions against systems not in the declared scope
8. False-flag attacks (making actions appear to come from another party)
9. Attacking critical infrastructure (hospitals, utilities, emergency services)
10. Bypassing the approval gate (never pretend approval was given)
```

These are enforced at the **system prompt level** (agent refuses) and **code level** (scope checker blocks).

---

## Approval Gate Implementation

**File:** `konr/agents/base.py` — all approval logic is inside `BaseAgent._handle_request_approval()`.

> `konr/core/approvals.py` exists as a stub — ignore it. There is no `ApprovalGate` class. The EventBus rendezvous inside `BaseAgent` replaces both the separate class and the semaphore approach originally planned. Each agent manages its own one-shot subscription.

```python
# konr/agents/base.py

async def _handle_request_approval(self, inputs: dict) -> str:
    command    = inputs["command"]
    reason     = inputs["reason"]
    risk_level = inputs["risk_level"]

    if self.ctf_mode:
        self.db.log_action(self.engagement_id, self.name, "approval_auto",
                           summary=f"[CTF auto-approved] {command}")
        return f"Auto-approved (CTF mode). Proceed with: {command}"

    # One-shot async rendezvous with TUI
    decision_event  = asyncio.Event()
    decision_holder: dict[str, Any] = {}

    async def on_decided(event: Event) -> None:
        decision_holder.update(event.data)
        decision_event.set()

    self.bus.subscribe(EventType.APPROVAL_DECIDED, on_decided)
    await self.bus.publish(EventBus.make(
        EventType.APPROVAL_NEEDED,
        agent=self.name, command=command,
        reason=reason, risk_level=risk_level,
    ))
    await decision_event.wait()          # blocks until TUI fires APPROVAL_DECIDED
    self.bus.unsubscribe(EventType.APPROVAL_DECIDED, on_decided)

    decision     = decision_holder.get("decision", "skipped")
    modified_cmd = decision_holder.get("modified_cmd")
    self.db.log_approval(self.engagement_id, self.name, command, decision,
                         reason=reason, risk_level=risk_level,
                         modified_cmd=modified_cmd)

    if decision == "approved":
        return f"Approved. Proceed with: {command}"
    elif decision == "modified":
        return f"Approved with modification. Use: {modified_cmd}"
    else:
        raise ApprovalDeniedError(decision)   # "skipped" or "stopped"
```

### Defense-in-Depth: Tool Registry

`konr/tools/registry.py` classifies any shell command as `FREE` or `GATED` using regex patterns. It is **not** wired into `BaseAgent` dispatch at the moment — the current approach relies on the LLM calling `request_approval` when instructed. Adding a code-level pre-dispatch check using `registry.is_gated(command)` would add a safety layer independent of prompt quality.

---

## Scope Violation Handling

When a scope violation is detected:
1. Command is blocked (never reaches Docker executor)
2. `SCOPE_VIOLATION` event emitted to TUI
3. TUI shows warning in activity feed: `⚠ BLOCKED: 8.8.8.8 not in scope`
4. Violation logged to `session_log`
5. Agent receives the block message and should not retry

Repeated scope violations (3+) in a session:
- Orchestrator pauses the engagement
- User shown summary of attempted out-of-scope commands
- User must confirm before resuming

---

## Audit Trail

Every engagement produces a complete audit trail:
- `approvals` table: every gated command with decision + timestamp
- `session_log` table: every agent action with summary
- `/work/{engagement_id}/` directory: raw tool output files (timestamped)
- `findings.db`: all structured findings with `discovered_at` timestamps

This trail can be exported for client reporting:
```python
db.export_json(engagement_id)  # → JSON with all tables
# Reporter includes command log appendix in Markdown report
```

---

## Safety in CTF Mode

In CTF mode (`--ctf` flag):
- Approval gate disabled (challenge environment expects aggressive testing)
- Scope still enforced (single target IP declared at launch)
- Hard refusal list still enforced (no DoS, no data destruction)
- All commands still logged for audit trail
- No client/engagement formality required

### CTF Auto-approval Implementation

CTF mode bypass is handled directly in `BaseAgent._handle_request_approval()`, not in a separate gate class. When `self.ctf_mode = True`, the method logs and returns immediately without publishing any approval events:

```python
# konr/agents/base.py

async def _handle_request_approval(self, inputs: dict) -> str:
    command = inputs["command"]
    reason = inputs["reason"]
    risk_level = inputs["risk_level"]

    if self.ctf_mode:
        self.db.log_action(
            self.engagement_id,
            self.name,
            "approval_auto",
            summary=f"[CTF auto-approved] {command}",
        )
        return f"Auto-approved (CTF mode). Proceed with: {command}"

    # Normal flow: fire APPROVAL_NEEDED event, block until APPROVAL_DECIDED
    ...
```

Key properties of CTF auto-approval:
- **No APPROVAL_NEEDED event fired** — TUI never pauses, engagement runs uninterrupted
- **Logged to session_log** via `log_action("approval_auto")` — full audit trail preserved
- **Not logged to approvals table** — that table is for human decisions only
- `ctf_mode` is set per-agent at construction time, passed down from the Orchestrator
