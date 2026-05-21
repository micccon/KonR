"""Claude tool_use schemas for all agent tools."""
from __future__ import annotations

from typing import Any

# ── Individual tool schemas ───────────────────────────────────────────────────

EXECUTE_COMMAND: dict[str, Any] = {
    "name": "execute_command",
    "description": (
        "Run a shell command inside the pentest container. "
        "stdout and stderr are merged. Output over 8KB is automatically truncated. "
        "Always check exit_code in the response."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute (runs under bash -c)",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds before the command is killed (default 300)",
                "default": 300,
            },
        },
        "required": ["command"],
    },
}

READ_FILE: dict[str, Any] = {
    "name": "read_file",
    "description": "Read a file from inside the container (e.g. /work/nmap_output.xml).",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absolute path inside the container",
            },
        },
        "required": ["path"],
    },
}

WRITE_FILE: dict[str, Any] = {
    "name": "write_file",
    "description": "Write a file inside the container (e.g. custom exploit scripts, wordlists).",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absolute path inside the container",
            },
            "content": {
                "type": "string",
                "description": "Content to write",
            },
        },
        "required": ["path", "content"],
    },
}

STORE_FINDING: dict[str, Any] = {
    "name": "store_finding",
    "description": (
        "Persist a discovered finding to the engagement database. "
        "Call this every time you discover a host, service, vulnerability, credential, "
        "attack chain, or flag."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "type": {
                "type": "string",
                "enum": ["host", "service", "vulnerability", "finding", "credential", "attack_chain", "flag"],
                "description": "Category of finding",
            },
            "data": {
                "type": "object",
                "description": (
                    "Fields vary by type:\n"
                    "host: ip (required), hostname, os, os_version, role\n"
                    "service: ip (required), port (required), protocol, service_name, version,"
                    " banner\n"
                    "vulnerability: title (required), severity (required:"
                    " critical/high/medium/low/info), "
                    "ip, port, cvss, cve, description, evidence, reproduction, remediation,"
                    " mitre_id\n"
                    "finding: title (required), description (required), ip — use for intelligence"
                    " leads: passive research, version-based CVE hits, searchsploit matches that"
                    " have NOT been actively verified. These appear as Unverified Leads in the"
                    " report, not as confirmed vulnerabilities.\n"
                    "credential: username, secret, secret_type, domain, access_level, source_tool, "
                    "validity (valid/invalid/unknown), ip\n"
                    "attack_chain: title (required), steps (required: list of step objects), "
                    "severity (required), mitre_techniques\n"
                    "flag: value (required), flag_type (user/root/other), context"
                ),
            },
        },
        "required": ["type", "data"],
    },
}

REQUEST_APPROVAL: dict[str, Any] = {
    "name": "request_approval",
    "description": (
        "Request human approval before running a dangerous command. "
        "REQUIRED before: sqlmap, metasploit, impacket attacks, crackmapexec auth attacks, "
        "evil-winrm, psexec, any privesc exploit, persistence, or lateral movement. "
        "The user will see the command and your reasoning before deciding."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The exact command you intend to run after approval",
            },
            "reason": {
                "type": "string",
                "description": "Why this command is needed and what you expect it to reveal",
            },
            "risk_level": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Potential impact if this command causes unintended effects",
            },
        },
        "required": ["command", "reason", "risk_level"],
    },
}

SEARCH_MEMORY: dict[str, Any] = {
    "name": "search_memory",
    "description": (
        "Semantic search over past tool outputs and known techniques stored in vector memory. "
        "Use this to recall what worked against similar targets or to look up CVE details."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Natural language query (e.g. 'SMB exploits Windows Server 2019')",
            },
            "collection": {
                "type": "string",
                "enum": ["tool_outputs", "techniques", "osint_data", "knowledge"],
                "description": "Which collection to search (default: tool_outputs)",
                "default": "tool_outputs",
            },
            "n_results": {
                "type": "integer",
                "description": "Number of results to return (default 3)",
                "default": 3,
            },
        },
        "required": ["query"],
    },
}

DELEGATE_TO_CODER: dict[str, Any] = {
    "name": "delegate_to_coder",
    "description": (
        "Delegate a coding task to the CoderAgent. Use when you need a custom exploit, "
        "payload, or script that no existing tool provides. Returns the file path of the "
        "written artifact and a summary of what was created."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "task": {
                "type": "string",
                "description": (
                    "What to write and why (be specific about the vulnerability and target)"
                ),
            },
            "context": {
                "type": "string",
                "description": "Relevant target info: service name/version, CVE, constraints, OS",
            },
            "language": {
                "type": "string",
                "enum": ["python", "c", "go", "bash"],
                "description": "Language to write in (default: python)",
                "default": "python",
            },
        },
        "required": ["task", "context"],
    },
}

UPDATE_STATE: dict[str, Any] = {
    "name": "update_state",
    "description": (
        "Record a key discovery to your persistent state. "
        "Call this after every confirmed finding, identified service, working credential, "
        "or important observation. State persists across the entire run even when old "
        "messages are trimmed from context."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "enum": ["hosts", "services", "credentials", "vulnerabilities", "findings", "tried"],
                "description": (
                    "hosts: live hosts found. "
                    "services: open ports/services identified. "
                    "credentials: working username/password/session. "
                    "vulnerabilities: actively confirmed issues. "
                    "findings: unverified leads, CVE matches, candidates. "
                    "tried: approaches attempted (success or failure) — prevents re-testing."
                ),
            },
            "entry": {
                "type": "string",
                "description": (
                    "Concise one-line description. Examples: "
                    "'172.17.0.2:8000 HTTP Flask login page, Werkzeug 3.1.8' | "
                    "'admin:admin123 works on /login via SQLi' | "
                    "'SQLi auth bypass on /login — CRITICAL confirmed' | "
                    "'tried UDS SecurityAccess key derivation XOR/NOT/seed+1 — all failed'"
                ),
            },
        },
        "required": ["category", "entry"],
    },
}

TASK_COMPLETE: dict[str, Any] = {
    "name": "task_complete",
    "description": (
        "Signal that your assigned task is fully complete. "
        "Call this when you have nothing more to do — not when you are stuck."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "What was accomplished and key findings",
            },
            "findings_count": {
                "type": "integer",
                "description": "How many findings were stored via store_finding",
                "default": 0,
            },
        },
        "required": ["summary"],
    },
    "cache_control": {"type": "ephemeral"},
}

# ── Tool sets ─────────────────────────────────────────────────────────────────

SPECIALIST_TOOLS: list[dict[str, Any]] = [
    EXECUTE_COMMAND,
    READ_FILE,
    WRITE_FILE,
    REQUEST_APPROVAL,
    SEARCH_MEMORY,
    DELEGATE_TO_CODER,
    UPDATE_STATE,
    TASK_COMPLETE,
]

VERIFIER_TOOLS: list[dict[str, Any]] = [
    STORE_FINDING,
    TASK_COMPLETE,
]

