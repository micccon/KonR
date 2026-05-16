# Storage Design

## Overview

Two storage layers:
1. **SQLite** (`findings.db`) — structured findings, engagement data, credentials, approval logs
2. **ChromaDB** (`memory/`) — vector embeddings for semantic memory across sessions

Both stored on the host, not inside the Docker container.

---

## SQLite — findings.db

**File:** `konr/storage/db.py`
**Schema:** schema is applied inline via `_init_schema()` at `__init__` time (no separate `.sql` file)

### Full Schema

```sql
-- Core engagement tracking
CREATE TABLE IF NOT EXISTS engagements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    client      TEXT,
    mode        TEXT NOT NULL DEFAULT 'pentest',  -- 'pentest' | 'ctf'
    target_scope TEXT NOT NULL,                    -- JSON: ["10.0.1.0/24", "acme.com"]
    objectives  TEXT,                              -- engagement objectives / notes
    status      TEXT NOT NULL DEFAULT 'active',   -- active | paused | complete
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Discovered hosts
CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    ip            TEXT NOT NULL,
    hostname      TEXT,
    os            TEXT,
    os_version    TEXT,
    role          TEXT,     -- dc | web | db | workstation | unknown
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, ip)
);

-- Services on hosts
CREATE TABLE IF NOT EXISTS services (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES hosts(id),
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    service_name  TEXT,
    version       TEXT,
    banner        TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);

-- Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    host_id       INTEGER REFERENCES hosts(id),
    service_id    INTEGER REFERENCES services(id),
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,  -- critical | high | medium | low | info
    cvss          REAL,
    cve           TEXT,
    description   TEXT,
    evidence      TEXT,           -- snippet of tool output proving the vuln
    evidence_file TEXT,           -- path to full tool output in /work
    reproduction  TEXT,           -- steps to reproduce
    remediation   TEXT,
    status        TEXT DEFAULT 'confirmed',  -- confirmed | false_positive | needs_review
    agent         TEXT,           -- which agent found it
    mitre_id      TEXT,           -- ATT&CK technique ID if applicable
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Discovered credentials
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    host_id       INTEGER REFERENCES hosts(id),
    username      TEXT,
    secret        TEXT,           -- password, hash, or token (stored as-is)
    secret_type   TEXT,           -- password | ntlm | kerberos | token | key
    domain        TEXT,
    access_level  TEXT,           -- local_admin | domain_user | domain_admin | service
    source_tool   TEXT,
    validity      TEXT DEFAULT 'unknown',  -- valid | invalid | unknown
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Attack chains (multi-step compromise paths)
CREATE TABLE IF NOT EXISTS attack_chains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    title         TEXT NOT NULL,
    steps         TEXT NOT NULL,  -- JSON array of step descriptions
    severity      TEXT NOT NULL,
    status        TEXT DEFAULT 'identified',  -- identified | attempted | succeeded | failed
    mitre_techniques TEXT,        -- JSON array of ATT&CK IDs
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Human approval decisions (audit trail)
CREATE TABLE IF NOT EXISTS approvals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    agent         TEXT NOT NULL,
    command       TEXT NOT NULL,
    reason        TEXT,
    risk_level    TEXT,           -- low | medium | high | critical
    decision      TEXT NOT NULL,  -- approved | skipped | modified | stopped
    modified_cmd  TEXT,           -- if decision = 'modified', the user's version
    user_note     TEXT,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- CTF flags (CTF mode only)
CREATE TABLE IF NOT EXISTS flags (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    flag_value    TEXT NOT NULL,
    flag_type     TEXT,           -- user | root | htb | thm
    context       TEXT,           -- what the agent was doing when found
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Full session audit log
CREATE TABLE IF NOT EXISTS session_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
    agent         TEXT NOT NULL,
    action        TEXT NOT NULL,  -- brief action description
    summary       TEXT,           -- longer summary
    evidence_file TEXT            -- path in /work if applicable
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_engagement ON vulnerabilities(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_log_engagement ON session_log(engagement_id);
```

---

### Database Interface

```python
# pentest_ai/storage/db.py

class FindingsDB:
    def __init__(self, db_path: str = "./work/findings.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    # Engagement management
    def create_engagement(self, name, client, mode, target_scope, objectives) -> int: ...
    def get_engagement(self, engagement_id) -> dict: ...
    def update_engagement_status(self, engagement_id, status): ...

    # Host/service tracking
    def upsert_host(self, engagement_id, ip, hostname=None, os=None, role=None) -> int: ...
    def upsert_service(self, host_id, port, protocol, service_name=None, version=None) -> int: ...

    # Findings
    def add_vulnerability(self, engagement_id, host_id, title, severity, **kwargs) -> int: ...
    def add_credential(self, engagement_id, host_id, username, secret, **kwargs) -> int: ...
    def add_attack_chain(self, engagement_id, title, steps, severity) -> int: ...

    # Approval logging
    def log_approval(self, engagement_id, agent, command, reason, risk_level, decision, **kwargs): ...

    # CTF
    def add_flag(self, engagement_id, flag_value, flag_type, context): ...

    # Session log
    def log_action(self, engagement_id, agent, action, summary=None, evidence_file=None): ...

    # Reporting queries
    def get_findings_for_report(self, engagement_id) -> dict: ...
    # Returns: {hosts, services, vulns_by_severity, credentials, attack_chains, approvals}

    # Export
    def export_json(self, engagement_id) -> str: ...
```

### store_finding Tool Implementation

The `store_finding` tool (called by agents via Claude tool_use) maps to these DB methods:

```python
async def handle_store_finding(self, tool_input: dict) -> str:
    finding_type = tool_input["type"]
    data = tool_input["data"]

    if finding_type == "host":
        host_id = self.db.upsert_host(self.engagement_id, **data)
        return f"Host stored: id={host_id}"

    elif finding_type == "service":
        svc_id = self.db.upsert_service(**data)
        return f"Service stored: id={svc_id}"

    elif finding_type == "vulnerability":
        vuln_id = self.db.add_vulnerability(self.engagement_id, **data)
        return f"Vulnerability stored: id={vuln_id}"

    elif finding_type == "credential":
        cred_id = self.db.add_credential(self.engagement_id, **data)
        return f"Credential stored: id={cred_id}"

    elif finding_type == "attack_chain":
        chain_id = self.db.add_attack_chain(self.engagement_id, **data)
        return f"Attack chain stored: id={chain_id}"

    elif finding_type == "flag":  # CTF mode
        self.db.add_flag(self.engagement_id, **data)
        await self.event_bus.emit(Event.FLAG_FOUND, flag=data["flag_value"])
        return f"Flag stored: {data['flag_value']}"
```

---

## ChromaDB — Vector Memory

**File:** `konr/storage/memory.py`

Used to give agents semantic recall across sessions: "What techniques worked against Apache Tomcat 9.x before?"

### Collections

| Collection | Content | Auto-populated |
|-----------|---------|----------------|
| `tool_outputs` | Raw command output + metadata | Every `execute_command` call |
| `techniques` | Successful attack technique descriptions | When `store_finding(type="vulnerability")` |
| `osint_data` | theHarvester, Shodan, Recon-ng, WHOIS results | OSINTAgent tool outputs |
| `code_artifacts` | Custom exploits, payloads, scripts written by CoderAgent | CoderAgent `write_file` calls |
| `knowledge` | **Pre-seeded at install**: MITRE ATT&CK techniques, CWE Top 25, exploitation guides | `scripts/seed_knowledge.py` |

### Knowledge Base Pre-seeding

`scripts/seed_knowledge.py` — run once during install:

```python
"""
Seeds ChromaDB knowledge collection with structured security knowledge.
Agents can query this instead of relying solely on model training data.
"""
KNOWLEDGE_SOURCES = [
    # MITRE ATT&CK Enterprise techniques (fetched from MITRE TAXII)
    {"source": "mitre_attack", "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"},
    # CWE Top 25 (fetched from MITRE)
    {"source": "cwe_top25", "url": "https://cwe.mitre.org/data/json/cwec_latest.json.zip"},
    # Common exploitation guides (local markdown files bundled with the tool)
    {"source": "local_guides", "path": "knowledge/"},
]

def seed():
    memory = VectorMemory()
    for source in KNOWLEDGE_SOURCES:
        docs = fetch_and_parse(source)
        for doc in docs:
            memory.store(
                collection="knowledge",
                content=doc["content"],
                metadata={"source": source["source"], "id": doc["id"], "name": doc["name"]},
                doc_id=f"{source['source']}_{doc['id']}",  # idempotent
            )
    print(f"Seeded {len(docs)} knowledge entries")
```

Bundled local guides in `knowledge/` directory:
- `privilege_escalation_linux.md` — SUID, sudo, cron, kernel exploits
- `privilege_escalation_windows.md` — token impersonation, service abuse, UAC bypass
- `ad_attack_techniques.md` — Kerberoasting, AS-REP, DCSync, delegation abuse
- `web_exploitation_checklist.md` — OWASP Top 10 testing methodology
- `network_service_exploits.md` — Common CVEs by service (SMB, RDP, SSH, HTTP)

### Metadata Schema

Every document stored with:
```python
metadata = {
    "engagement_id": str,
    "agent": str,           # recon | web | ad | postexploit
    "tool": str,            # nmap | sqlmap | etc.
    "target": str,          # IP or hostname
    "timestamp": str,       # ISO format
    "success": bool,        # did this technique work?
}
```

### Interface

```python
class VectorMemory:
    def __init__(self, persist_dir: str = "./work/memory"):
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collections = {
            "tool_outputs": self.client.get_or_create_collection("tool_outputs"),
            "techniques": self.client.get_or_create_collection("techniques"),
            "osint_data": self.client.get_or_create_collection("osint_data"),
            "knowledge": self.client.get_or_create_collection("knowledge"),
        }

    def store(self, collection: str, content: str, metadata: dict, doc_id: str = None):
        """Store a document. Auto-generates ID if not provided."""
        if len(content) > 16_000:
            content = self._summarize(content)  # Claude Haiku summarization

        self.collections[collection].add(
            documents=[content],
            metadatas=[metadata],
            ids=[doc_id or str(uuid4())],
        )

    def search(self, collection: str, query: str, n_results: int = 3) -> list[dict]:
        """Semantic search. Returns list of {content, metadata, distance}."""
        results = self.collections[collection].query(
            query_texts=[query],
            n_results=n_results,
        )
        return [
            {"content": doc, "metadata": meta, "distance": dist}
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
            if dist < 0.8  # similarity threshold — discard poor matches
        ]
```

### search_memory Tool Implementation

> **Gap:** There is no `search_memory` entry in `konr/tools/definitions.py` / `SPECIALIST_TOOLS`. `VectorMemory` is fully implemented but agents cannot call it — the tool definition must be added. See `konr/tools/definitions.py`.



```python
async def handle_search_memory(self, tool_input: dict) -> str:
    results = self.memory.search(
        collection=tool_input.get("collection", "tool_outputs"),
        query=tool_input["query"],
        n_results=tool_input.get("n_results", 3),
    )
    if not results:
        return "No relevant memory found."

    formatted = []
    for r in results:
        formatted.append(
            f"[{r['metadata']['tool']} on {r['metadata']['target']} "
            f"at {r['metadata']['timestamp']}]\n{r['content'][:500]}..."
        )
    return "\n\n---\n\n".join(formatted)
```

### Auto-storage of Tool Outputs

Every `execute_command` result is automatically stored in `tool_outputs`:

```python
# In executor.py, after command completes:
await self.memory.store(
    collection="tool_outputs",
    content=result.output,
    metadata={
        "engagement_id": self.engagement_id,
        "agent": self.current_agent,
        "tool": command.split()[0],
        "target": self._extract_target(command),
        "timestamp": datetime.now().isoformat(),
        "success": result.success,
    }
)
```

### Content Summarization for Large Outputs

When tool output exceeds 16KB, it's summarized before storing:

```python
def _summarize(self, content: str) -> str:
    """Use Claude Haiku to compress large tool outputs for vector storage."""
    response = anthropic.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": f"Summarize this security tool output, preserving all findings, "
                       f"IP addresses, ports, services, and vulnerabilities:\n\n{content[:32000]}"
        }]
    )
    return response.content[0].text
```

---

## File Layout on Disk

```
./work/
├── findings.db          # SQLite — all structured findings
├── memory/              # ChromaDB persistent storage
│   ├── tool_outputs/
│   ├── techniques/
│   ├── osint_data/
│   └── knowledge/
├── {engagement_id}/     # Raw tool output artifacts
│   ├── recon/
│   ├── web/
│   ├── ad/
│   └── postexploit/
└── reports/
    └── *.md
```

---

## Data Flow Example

1. ReconAgent calls `execute_command("nmap -sV 10.0.1.5")`
2. Output streams to TUI, saved to `/work/abc123/recon/nmap_20260508_120000.txt`
3. Output auto-stored in ChromaDB `tool_outputs` collection
4. Agent calls `store_finding(type="host", data={ip: "10.0.1.5", hostname: "dc01", ...})`
5. Agent calls `store_finding(type="service", data={host_id: 1, port: 445, service: "smb", ...})`
6. Later, WebAgent calls `search_memory(query="SMB vulnerabilities on Windows Server")` → retrieves relevant past nmap output
7. Reporter calls `db.get_findings_for_report(engagement_id)` → queries all tables → renders Markdown
