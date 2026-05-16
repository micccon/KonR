# KonR

Hierarchical multi-agent AI penetration testing system powered by Claude.

KonR orchestrates a team of specialized AI agents — each running inside a Docker container with a full pentest toolset — to autonomously discover, exploit, and report on vulnerabilities.

```
  ██╗  ██╗ ██████╗ ███╗   ██╗██████╗
  ██║ ██╔╝██╔═══██╗████╗  ██║██╔══██╗
  █████╔╝ ██║   ██║██╔██╗ ██║██████╔╝
  ██╔═██╗ ██║   ██║██║╚██╗██║██╔══██╗
  ██║  ██╗╚██████╔╝██║ ╚████║██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

## How it works

1. **Plan** — a planner LLM generates a phased task graph from your target and objectives
2. **Execute** — specialist agents run in parallel across phases, sharing findings via a vector memory store
3. **Report** — a reporter agent synthesizes all findings into a structured pentest report

### Agent roster

| Agent | Role |
|---|---|
| `osint` | Passive recon: WHOIS, DNS, cert transparency, Shodan/Censys |
| `recon` | Active scanning: nmap, service fingerprinting |
| `web` | Web application testing: OWASP Top 10, auth, API |
| `network_exploit` | CVE research and network service exploitation |
| `ad` | Active Directory: enumeration, Kerberoasting, lateral movement |
| `postexploit` | Privilege escalation, credential hunting, flag capture |

## Requirements

- Python 3.12+
- Docker
- An Anthropic API key

## Setup

**1. Clone and install**

```bash
git clone https://github.com/yourusername/konr.git
cd konr
./install.sh
```

The script installs [uv](https://github.com/astral-sh/uv) if needed, creates a virtualenv, and installs all dependencies.

**2. Activate the environment**

```bash
source .venv/bin/activate
```

> The install script cannot activate the environment for you — shell activation always has to be run manually in your current terminal session. You'll need to repeat this step each time you open a new terminal.

**3. Configure API keys**

The install script creates `.env` from `.env.example` automatically. Open it and add your keys:

```
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Optional — OSINT agent degrades gracefully without these
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
HUNTER_API_KEY=
VIRUSTOTAL_API_KEY=
```

**4. Build the Docker container**

```bash
make docker-build
```

This builds the pentest image with nmap, ffuf, sqlmap, nuclei, and the full SecLists wordlist collection pre-installed.

**5. (Optional) Seed the knowledge base**

```bash
make seed-knowledge
```

Populates ChromaDB with pentest reference data (GTFOBins, common CVEs, technique descriptions) that agents can query via `search_memory`.

**6. Verify**

```bash
konr --help
```

## Modes

| Mode | Flag | Behaviour |
|---|---|---|
| **CTF** | `--ctf` | Fully autonomous — all tool calls auto-approved, flag detection enabled (`HTB{...}`, `THM{...}` etc.) |
| **Pentest** | _(default)_ | Approval gates on risky actions (sqlmap, msfconsole, brute force). You confirm before anything destructive runs. |

> Docker must be running before launching an engagement. KonR spawns and manages the pentest container automatically.

## Usage

```bash
# CTF — fully autonomous, flag detection enabled
konr --target 10.10.11.22 --ctf --engagement "HTB Box"

# CTF with VPN
konr --target 10.10.11.22 --ctf --vpn ~/lab.ovpn --engagement "HTB Box"

# Pentest — approval gates on risky actions
konr --target example.com --engagement "Client Pentest"

# With a specific goal
konr --target 10.0.0.0/24 --goal "obtain domain admin" --engagement "Internal"

# Write an activity log
konr --target 10.10.11.22 --ctf --log

# Cap spend
konr --target 10.10.11.22 --ctf --max-cost 5.00
```

## TUI controls

| Key | Action |
|---|---|
| `^\\` | Pause / Resume |
| `^X` | Skip current agent |
| `^C` | Quit |
| `v` | Toggle verbose output |
| `f` | Cycle event filter |

## Output

All engagement output lands in `work/` (gitignored):

- `work/findings.db` — SQLite database of all findings
- `work/reports/` — generated pentest reports (Markdown)
- `work/logs/` — activity logs (if `--log` is set)

## Disclaimer

For authorized security testing only. Never use against systems you don't own or have explicit written permission to test.
