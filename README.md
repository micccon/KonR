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

## Installation

```bash
git clone https://github.com/yourusername/konr.git
cd konr
./install.sh
```

The install script creates a virtualenv, installs dependencies, builds the Docker image, and drops a `.env` template.

Add your API key to `.env`:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Optional API keys (used by the OSINT agent if present):

```
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
HUNTER_API_KEY=
VIRUSTOTAL_API_KEY=
```

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
