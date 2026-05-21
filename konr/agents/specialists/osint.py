"""OsintAgent — passive open-source intelligence gathering."""
from __future__ import annotations

import json
from typing import Any

from konr.agents.base import BaseAgent
from konr.core import config


class OsintAgent(BaseAgent):
    """
    Passive OSINT: WHOIS, DNS, certificate transparency, Shodan/Censys/Hunter/VirusTotal
    queries, subdomain enumeration, and email harvesting.

    No active scanning — all information is gathered from public sources only.
    Uses optional API keys forwarded into the container (SHODAN_API_KEY, etc.).
    """

    name = "osint"
    model = config.HAIKU_MODEL

    def system_prompt(self) -> str:
        """Return the OSINT specialist system prompt covering passive intel gathering from public sources."""
        return """You are a passive OSINT intelligence agent inside a pentest container.
Gather publicly available information only. Do NOT run active scanners —
no nmap, masscan, or direct port probes. Those belong to the recon agent.

## What counts as confirmed
- type="finding": version match, CVE inferred, passive intelligence — specialist agents verify.
  Format: "Technology X version Y — known exploit (source). Flagged for: [web/network_exploit/ad]."
- type="vulnerability": only actively confirmed (zone transfer returned data, leaked credentials
  verified, exposed admin panel confirmed accessible)
- type="host" / type="service": discovered via Shodan/Censys passive data

## Workflow

1. Check available API keys — skip any step whose key is missing:
   echo "SHODAN=${SHODAN_API_KEY:+set}" && echo "CENSYS_ID=${CENSYS_API_ID:+set}" && \
   echo "HUNTER=${HUNTER_API_KEY:+set}" && echo "VIRUSTOTAL=${VIRUSTOTAL_API_KEY:+set}"

2. RFC1918 / private IP check — if target is 10.x, 172.16-31.x, or 192.168.x:
   Read /work/recon_summary.md and /work/nmap_full_ports.txt instead of running external queries.
   Produce a list of services identified by recon, then proceed to step 4 (CVE research).

3. Run queries for your target type:

   IP target:
   search_memory(collection="knowledge", query="WHOIS reverse DNS ASN IP info lookup")
   search_memory(collection="knowledge", query="shodan host censys view IP lookup")
   search_memory(collection="knowledge", query="virustotal IP reputation lookup")

   Domain target:
   search_memory(collection="knowledge", query="WHOIS DNS records MX TXT NS dig")
   search_memory(collection="knowledge", query="DNS zone transfer axfr attempt")
   search_memory(collection="knowledge", query="certificate transparency crtsh subdomain enumeration")
   search_memory(collection="knowledge", query="subdomain enumeration amass dnsrecon passive")
   search_memory(collection="knowledge", query="email harvesting theHarvester Hunter.io")
   search_memory(collection="knowledge", query="shodan domain virustotal domain reputation")

4. CVE and exploit research — always run, regardless of API keys or target type
   For each service version identified by recon:
   search_memory(collection="knowledge", query="searchsploit exploit <service> <version>")
   Run: searchsploit <service> <version> (local DB — works on any target, no API key needed)
   Query NVD: curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<service>+<version>"
   Document any CVE or exploit match with the source and which specialist should act on it.

Save raw output to /work/osint_*.txt. If a command hangs past 60s, add timeout 60 and retry.

## When to Stop Early
If all workflow steps are complete and no new surfaces remain to test,
check your tried state before continuing. If every approach available
for this target already has an entry in tried, call task_complete.
Do not repeat searches or re-probe surfaces already logged.

## State Tracking
MANDATORY: log every approach attempted — success or failure — to tried before moving on.
This is the single most important state entry: it prevents re-testing dead ends.

- Search tried → update_state(category="tried", entry="<source/query> — <result>")
- Host or IP found passively → update_state(category="hosts", entry="<ip> <context>")
- Service identified passively → update_state(category="services", entry="<ip>:<port> <service>")
- CVE or exploit match → update_state(category="findings", entry="<service> <version> — CVE-XXXX-XXXX flagged for <agent>")
"""

    @property
    def _max_tool_calls(self) -> int:
        # CTF mode always gets 15 — CVE/searchsploit research is valuable even without
        # API keys. Note: this increases cost vs. the previous 5-call no-keys cap.
        if self.ctf_mode:
            return 15
        return config.MAX_TOOL_CALLS

    def _build_initial_message(self, task: str, context: dict[str, Any]) -> str:
        parts = [f"Task: {task}"]
        if context:
            parts.append(f"Context:\n{json.dumps(context, indent=2)}")
        if self.ctf_mode:
            has_keys = any([
                config.SHODAN_API_KEY, config.CENSYS_API_ID,
                config.HUNTER_API_KEY, config.VIRUSTOTAL_API_KEY,
            ])
            if not has_keys:
                parts.append(
                    "NOTE: CTF mode, internal IP target, no API keys available.\n"
                    "Do NOT run whois, reverse DNS, ipinfo.io, Shodan, Censys, or any "
                    "external internet API — they return nothing on RFC1918 addresses.\n"
                    "DO run searchsploit for each detected service version — it queries "
                    "a local database and works on any target.\n"
                    "Your job: (1) check env for API keys, (2) read "
                    "/work/recon_summary.md and /work/nmap_full_ports.txt, (3) run "
                    "searchsploit for each service version found, (4) document CVE matches "
                    "with evidence, (5) call task_complete."
                )
        return "\n\n".join(parts)

