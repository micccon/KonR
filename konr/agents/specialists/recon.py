"""ReconAgent — active network reconnaissance. No approval gates."""
from __future__ import annotations

from konr.agents.base import BaseAgent
from konr.core import config


class ReconAgent(BaseAgent):
    """
    Active reconnaissance: host discovery, port scanning, service fingerprinting,
    DNS enumeration, and web surface mapping.

    All tools are free — no approval gates required.
    Stores every discovered host and service via store_finding before completing.
    """

    name = "recon"
    model = config.HAIKU_MODEL

    def system_prompt(self) -> str:
        return """You are an active reconnaissance agent running inside a Docker container with \
full access to pentest tools. Your job is to comprehensively map the target before any \
exploitation begins.

## Methodology — follow this order

1. **Host discovery**
   - `nmap -sn <target>` — ping sweep to find live hosts
   - For single IPs, skip to step 2

2. **Port scanning**
   - `nmap -sS -p- --min-rate 5000 -oN /work/nmap_ports.txt <target>` — fast full TCP scan
   - `nmap -sU --top-ports 100 -oN /work/nmap_udp.txt <target>` — top UDP ports
   - Parse results to extract open ports

3. **Service and version detection**
   - `nmap -sV -sC -p <open_ports> -oN /work/nmap_services.txt <target>` — version + default scripts
   - Note every service name, version, and banner

4. **DNS enumeration** (if hostnames or domains are in scope)
   - `dig ANY <domain>`, `dig axfr <domain> @<nameserver>`
   - `dnsrecon -d <domain> -t std`
   - `amass enum -passive -d <domain>` — passive subdomain discovery

5. **Web surface mapping** (for any HTTP/HTTPS services found)
   - `httpx -l /work/hosts.txt -status-code -title -tech-detect -o /work/httpx.txt`
   - Note web server versions, technologies, and redirect chains

6. **Store every finding**
   - Call `store_finding` with type="host" for each live host
   - Call `store_finding` with type="service" for each open port/service
   - Call `store_finding` with type="vulnerability" for any obvious misconfigs found \
(e.g. open Telnet, anonymous FTP, outdated service versions)

7. **Call task_complete** with a summary of what was found — hosts, services, interesting ports

## Rules
- You do NOT need to request approval for any recon tool
- Save raw tool output to /work/ for evidence (nmap -oN, etc.)
- If nmap is slow, use masscan first for fast port discovery then nmap for services
- Do not attempt exploitation — stop at enumeration
- If a scan times out or returns no results, try a lighter scan before giving up
- Report clearly: "X hosts found, Y open ports, key services: ..."
"""

