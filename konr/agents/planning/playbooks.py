"""Pre-built task plan templates for common engagement types."""
from __future__ import annotations

import re
from dataclasses import replace

from konr.agents.planning.generator import _PHASE_MAP, Task, TaskPlan


def _t(
    id: str,
    type: str,
    desc: str,
    depends_on: list[str] | None = None,
    priority: int = 5,
) -> Task:
    return Task(
        id=id,
        type=type,
        description=desc,
        target="{{target}}",
        depends_on=depends_on or [],
        priority=priority,
        phase=_PHASE_MAP[type],
    )


CTF = TaskPlan(engagement_id=0, mode="ctf", tasks=[
    _t("recon_1", "recon",           "Full port scan and service enumeration"),
    _t("osint_1", "osint",           "OSINT on target", ["recon_1"]),
    _t("web_1",   "web",             "Web application testing", ["recon_1"], priority=4),
    _t("net_1",   "network_exploit", "Network service exploitation",
       ["recon_1", "osint_1"], priority=3),
    _t("post_1",  "postexploit",     "Post-exploitation and flag capture",
       ["web_1", "net_1"], priority=2),
])

WEB_PENTEST = TaskPlan(engagement_id=0, mode="pentest", tasks=[
    _t("osint_1", "osint",       "Passive recon: subdomains, emails, tech fingerprint"),
    _t("recon_1", "recon",       "Active: port scan, service detection", ["osint_1"]),
    _t("web_1",   "web",         "Full web application audit: auth, OWASP Top 10, API",
       ["recon_1"], priority=3),
    _t("post_1",  "postexploit", "Post-exploitation if foothold obtained", ["web_1"], priority=2),
])

EXTERNAL_NETWORK = TaskPlan(engagement_id=0, mode="pentest", tasks=[
    _t("osint_1", "osint",           "External OSINT: ASN, certs, emails, Shodan"),
    _t("recon_1", "recon",           "Full external port scan", ["osint_1"]),
    _t("web_1",   "web",             "Web surface testing", ["recon_1"], priority=4),
    _t("net_1",   "network_exploit", "Network service exploitation",
       ["recon_1", "osint_1"], priority=3),
    _t("post_1",  "postexploit",     "Post-exploitation", ["web_1", "net_1"], priority=2),
])

AD_PENTEST = TaskPlan(engagement_id=0, mode="pentest", tasks=[
    _t("osint_1", "osint",           "OSINT: emails, subdomains, leaked credentials"),
    _t("recon_1", "recon",           "Internal scan: ports 88/389/445/3389", ["osint_1"]),
    _t("net_1",   "network_exploit", "Initial access via network services",
       ["recon_1"], priority=4),
    _t("ad_1",    "ad",              "AD enumeration, Kerberoasting, lateral movement",
       ["recon_1"], priority=3),
    _t("post_1",  "postexploit",     "Post-exploitation: DA, DCSync, persistence",
       ["ad_1", "net_1"], priority=2),
])

FULL_PENTEST = TaskPlan(engagement_id=0, mode="pentest", tasks=[
    _t("osint_1", "osint",           "Passive OSINT: all public sources"),
    _t("recon_1", "recon",           "Full scan: ports, services, versions", ["osint_1"]),
    _t("web_1",   "web",             "Web application audit", ["recon_1"], priority=4),
    _t("net_1",   "network_exploit", "Network exploitation", ["recon_1", "osint_1"], priority=4),
    _t("ad_1",    "ad",              "Active Directory testing", ["recon_1"], priority=4),
    _t("post_1",  "postexploit",     "Post-exploitation", ["web_1", "net_1", "ad_1"], priority=2),
])


def select_playbook(mode: str, target_scope: str) -> TaskPlan | None:
    """Return a playbook template or None to fall back to LLM generation.

    Heuristics for pentest mode:
    - AD keywords in scope string → AD_PENTEST
    - Bare IP or CIDR (no domain name) → EXTERNAL_NETWORK
    - Otherwise (hostname/domain) → WEB_PENTEST
    """
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$", target_scope.strip()))
    if mode == "ctf":
        return CTF
    if mode == "pentest":
        low = target_scope.lower()
        if any(k in low for k in ("domain", "ad", "corp", "internal", "dc")):
            return AD_PENTEST
        if is_ip:
            return EXTERNAL_NETWORK
        return WEB_PENTEST
    return None


def apply_target(plan: TaskPlan, engagement_id: int, target: str, mode: str) -> TaskPlan:
    """Clone a playbook template with the real target substituted and engagement metadata set."""
    tasks = [replace(t, target=target) for t in plan.tasks]
    return replace(plan, engagement_id=engagement_id, tasks=tasks, mode=mode)
