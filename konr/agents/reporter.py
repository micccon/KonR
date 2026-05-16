"""Reporter — single LLM call that reads the DB and writes a Markdown report."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from konr.agents.llm_agent import SingleCallLLMAgent
from konr.core import config
from konr.storage.db import FindingsDB

_PENTEST_SYSTEM = """You are a professional penetration test report writer. \
Given structured engagement findings, produce a complete Markdown report.

Follow this structure exactly:
1. Cover (client, engagement name, date, classification)
2. Executive Summary (severity table, key findings bullets)
3. Scope & Methodology
4. Detailed Findings — one section per vulnerability, ordered critical→low
5. Attack Chains (if any)
6. Discovered Credentials table (usernames only — no plaintext passwords)
7. Appendix A — Approved Commands Log
8. Appendix B — Tools Used

Be professional and precise. Include all findings from the data — do not omit any."""

_CTF_SYSTEM = """You are writing a CTF machine walkthrough document. \
Given structured engagement findings, produce a complete Markdown walkthrough.

Follow this structure:
1. Title (machine name, date, difficulty if known)
2. Summary (flags captured, attack path overview)
3. Flag table (flag values, where found, timestamp)
4. Step-by-step attack path:
   - Reconnaissance
   - Initial Access / Foothold
   - Privilege Escalation
   - Post-Exploitation
5. Key commands used
6. Tools used

Write for a technical audience. Include exact commands and output snippets where available."""


class Reporter(SingleCallLLMAgent):
    """Single-call LLM reporter. Not a BaseAgent — no tool loop."""

    def __init__(self, db: FindingsDB) -> None:
        super().__init__(model=config.HAIKU_MODEL, system_prompt=_PENTEST_SYSTEM)
        self._db = db

    async def generate(self, engagement_id: int) -> str:
        """Generate a Markdown report and write it to disk. Returns the file path."""
        engagement = self._db.get_engagement(engagement_id)
        if engagement is None:
            raise ValueError(f"Engagement {engagement_id} not found")

        findings = self._db.get_findings_for_report(engagement_id)
        mode = engagement.get("mode", "pentest")
        system_prompt = _CTF_SYSTEM if mode == "ctf" else _PENTEST_SYSTEM
        system: list[dict[str, Any]] = [
            {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
        ]
        user_message = _build_user_message(findings, mode)
        report_text = await self._call(user_message, max_tokens=8096, system=system)
        return _write_report(engagement, report_text)


def _build_user_message(findings: dict, mode: str) -> str:
    engagement = findings.get("engagement") or {}
    stats = findings.get("stats") or {}

    parts = [
        f"Mode: {mode}",
        f"\nENGAGEMENT:\n{json.dumps(engagement, indent=2, default=str)}",
        f"\nSTATS:\n{json.dumps(stats, indent=2)}",
        f"\nHOSTS:\n{json.dumps(findings.get('hosts', []), indent=2, default=str)}",
        "\nVULNERABILITIES:\n"
        + json.dumps(findings.get("vulnerabilities", []), indent=2, default=str),
        "\nATTACK CHAINS:\n"
        + json.dumps(findings.get("attack_chains", []), indent=2, default=str),
        f"\nFLAGS:\n{json.dumps(findings.get('flags', []), indent=2, default=str)}",
        "\nCREDENTIALS (usernames only — omit plaintext secrets from report):\n"
        + json.dumps(
            [
                {k: v for k, v in c.items() if k != "secret"}
                for c in findings.get("credentials", [])
            ],
            indent=2,
            default=str,
        ),
        "\nAPPROVED COMMANDS LOG:\n"
        + json.dumps(findings.get("approvals", []), indent=2, default=str),
        "\nGenerate the complete report now.",
    ]
    return "\n".join(parts)


def _write_report(engagement: dict, content: str) -> str:
    name = engagement.get("name") or "engagement"
    safe_name = re.sub(r"[^\w-]", "_", name).lower().strip("_")
    date = datetime.now().strftime("%Y-%m-%d")
    filename = f"{safe_name}_{date}.md"

    reports_dir = config.WORK_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    path = reports_dir / filename
    path.write_text(content, encoding="utf-8")
    return str(path)
