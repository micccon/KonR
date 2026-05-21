"""VerifierAgent — stores findings from specialist summary files."""
from __future__ import annotations

from typing import Any

from konr.agents.base import BaseAgent
from konr.agents.definitions import VERIFIER_TOOLS
from konr.core import config

_VERIFIER_PROMPT = """You are a findings storage agent. Specialist agent {agent_name} has \
completed its run and written a summary of what it found.

The summary is in your context under "Specialist Summary". Read it carefully.

Your only task: store every confirmed finding from the summary to the database, then call task_complete.

---

WHAT TO STORE

HOSTS
For each live host mentioned:
  store_finding(type="host", data={{ip, hostname, os, ...}})

SERVICES
For each open port/service:
  store_finding(type="service", data={{ip, port, protocol, service_name, version, banner}})

INTELLIGENCE LEADS
For each version string, CVE match, or unverified candidate with evidence:
  store_finding(type="finding", data={{title, description, ip}})

VULNERABILITIES
For each issue the summary shows was actively confirmed:
  store_finding(type="vulnerability", data={{
    title, severity (critical/high/medium/low/info),
    ip, port, description, evidence, reproduction, remediation
  }})

  Evidence MUST show BOTH:
  (1) the exact command that ran
  (2) output confirming exploitation — extracted data, shell access,
      confirmed bypass, or confirmed access to protected content

  A version string, error response, timeout, or searchsploit match alone
  is NOT sufficient. If the summary evidence does not meet this bar,
  store as type="finding" instead of type="vulnerability".

CREDENTIALS
For each working username/password or session token:
  store_finding(type="credential", data={{username, secret, access_level, ip, source_tool}})

FLAGS
For each value listed under the summary's "## Flags captured" section:
  store_finding(type="flag", data={{value, flag_type, context}})

ATTACK CHAINS
If the summary documents a multi-step exploitation path with evidence for each step:
  store_finding(type="attack_chain", data={{title, severity, steps: [...]}})

---

De-duplication: call store_finding freely — the database returns "Already stored (id=N)" on \
duplicates. No need to check first.

After storing all findings, call task_complete with a one-sentence summary of what was stored.
Do not run commands. Do not read files. Read the summary, store findings, complete.
"""


class VerifierAgent(BaseAgent):
    """
    Runs after each specialist to store all findings and write the agent's summary file.
    Single point of storage — reads the full conversation history and stores everything.
    Uses Haiku — no execution, no approval gates, restricted tool set.
    """

    model = config.HAIKU_MODEL

    def __init__(self, *args: object, specialist_name: str = "agent", **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.name = "verifier"
        self._specialist_name = specialist_name

    @property
    def _max_tool_calls(self) -> int:
        return config.MAX_TOOL_CALLS_VERIFIER

    def system_prompt(self) -> str:
        return _VERIFIER_PROMPT.format(agent_name=self._specialist_name)

    def tools(self) -> list[dict]:
        return VERIFIER_TOOLS

    async def _dispatch(self, name: str, inputs: dict[str, Any]) -> Any:
        if name == "store_finding":
            return await self._handle_store_finding(inputs)
        return await super()._dispatch(name, inputs)
