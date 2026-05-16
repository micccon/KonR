"""ToolHandlerMixin — tool dispatch handlers for BaseAgent."""
from __future__ import annotations

import asyncio
from typing import Any

from konr.agents.utils import extract_text
from konr.core import config
from konr.core.errors import ApprovalDeniedError
from konr.core.events import EventBus, EventType


class ToolHandlerMixin:
    """All _handle_* tool implementations. Mixed into BaseAgent."""

    async def _store_to_memory(self, content: str, metadata: dict[str, Any]) -> None:
        """Write a finding summary to VectorMemory so parallel agents can find it."""
        if self._memory is None:
            return
        try:
            await asyncio.to_thread(
                self._memory.store,
                "tool_outputs",
                content,
                {"agent": self.name, "engagement_id": str(self.engagement_id), **metadata},
            )
        except Exception:
            pass

    async def _handle_execute_command(self, inputs: dict[str, Any]) -> str:
        """Run a shell command in the container, check scope, auto-capture flags, and summarize if output is large."""
        if self.executor is None:
            return "Error: no container executor available for this agent"
        command = inputs["command"]
        timeout = int(inputs.get("timeout", 300))

        if self.scope is not None:
            target = self.scope.extract_target_from_command(command)
            if target and not self.scope.is_in_scope(target):
                await self.bus.publish(EventBus.make(
                    EventType.SCOPE_VIOLATION, agent=self.name,
                    command=command, target=target,
                ))
                return (
                    f"BLOCKED: '{target}' is outside declared scope. "
                    "Only act against in-scope targets."
                )

        result = await asyncio.to_thread(
            self.executor.run, command, timeout=timeout, ctf_mode=self.ctf_mode
        )

        if result.flags_found:
            for flag in result.flags_found:
                await asyncio.to_thread(
                    self.db.add_flag,
                    self.engagement_id,
                    flag_value=flag,
                    context=f"Detected in output of: {command}",
                )
                self._findings_count += 1
                await self.bus.publish(
                    EventBus.make(EventType.FLAG_FOUND, agent=self.name, value=flag)
                )

        output = result.output
        if result.truncated:
            output = await self._haiku_summarize(output, command)

        suffix = " [summarized]" if result.truncated else ""
        return f"[exit {result.exit_code}]{suffix}\n{output}"

    async def _handle_read_file(self, inputs: dict[str, Any]) -> str:
        """Read a file from inside the container and return its contents."""
        if self.executor is None:
            return "Error: no container executor available for this agent"
        path = inputs["path"]
        try:
            return await asyncio.to_thread(self.executor.read_file, path)
        except Exception as exc:
            return f"Error reading {path}: {exc}"

    async def _handle_write_file(self, inputs: dict[str, Any]) -> str:
        """Write content to a path inside the container."""
        if self.executor is None:
            return "Error: no container executor available for this agent"
        path, content = inputs["path"], inputs["content"]
        try:
            await asyncio.to_thread(self.executor.write_file, path, content)
            return f"Written: {path}"
        except Exception as exc:
            return f"Error writing {path}: {exc}"

    async def _handle_store_finding(self, inputs: dict[str, Any]) -> str:
        """Persist a finding to the DB and ChromaDB memory, dispatching on finding type."""
        finding_type = inputs["type"]
        data: dict[str, Any] = inputs["data"]

        try:
            self._findings_count += 1
            match finding_type:
                case "host":
                    host_id = await asyncio.to_thread(
                        self.db.upsert_host,
                        self.engagement_id,
                        data["ip"],
                        hostname=data.get("hostname"),
                        os=data.get("os"),
                        os_version=data.get("os_version"),
                        role=data.get("role"),
                    )
                    await self.bus.publish(
                        EventBus.make(EventType.HOST_FOUND, agent=self.name, ip=data["ip"])
                    )
                    await self._store_to_memory(
                        f"Host: {data['ip']} hostname={data.get('hostname')} "
                        f"os={data.get('os')} role={data.get('role')}",
                        {"type": "host", "target": data["ip"]},
                    )
                    return f"Host stored: {data['ip']} (id={host_id})"

                case "service":
                    host_id = await asyncio.to_thread(
                        self.db.upsert_host, self.engagement_id, data["ip"]
                    )
                    svc_id = await asyncio.to_thread(
                        self.db.upsert_service,
                        host_id,
                        int(data["port"]),
                        protocol=data.get("protocol", "tcp"),
                        service_name=data.get("service_name"),
                        version=data.get("version"),
                        banner=data.get("banner"),
                    )
                    await self.bus.publish(
                        EventBus.make(
                            EventType.SERVICE_FOUND,
                            agent=self.name,
                            ip=data["ip"],
                            port=data["port"],
                        )
                    )
                    await self._store_to_memory(
                        f"Service: {data['ip']}:{data['port']}/{data.get('protocol','tcp')} "
                        f"{data.get('service_name','')} {data.get('version','')}".strip(),
                        {"type": "service", "target": data["ip"]},
                    )
                    return f"Service stored: {data['ip']}:{data['port']} (id={svc_id})"

                case "vulnerability":
                    host_id = None
                    service_id = None
                    if ip := data.get("ip"):
                        host_id = await asyncio.to_thread(
                            self.db.upsert_host, self.engagement_id, ip
                        )
                        if port := data.get("port"):
                            service_id = await asyncio.to_thread(
                                self.db.upsert_service,
                                host_id,
                                int(port),
                                protocol=data.get("protocol", "tcp"),
                            )
                    vuln_id = await asyncio.to_thread(
                        self.db.add_vulnerability,
                        self.engagement_id,
                        data["title"],
                        data["severity"],
                        host_id=host_id,
                        service_id=service_id,
                        cvss=data.get("cvss"),
                        cve=data.get("cve"),
                        description=data.get("description"),
                        evidence=data.get("evidence"),
                        reproduction=data.get("reproduction"),
                        remediation=data.get("remediation"),
                        agent=self.name,
                        mitre_id=data.get("mitre_id"),
                    )
                    await self.bus.publish(
                        EventBus.make(
                            EventType.VULN_FOUND,
                            agent=self.name,
                            title=data["title"],
                            severity=data["severity"],
                        )
                    )
                    await self._store_to_memory(
                        f"Vulnerability [{data['severity']}]: {data['title']} "
                        f"on {data.get('ip','?')}:{data.get('port','')} "
                        f"CVE={data.get('cve','')} — {data.get('description','')[:200]}".strip(),
                        {"type": "vulnerability", "target": data.get("ip", "")},
                    )
                    return (
                        f"Vulnerability stored: {data['title']}"
                        f" [{data['severity']}] (id={vuln_id})"
                    )

                case "credential":
                    host_id = None
                    if ip := data.get("ip"):
                        host_id = await asyncio.to_thread(
                            self.db.upsert_host, self.engagement_id, ip
                        )
                    cred_id = await asyncio.to_thread(
                        self.db.add_credential,
                        self.engagement_id,
                        host_id=host_id,
                        username=data.get("username"),
                        secret=data.get("secret"),
                        secret_type=data.get("secret_type"),
                        domain=data.get("domain"),
                        access_level=data.get("access_level"),
                        source_tool=data.get("source_tool"),
                        validity=data.get("validity", "unknown"),
                    )
                    await self.bus.publish(
                        EventBus.make(
                            EventType.CRED_FOUND,
                            agent=self.name,
                            username=data.get("username"),
                        )
                    )
                    await self._store_to_memory(
                        f"Credential: {data.get('username')} on {data.get('ip','?')} "
                        f"type={data.get('secret_type','')} access={data.get('access_level','')}".strip(),
                        {"type": "credential", "target": data.get("ip", "")},
                    )
                    return f"Credential stored: {data.get('username', 'unknown')} (id={cred_id})"

                case "attack_chain":
                    chain_id = await asyncio.to_thread(
                        self.db.add_attack_chain,
                        self.engagement_id,
                        data["title"],
                        data["steps"],
                        data["severity"],
                        mitre_techniques=data.get("mitre_techniques"),
                    )
                    return f"Attack chain stored: {data['title']} (id={chain_id})"

                case "finding":
                    # Stored at severity="finding" so the reporter can separate it from
                    # confirmed vulnerabilities and place it in the Unverified Leads section.
                    host_id = None
                    if ip := data.get("ip"):
                        host_id = await asyncio.to_thread(
                            self.db.upsert_host, self.engagement_id, ip
                        )
                    vuln_id = await asyncio.to_thread(
                        self.db.add_vulnerability,
                        self.engagement_id,
                        data["title"],
                        "finding",
                        host_id=host_id,
                        description=data.get("description"),
                        agent=self.name,
                    )
                    await self._store_to_memory(
                        f"Lead: {data['title']} — {data.get('description', '')[:300]}".strip(),
                        {"type": "finding", "target": data.get("ip", "")},
                    )
                    return f"Intelligence lead stored: {data['title']} (id={vuln_id})"

                case "flag":
                    flag_id = await asyncio.to_thread(
                        self.db.add_flag,
                        self.engagement_id,
                        data["value"],
                        flag_type=data.get("flag_type"),
                        context=data.get("context"),
                    )
                    await self.bus.publish(
                        EventBus.make(EventType.FLAG_FOUND, agent=self.name, value=data["value"])
                    )
                    return f"Flag stored: {data['value']} (id={flag_id})"

                case _:
                    self._findings_count -= 1
                    return f"Unknown finding type: {finding_type}"

        except KeyError as exc:
            self._findings_count -= 1
            return f"Missing required field for {finding_type}: {exc}"
        except Exception as exc:
            self._findings_count -= 1
            return f"Error storing {finding_type}: {exc}"

    async def _handle_request_approval(self, inputs: dict[str, Any]) -> str:
        command = inputs["command"]
        reason = inputs["reason"]
        risk_level = inputs["risk_level"]

        if self.ctf_mode:
            await asyncio.to_thread(
                self.db.log_action,
                self.engagement_id,
                self.name,
                "approval_auto",
                summary=f"[CTF auto-approved] {command}",
            )
            return f"Auto-approved (CTF mode). Proceed with: {command}"

        # One-shot event subscription: subscribe before publishing so we never miss the reply,
        # wait on the event, then immediately unsubscribe to avoid leaking the handler.
        decision_event = asyncio.Event()
        decision_holder: dict[str, Any] = {}

        async def on_decided(event: Any) -> None:
            decision_holder.update(event.data)
            decision_event.set()

        self.bus.subscribe(EventType.APPROVAL_DECIDED, on_decided)

        await asyncio.to_thread(
            self.db.log_action,
            self.engagement_id,
            self.name,
            "approval_requested",
            summary=f"[{risk_level}] {command}",
        )

        await self.bus.publish(
            EventBus.make(
                EventType.APPROVAL_NEEDED,
                agent=self.name,
                command=command,
                reason=reason,
                risk_level=risk_level,
            )
        )

        await decision_event.wait()
        self.bus.unsubscribe(EventType.APPROVAL_DECIDED, on_decided)

        decision = decision_holder.get("decision", "skipped")
        modified_cmd = decision_holder.get("modified_cmd")
        user_note = decision_holder.get("user_note", "")

        await asyncio.to_thread(
            self.db.log_approval,
            self.engagement_id,
            self.name,
            command,
            decision,
            reason=reason,
            risk_level=risk_level,
            modified_cmd=modified_cmd,
            user_note=user_note,
        )

        if decision == "approved":
            return f"Approved. Proceed with: {command}"
        elif decision == "modified":
            return f"Approved with modification. Use this command instead: {modified_cmd}"
        elif decision == "stopped":
            raise ApprovalDeniedError("stopped")
        else:
            raise ApprovalDeniedError("skipped")

    async def _handle_search_memory(self, inputs: dict[str, Any]) -> str:
        """Query ChromaDB for semantically similar past findings or knowledge entries."""
        from konr.storage.memory import VectorMemory
        if self._memory is None:
            try:
                self._memory = VectorMemory()
            except Exception as exc:
                return f"Memory unavailable: {exc}"
        query      = inputs["query"]
        collection = inputs.get("collection", "tool_outputs")
        n_results  = int(inputs.get("n_results", 3))
        try:
            results = await asyncio.to_thread(
                self._memory.search, collection, query, n_results=n_results
            )
        except Exception as exc:
            return f"Memory search failed: {exc}"
        if not results:
            return "No relevant memory found."
        parts = []
        for r in results:
            meta = r.get("metadata", {})
            header = (
                f"[{meta.get('tool', '?')} on {meta.get('target', '?')}"
                f" at {meta.get('timestamp', '?')}]"
            )
            parts.append(f"{header}\n{r['content'][:config.MEMORY_RESULT_MAX_CHARS]}")
        return "\n\n---\n\n".join(parts)

    async def _handle_delegate_to_coder(self, inputs: dict[str, Any]) -> str:
        """Spin up a CoderAgent sub-task and return its result inline."""
        from konr.agents.specialists.coder import CoderAgent
        coder = CoderAgent(
            engagement_id=self.engagement_id,
            session=self.session,
            bus=self.bus,
            db=self.db,
            executor=self.executor,
            ctf_mode=self.ctf_mode,
            scope=self.scope,
        )
        task = inputs["task"]
        context = inputs.get("context", "")
        lang = inputs.get("language", "python")
        result = await coder.run(f"{task}\n\nContext: {context}\nPreferred language: {lang}")
        if result.success:
            return result.summary or "CoderAgent completed but returned no summary."
        return f"CoderAgent failed: {result.error}"

    def _handle_task_complete(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Return a sentinel dict that signals the loop to exit with this summary."""
        return {
            "_task_complete": True,
            "_summary": inputs["summary"],
            "_findings_count": inputs.get("findings_count", self._findings_count),
        }

    async def _haiku_summarize(self, output: str, command: str) -> str:
        """Use Haiku to condense large tool output, preserving all security-relevant details."""
        tool_name = command.split()[0] if command else "tool"
        prompt = (
            f"Summarize this pentest tool output from `{tool_name}`. "
            "Preserve all IPs, ports, CVEs, usernames, credentials, service versions, and flags. "
            "Remove repetitive lines and verbose boilerplate. Be concise.\n\n"
            f"{output}"
        )
        try:
            response = await asyncio.to_thread(
                self._client.messages.create,
                model=config.HAIKU_MODEL,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            return extract_text(response.content)
        except Exception:
            return output
