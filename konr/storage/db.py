from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()

_SCHEMA = Path(__file__).parent / "schema.sql"

_SEVERITY_WEIGHT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FindingsDB:
    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(_SCHEMA.read_text())
        self._conn.commit()

    # ── Engagements ──────────────────────────────────────────────────────

    def create_engagement(
        self,
        name: str,
        target_scope: str,
        *,
        client: str | None = None,
        mode: str = "pentest",
        objectives: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO engagements
                (name, client, mode, target_scope, objectives, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (name, client, mode, target_scope, objectives, _now(), _now()),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_engagement(self, engagement_id: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_engagements(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_engagement_status(self, engagement_id: int, status: str) -> None:
        self._conn.execute(
            "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), engagement_id),
        )
        self._conn.commit()

    # ── Hosts ─────────────────────────────────────────────────────────────

    def upsert_host(
        self,
        engagement_id: int,
        ip: str,
        *,
        hostname: str | None = None,
        os: str | None = None,
        os_version: str | None = None,
        role: str | None = None,
    ) -> int:
        self._conn.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os, os_version, role)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, ip) DO UPDATE SET
                hostname   = COALESCE(excluded.hostname,   hostname),
                os         = COALESCE(excluded.os,         os),
                os_version = COALESCE(excluded.os_version, os_version),
                role       = COALESCE(excluded.role,       role)
            """,
            (engagement_id, ip, hostname, os, os_version, role),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM hosts WHERE engagement_id = ? AND ip = ?",
            (engagement_id, ip),
        ).fetchone()
        return row["id"]

    def get_hosts(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM hosts WHERE engagement_id = ? ORDER BY ip",
            (engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Services ──────────────────────────────────────────────────────────

    def upsert_service(
        self,
        host_id: int,
        port: int,
        *,
        protocol: str = "tcp",
        service_name: str | None = None,
        version: str | None = None,
        banner: str | None = None,
    ) -> int:
        self._conn.execute(
            """
            INSERT INTO services (host_id, port, protocol, service_name, version, banner)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                service_name = COALESCE(excluded.service_name, service_name),
                version      = COALESCE(excluded.version,      version),
                banner       = COALESCE(excluded.banner,       banner)
            """,
            (host_id, port, protocol, service_name, version, banner),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM services WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol),
        ).fetchone()
        return row["id"]

    def get_services(self, host_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port",
            (host_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Vulnerabilities ───────────────────────────────────────────────────

    def add_vulnerability(
        self,
        engagement_id: int,
        title: str,
        severity: str,
        *,
        host_id: int | None = None,
        service_id: int | None = None,
        cvss: float | None = None,
        cve: str | None = None,
        description: str | None = None,
        evidence: str | None = None,
        evidence_file: str | None = None,
        reproduction: str | None = None,
        remediation: str | None = None,
        status: str = "confirmed",
        agent: str | None = None,
        mitre_id: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO vulnerabilities
                (engagement_id, host_id, service_id, title, severity, cvss, cve,
                 description, evidence, evidence_file, reproduction, remediation,
                 status, agent, mitre_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id, host_id, service_id, title, severity, cvss, cve,
                description, evidence, evidence_file, reproduction, remediation,
                status, agent, mitre_id,
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_vulnerabilities(
        self, engagement_id: int, severity: str | None = None
    ) -> list[dict[str, Any]]:
        if severity:
            rows = self._conn.execute(
                "SELECT * FROM vulnerabilities WHERE engagement_id = ? AND severity = ?",
                (engagement_id, severity),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM vulnerabilities WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        return sorted(
            [dict(r) for r in rows],
            key=lambda v: _SEVERITY_WEIGHT.get(v["severity"].lower(), 99),
        )

    # ── Credentials ───────────────────────────────────────────────────────

    def add_credential(
        self,
        engagement_id: int,
        *,
        host_id: int | None = None,
        username: str | None = None,
        secret: str | None = None,
        secret_type: str | None = None,
        domain: str | None = None,
        access_level: str | None = None,
        source_tool: str | None = None,
        validity: str = "unknown",
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO credentials
                (engagement_id, host_id, username, secret, secret_type,
                 domain, access_level, source_tool, validity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id, host_id, username, secret, secret_type,
                domain, access_level, source_tool, validity,
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_credentials(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM credentials WHERE engagement_id = ? ORDER BY discovered_at",
            (engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Attack Chains ─────────────────────────────────────────────────────

    def add_attack_chain(
        self,
        engagement_id: int,
        title: str,
        steps: list[dict[str, Any]],
        severity: str,
        *,
        status: str = "identified",
        mitre_techniques: list[str] | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO attack_chains
                (engagement_id, title, steps, severity, status, mitre_techniques)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                title,
                json.dumps(steps),
                severity,
                status,
                json.dumps(mitre_techniques or []),
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_attack_chains(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM attack_chains WHERE engagement_id = ? ORDER BY created_at",
            (engagement_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["steps"] = json.loads(d["steps"])
            d["mitre_techniques"] = json.loads(d["mitre_techniques"] or "[]")
            result.append(d)
        return result

    # ── Flags (CTF) ───────────────────────────────────────────────────────

    def add_flag(
        self,
        engagement_id: int,
        flag_value: str,
        *,
        flag_type: str | None = None,
        context: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO flags (engagement_id, flag_value, flag_type, context)
            VALUES (?, ?, ?, ?)
            """,
            (engagement_id, flag_value, flag_type, context),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_flags(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM flags WHERE engagement_id = ? ORDER BY discovered_at",
            (engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Approvals ─────────────────────────────────────────────────────────

    def log_approval(
        self,
        engagement_id: int,
        agent: str,
        command: str,
        decision: str,
        *,
        reason: str | None = None,
        risk_level: str | None = None,
        modified_cmd: str | None = None,
        user_note: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO approvals
                (engagement_id, agent, command, reason, risk_level,
                 decision, modified_cmd, user_note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id, agent, command, reason, risk_level,
                decision, modified_cmd, user_note,
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_approvals(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE engagement_id = ? ORDER BY timestamp",
            (engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Session Log ───────────────────────────────────────────────────────

    def log_action(
        self,
        engagement_id: int,
        agent: str,
        action: str,
        *,
        summary: str | None = None,
        evidence_file: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO session_log
                (engagement_id, agent, action, summary, evidence_file)
            VALUES (?, ?, ?, ?, ?)
            """,
            (engagement_id, agent, action, summary, evidence_file),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_session_log(self, engagement_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM session_log WHERE engagement_id = ? ORDER BY timestamp",
            (engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Reporting ─────────────────────────────────────────────────────────

    def get_findings_for_report(self, engagement_id: int) -> dict[str, Any]:
        engagement = self.get_engagement(engagement_id)
        hosts = self.get_hosts(engagement_id)
        vulns = self.get_vulnerabilities(engagement_id)
        creds = self.get_credentials(engagement_id)
        chains = self.get_attack_chains(engagement_id)
        flags = self.get_flags(engagement_id)
        approvals = self.get_approvals(engagement_id)

        severity_counts: dict[str, int] = {}
        for v in vulns:
            sev = v["severity"].lower()
            if sev != "finding":
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        services_by_host: dict[int, list[dict[str, Any]]] = {}
        for h in hosts:
            services_by_host[h["id"]] = self.get_services(h["id"])

        return {
            "engagement": engagement,
            "hosts": hosts,
            "services_by_host": services_by_host,
            "vulnerabilities": vulns,
            "credentials": creds,
            "attack_chains": chains,
            "flags": flags,
            "approvals": approvals,
            "stats": {
                "host_count": len(hosts),
                "vuln_count": len(vulns),
                "cred_count": len(creds),
                "severity_counts": severity_counts,
            },
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> FindingsDB:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
