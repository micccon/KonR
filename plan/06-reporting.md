# Reporting Design

## Overview

The Reporter agent queries SQLite at engagement end and generates a structured Markdown report. In CTF mode it generates a walkthrough instead. Reports are saved to `./work/reports/`.

---

## Report Structure (Pentest Mode)

```
reports/{engagement_name}_{YYYY-MM-DD}.md

1. Cover / Title
2. Executive Summary
3. Scope & Methodology
4. Findings Overview (severity chart)
5. Detailed Findings (one section per vulnerability)
6. Attack Chains
7. Discovered Credentials
8. Appendix A — Command Log (approved commands)
9. Appendix B — Tools Used
```

---

## Markdown Template

```markdown
# Penetration Test Report
**Client:** {client}
**Engagement:** {engagement_name}
**Date:** {date}
**Conducted By:** AI Pentest System v1.0
**Classification:** CONFIDENTIAL

---

## Executive Summary

During the period of this engagement, **{vuln_count} vulnerabilities** were identified
across **{host_count} hosts** within the declared scope.

| Severity | Count |
|----------|-------|
| Critical | {critical_count} |
| High     | {high_count} |
| Medium   | {medium_count} |
| Low      | {low_count} |

**Key findings:**
{top_3_findings_bullets}

---

## Scope & Methodology

**Target Scope:**
{scope_list}

**Phases Conducted:**
- Reconnaissance & OSINT
- Web Application Testing
- Active Directory Assessment
- Post-Exploitation

**Tools:** {tools_list}

---

## Findings Overview

### Risk Distribution

{severity_summary_table}

---

## Detailed Findings

### [CRITICAL] {vuln_title}

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **CVSS** | {cvss} |
| **CVE** | {cve} |
| **Host** | {host_ip} ({hostname}) |
| **Service** | {port}/{service} |
| **Discovered By** | {agent} |

**Description:**
{description}

**Evidence:**
```
{evidence_snippet}
```

**Reproduction Steps:**
{reproduction}

**Remediation:**
{remediation}

---
(repeated for each vulnerability, ordered by severity then CVSS)

---

## Attack Chains

### {chain_title}

**Severity:** {severity}
**MITRE ATT&CK Techniques:** {mitre_ids}

**Steps:**
{chain_steps_numbered}

---

## Discovered Credentials

| Username | Type | Domain | Access Level | Source |
|----------|------|--------|--------------|--------|
| {username} | {type} | {domain} | {access_level} | {tool} |

*Plaintext passwords redacted in this report. Full credential data available in findings.db.*

---

## Appendix A — Approved Commands Log

| Timestamp | Agent | Command | Risk | Decision |
|-----------|-------|---------|------|----------|
| {timestamp} | {agent} | `{command}` | {risk} | {decision} |

---

## Appendix B — Tools Used

{tools_table}
```

---

## Reporter Agent — `agents/reporter.py`

The reporter does **not** run a tool execution loop. It:
1. Queries SQLite via `get_findings_for_report(engagement_id)`
2. Passes structured data to Claude Sonnet with the template
3. Writes output to disk

```python
class ReporterAgent:
    model = "claude-sonnet-4-6"

    async def generate(self, engagement_id: int) -> str:
        findings = self.db.get_findings_for_report(engagement_id)

        prompt = f"""
        Generate a professional penetration test report in Markdown.
        Use the following structured data. Follow the template exactly.

        ENGAGEMENT:
        {json.dumps(findings['engagement'], indent=2)}

        HOSTS & SERVICES:
        {json.dumps(findings['hosts'], indent=2)}

        VULNERABILITIES (ordered by severity, then CVSS):
        {json.dumps(findings['vulnerabilities'], indent=2)}

        ATTACK CHAINS:
        {json.dumps(findings['attack_chains'], indent=2)}

        CREDENTIALS (usernames only — do not include plaintext passwords in report):
        {json.dumps(findings['credentials_summary'], indent=2)}

        APPROVED COMMANDS LOG:
        {json.dumps(findings['approvals'], indent=2)}

        Template to follow:
        {REPORT_TEMPLATE}
        """

        response = await self.client.messages.create(
            model=self.model,
            max_tokens=8192,
            messages=[{"role": "user", "content": prompt}],
        )

        report_content = response.content[0].text
        output_path = self._write_report(engagement_id, report_content)
        return output_path

    def _write_report(self, engagement_id: int, content: str) -> str:
        engagement = self.db.get_engagement(engagement_id)
        safe_name = engagement['name'].replace(" ", "_").lower()
        date = datetime.now().strftime("%Y-%m-%d")
        filename = f"{safe_name}_{date}.md"
        path = f"./work/reports/{filename}"
        os.makedirs("./work/reports", exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path
```

---

## FindingsDB Report Query

```python
def get_findings_for_report(self, engagement_id: int) -> dict:
    return {
        "engagement": self._get_engagement(engagement_id),
        "hosts": self._get_hosts_with_services(engagement_id),
        "vulnerabilities": self._get_vulns_ordered(engagement_id),
        "attack_chains": self._get_attack_chains(engagement_id),
        "credentials_summary": self._get_credentials_summary(engagement_id),
        "approvals": self._get_approvals(engagement_id),
        "stats": {
            "host_count": ...,
            "vuln_count": ...,
            "critical_count": ...,
            "high_count": ...,
            "medium_count": ...,
            "low_count": ...,
        }
    }

def _get_vulns_ordered(self, engagement_id: int) -> list[dict]:
    """Vulnerabilities ordered by severity weight, then CVSS score."""
    severity_order = "CASE severity "
    severity_order += "WHEN 'critical' THEN 1 "
    severity_order += "WHEN 'high' THEN 2 "
    severity_order += "WHEN 'medium' THEN 3 "
    severity_order += "WHEN 'low' THEN 4 END"

    return self.conn.execute(f"""
        SELECT v.*, h.ip, h.hostname, s.port, s.service_name
        FROM vulnerabilities v
        LEFT JOIN hosts h ON v.host_id = h.id
        LEFT JOIN services s ON v.service_id = s.id
        WHERE v.engagement_id = ? AND v.status = 'confirmed'
        ORDER BY {severity_order}, v.cvss DESC
    """, (engagement_id,)).fetchall()
```

---

## CTF Mode — Walkthrough Output

In CTF mode, Reporter generates a walkthrough document instead of a professional report.

```markdown
# HTB Walkthrough — {machine_name}
**Date:** {date}
**Mode:** HackTheBox CTF

---

## Summary

Successfully pwned **{machine_name}** and captured {flag_count} flag(s).

| Flag | Value | Found At |
|------|-------|----------|
| user.txt | {user_flag} | {timestamp} |
| root.txt | {root_flag} | {timestamp} |

---

## Attack Path

### 1. Reconnaissance
{recon_summary}

### 2. Initial Access
{web_exploit_summary}

### 3. Privilege Escalation
{privesc_summary}

---

## Commands Used

{approved_commands_log}

---

## Tools
{tools_used}
```

---

## CVSS Scoring Guidance

Agents are prompted to estimate CVSS when storing vulnerabilities. The prompt includes:

```
When calling store_finding for a vulnerability, estimate the CVSS v3.1 base score:
- Critical: 9.0-10.0 (network-accessible, no auth, full system compromise)
- High: 7.0-8.9 (network-accessible, partial auth or limited impact)
- Medium: 4.0-6.9 (local access or authenticated exploitation)
- Low: 0.1-3.9 (limited impact, requires significant conditions)

Include CVE ID if known. Use 'N/A' if no CVE exists.
```

---

## Output

Report saved to: `./work/reports/{engagement_name}_{date}.md`

TUI shows completion message:
```
[system]  Report generated: ./work/reports/acme_corp_2026-05-08.md
[system]  Engagement complete. Total cost: $4.23 | Duration: 1h 42m
```

To convert to PDF (user runs manually):
```bash
# pandoc
pandoc report.md -o report.pdf --pdf-engine=weasyprint

# Or: grip (GitHub-style rendering)
grip report.md
```
