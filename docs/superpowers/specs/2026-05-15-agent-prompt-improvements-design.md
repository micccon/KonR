# Agent Prompt Improvements Design
**Date:** 2026-05-15  
**Status:** Approved  
**Scope:** System prompt changes across all KonR specialist agents and reporter

---

## Background

Analysis of the Automotive Testbed engagement log (2026-05-15) identified six categories of agent failure:

1. **False positive** — osint stored a Werkzeug Debug Shell RCE as a confirmed vulnerability based solely on a searchsploit version match. No agent ever tested `/__debugger__`. The reporter surfaced it as Critical/Confirmed.
2. **Missed IDOR coverage** — web agent tested path-based IDOR (`/user/2`) but not parameter-based (`?user_id=2`). Postexploit found the `/settings?user_id=` IDOR by accident.
3. **network_exploit stuck in blind fuzzing** — spent 9 minutes on exhaustive byte sweeps of unknown binary services (ports 9555/9556) with no stop condition.
4. **network_exploit missed memory context** — the `/status` endpoint output (stored by web) was never read. Ports 9555/9556 could have been identified as automotive protocol services from service names alone.
5. **sshpass not installed** — SSH brute force silently failed every attempt.
6. **Reporter accuracy** — finding notes and confirmed vulnerabilities were indistinguishable in output.

All fixes are system prompt changes only. No code changes required.

---

## Design

### Section 1: Universal Principles (all agents)

Two rules added as a preamble to every specialist agent's system prompt.

**Rule 1 — Store by action, not by research:**
> Passive research (version matching, searchsploit, CVE lookup, banner grabbing) → use `store_finding` type `finding`. Active confirmation (you ran the exploit and got a response proving it works) → use `store_finding` type `vulnerability`. Never store a vulnerability you have not exercised.

**Rule 2 — Read before you act:**
> Before starting your steps, search memory for findings, services, and vulnerabilities other agents have stored on this target. Use this context to prioritize what to test — don't duplicate work, do follow up on flagged intelligence.

These two rules are the foundation for all other changes. Rule 1 eliminates false positives system-wide. Rule 2 fixes coordination gaps between agents running in parallel.

---

### Section 2: osint.py

**Problem:** osint stores searchsploit/CVE hits as `vulnerability` type records. These are version-based, never exercised.

**Change:** The searchsploit/CVE research step stores results as `finding` type notes in this format:
> "Technology X version Y — known exploit exists (source: searchsploit/CVE). Verify whether the vulnerability is active before treating as exploitable. Flagged for: [appropriate specialist agent]."

**What stays the same:** all passive recon steps — subdomains, WHOIS, DNS, cert transparency, email harvesting, Shodan/Censys. Those already store as `finding` type.

**Effect:** osint notes land in memory. Web or network_exploit reads them (Rule 2), verifies the actual endpoint, and if confirmed, stores the vulnerability. If no agent confirms it, no vulnerability is written.

---

### Section 3: web.py

Two additions, both principle-based.

**Addition 1 — Framework verification:**

When a framework or server technology is identified from a banner or response header, the agent identifies and tests that technology's known debug, diagnostic, or admin endpoints before storing anything. Principle:
> Detection of a technology version is not a finding — it's a lead. Follow it by testing the actual endpoint. If it responds in a way that confirms the vulnerability is active, store it as confirmed. If not, do not store it.

This covers all frameworks (Werkzeug `/__debugger__`, Spring Boot `/actuator`, Django debug error pages, Laravel debug mode, etc.) without listing any of them specifically. The agent reasons about what to test based on what it found.

**Addition 2 — Principle-based IDOR:**

The current IDOR step tests path-based enumeration only. Add:
> For every authenticated endpoint that returns user-specific or resource-specific data, test whether access control is enforced on identifiers — both in URL paths and in query parameters. Substitute different values (higher, lower, zero, negative) and compare responses. A different response body with a 200 status is evidence of IDOR regardless of where the identifier appears.

The agent determines which parameters to test by reading what the endpoint actually accepts — not from a hardcoded list of parameter names.

---

### Section 4: network_exploit.py

Three targeted fixes.

**Fix 1 — SSH brute force tool:**

Replace `sshpass` (not installed in the container image) with `hydra`:
> Use `hydra -l <user> -P <wordlist> ssh://<target>` for credential testing against SSH. Do not use sshpass.

**Fix 2 — Hard cap on unknown binary services:**

Replace exhaustive byte sweeps with a bounded investigation:
> For unknown binary services, make at most 5 structured probes: send empty, send `GET /\r\n`, send a null byte, send a 4-byte length-prefixed empty message, send `HELP\r\n`. If none produce a recognizable protocol pattern, store a finding note — "Unknown binary service on port X, protocol unidentified" — and move on. Do not run exhaustive byte sweeps.

**Fix 3 — Context-first probing:**

Before probing any service, check memory for context clues:
> Before probing an unknown service, check memory for any context clues — service names, status endpoint output, nmap guesses, prior agent notes. If context suggests what the protocol might be, research it and probe accordingly. Only fall back to generic structured probes if you have no context at all. Cap generic probing at 5 attempts, then store as unknown and move on.

This applies to any protocol — industrial, automotive, enterprise, custom — without listing specific protocol names.

---

### Section 5: recon.py and ad.py

Minor reinforcements of the universal rules applied to each agent's domain.

**recon.py:**
> Store hosts and services. If an NSE script actively confirms a vulnerability by eliciting a specific response, store a finding note for a specialist agent to verify. Version-based CVE matches from banners alone do not get stored.

**ad.py:**
> Enumeration output (users, groups, SPNs, shares) is intelligence — store as `finding` type. Only store a `vulnerability` when you have actively confirmed it: ticket extracted, hash cracked, privilege escalated. Inference ("this is probably vulnerable because X service is running") is a finding note, not a vulnerability.

---

### Section 6: reporter.py

**Problem:** reporter queries the DB and renders only `vulnerability` records in its output. Finding notes stored by osint and other agents are invisible in the final report, meaning useful intelligence disappears entirely.

**Change:** After the main findings section, the reporter renders a distinct "Unverified Leads" section:
> After the main findings section, add a section titled 'Unverified Leads'. Query all records stored as `finding` type whose description contains "Flagged for:" — this is the marker agents use when storing intelligence leads for verification (as opposed to routine recon findings like subdomains or open ports). List each with: what was found, which agent flagged it, and what verification step is needed. Use clear language — these are intelligence leads, not confirmed vulnerabilities. Do not assign severity scores to unverified leads.

**Example output:**
```
## Unverified Leads

These items were flagged during reconnaissance but not confirmed through 
active exploitation. They require manual verification before being treated 
as vulnerabilities.

- **Werkzeug 3.1.8** (ports 8000, 8080, 9999): Known debug shell exploit 
  exists. Verify whether debug mode is active by testing /__debugger__ 
  endpoint. Flagged by: osint.
```

**What stays the same:** main findings section, severity scoring, executive summary, remediation steps, CVSS scores — all untouched.

---

## Files Changed

| File | Change | Section |
|------|--------|---------|
| All specialist agents | Universal store + memory rules added as preamble | 1 |
| `konr/agents/specialists/osint.py` | Store searchsploit/CVE hits as `finding` notes | 2 |
| `konr/agents/specialists/web.py` | Framework verify principle + parameter IDOR principle | 3 |
| `konr/agents/specialists/network_exploit.py` | hydra for SSH, 5-probe cap, context-first probing | 4 |
| `konr/agents/specialists/recon.py` | No version-based CVEs stored as vulns | 5 |
| `konr/agents/specialists/ad.py` | Enum = finding, confirm = vulnerability | 5 |
| `konr/agents/reporter.py` | Unverified Leads section added to report output | 6 |

---

## What This Does Not Fix

- **v10_can_dlc** — the CAN DLC vulnerability on ports 9555/9556. Excluded from scope by design decision. Requires automotive protocol domain knowledge.
- **SSH credential sequencing** — network_exploit runs in parallel with web/postexploit and cannot use credentials those agents discover mid-run. Orchestrator limitation, not a prompt issue. Low impact since SSH was disabled in this engagement.
