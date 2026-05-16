"""ScopeChecker — pure Python scope enforcement, no LLM."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from urllib.parse import urlparse


@dataclass
class EngagementScope:
    ip_ranges: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)

    @classmethod
    def from_target_scope(cls, target_scope: str) -> EngagementScope:
        """Parse a CLI target string into IP ranges and domains. Accepts IPs, CIDRs, domains, or a comma/space-separated mix."""
        ip_ranges: list[str] = []
        domains: list[str] = []

        for part in re.split(r"[,\s]+", target_scope.strip()):
            part = part.strip()
            if not part:
                continue
            # Try as IP or CIDR first
            try:
                IPv4Network(part, strict=False)
                ip_ranges.append(part)
                continue
            except (AddressValueError, ValueError):
                pass
            try:
                IPv4Address(part)
                ip_ranges.append(part)
                continue
            except (AddressValueError, ValueError):
                pass
            # Treat as domain
            domains.append(part.lstrip("*.").lower())

        return cls(ip_ranges=ip_ranges, domains=domains)


class ScopeChecker:
    def __init__(self, scope: EngagementScope) -> None:
        """Pre-compile IP networks and exclusions for O(n) membership checks."""
        self._scope = scope
        self._networks: list[IPv4Network] = []
        for r in scope.ip_ranges:
            try:
                self._networks.append(IPv4Network(r, strict=False))
            except (AddressValueError, ValueError):
                pass
        self._excluded: list[IPv4Network] = []
        for e in scope.excluded:
            try:
                self._excluded.append(IPv4Network(e, strict=False))
            except (AddressValueError, ValueError):
                pass

    def is_in_scope(self, target: str) -> bool:
        """Return True if `target` (IP or hostname) is within declared scope."""
        # Try as IP first
        try:
            addr = IPv4Address(target)
            # Exclusions take priority
            if any(addr in net for net in self._excluded):
                return False
            return any(addr in net for net in self._networks)
        except (AddressValueError, ValueError):
            pass

        # Treat as hostname/domain
        target_lower = target.lower().lstrip("*.")
        if not self._scope.domains:
            # No domains in scope — only IP ranges declared
            return False
        for domain in self._scope.domains:
            if target_lower == domain or target_lower.endswith("." + domain):
                return True
        return False

    def extract_target_from_command(self, command: str) -> str | None:
        """
        Heuristically extract the target IP/hostname from a tool command.
        Returns None if the tool is not recognised or no target can be extracted.
        """
        # Strip shell pipes — only check the first command in a pipeline
        command = command.split("|")[0].strip()
        # Strip I/O redirections (2>/dev/null, >/tmp/x, 2>&1, >>file, <file)
        command = re.sub(r'\s+\d*>{1,2}\S*', '', command).strip()
        command = re.sub(r'\s+\d*<\S*', '', command).strip()

        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()

        if not parts:
            return None

        tool = parts[0].split("/")[-1].lower()

        # nmap / masscan — first positional that looks like a host (not a file path)
        if tool in ("nmap", "masscan"):
            return _ip_positional(parts)

        # URL-based tools: extract hostname from -u / --url
        if tool in (
            "sqlmap", "ffuf", "gobuster", "feroxbuster", "nikto",
            "httpx", "dalfox", "commix", "nuclei",
        ):
            url = _flag_value(parts, ("-u", "--url", "-target", "--target"))
            if url:
                return _hostname_from_url(url)
            return _last_positional(parts)

        # crackmapexec / netexec — first positional after the protocol word
        if tool in ("crackmapexec", "cme", "netexec", "nxc"):
            return _cme_target(parts)

        # impacket tools (GetNPUsers, secretsdump, etc.) — last non-flag arg
        if tool in (
            "getnpusers", "getuserspns", "secretsdump", "psexec",
            "wmiexec", "smbclient",
        ):
            return _last_positional(parts)

        # ssh — first non-flag arg that contains @ or looks like an IP/host
        if tool == "ssh":
            return _ssh_target(parts)

        # Unrecognised tool — caller skips scope check rather than blocking unknown tools
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _last_positional(parts: list[str]) -> str | None:
    """Return the last positional argument (one that doesn't start with '-')."""
    for part in reversed(parts[1:]):
        if not part.startswith("-"):
            return part
    return None


# Flags that consume the next argument — used by _ip_positional to avoid
# treating a flag's value (e.g. "80,443" after -p) as the target host.
_NMAP_VALUE_FLAGS = frozenset({
    "-p", "--port", "--ports",
    "--script", "--script-args",
    "-e", "--interface",
    "--source-port", "-g",
    "--exclude", "--excludefile",
    "--min-rate", "--max-rate",
    "--min-parallelism", "--max-parallelism",
    "-oN", "-oX", "-oG", "-oA", "-oS",
    "--stylesheet",
    "-T",
})


def _looks_like_port_spec(s: str) -> bool:
    """Return True if s looks like a port spec (e.g. 80,443 or 1-1024)."""
    return bool(re.match(r'^[\d,\-]+$', s))


def _ip_positional(parts: list[str]) -> str | None:
    """Return the first positional arg that looks like a host (IP/CIDR/hostname)."""
    skip_next = False
    for part in parts[1:]:
        if skip_next:
            skip_next = False
            continue
        if part in _NMAP_VALUE_FLAGS:
            skip_next = True
            continue
        if part.startswith("-"):
            continue
        if part.startswith("/"):           # absolute file path
            continue
        if ">" in part or "<" in part:     # redirection remnant
            continue
        if part.isdigit():                 # bare number (e.g. --min-rate value)
            continue
        if _looks_like_port_spec(part):    # comma/hyphen port list: 80,443 or 1-1024
            continue
        return part
    return None


def _flag_value(parts: list[str], flags: tuple[str, ...]) -> str | None:
    """Return the value that follows any of the given flag names, handling both --flag value and --flag=value forms."""
    for i, part in enumerate(parts):
        if part in flags and i + 1 < len(parts):
            return parts[i + 1]
        # Handle --flag=value form
        for flag in flags:
            if part.startswith(flag + "="):
                return part.split("=", 1)[1]
    return None


def _hostname_from_url(url: str) -> str | None:
    """Extract the hostname from a URL string, prepending http:// if no scheme is present."""
    if "://" not in url:
        url = "http://" + url
    try:
        return urlparse(url).hostname or None
    except Exception:
        return None


def _cme_target(parts: list[str]) -> str | None:
    """crackmapexec smb <target> — skip tool name and protocol word."""
    _PROTOCOLS = {"smb", "ssh", "winrm", "mssql", "rdp", "ldap", "ftp"}
    positionals = [p for p in parts[1:] if not p.startswith("-")]
    for p in positionals:
        if p.lower() in _PROTOCOLS:
            continue
        return p
    return None


def _ssh_target(parts: list[str]) -> str | None:
    """ssh [opts] [user@]host — find host in positional args."""
    for part in parts[1:]:
        if part.startswith("-"):
            continue
        # Strip user@ prefix
        return part.split("@")[-1]
    return None
