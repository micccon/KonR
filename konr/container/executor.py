"""Execute commands inside the pentest container and stream output."""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

import docker.errors
from docker.models.containers import Container

from konr.container.manager import ContainerError
from konr.core import config

# Strips ANSI escape codes from tool output before storing/summarising
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")

# Flag patterns for CTF mode auto-detection
_FLAG_PATTERNS = [
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"THM\{[^}]+\}"),
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"[a-f0-9]{32}"),  # MD5-style hex — high false-positive rate, kept for coverage
]


@dataclass
class ExecResult:
    command: str
    exit_code: int
    output: str                        # full raw output (stdout + stderr merged)
    truncated: bool = False            # True if output exceeded OUTPUT_TRUNCATE_BYTES
    flags_found: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


class CommandExecutor:
    """Runs shell commands inside a running Docker container."""

    def __init__(self, container: Container) -> None:
        """Bind the executor to an already-running Docker container."""
        self._container = container

    # ── Blocking execution ────────────────────────────────────────────────

    def run(
        self,
        command: str,
        *,
        timeout: int = 300,
        workdir: str = "/work",
        ctf_mode: bool = False,
    ) -> ExecResult:
        """Run a command and return when it completes."""
        try:
            exit_code, raw_output = self._container.exec_run(
                cmd=["bash", "-c", command],
                stdout=True,
                stderr=True,
                stream=False,
                demux=False,
                workdir=workdir,
                environment={"TERM": "dumb"},  # suppress colour codes from most tools
            )
        except docker.errors.APIError as exc:
            raise ContainerError(f"exec_run failed: {exc}") from exc

        output = _strip_ansi(raw_output.decode("utf-8", errors="replace") if raw_output else "")
        truncated = False

        if len(output.encode()) > config.OUTPUT_TRUNCATE_BYTES:
            output = _truncate(output, config.OUTPUT_TRUNCATE_BYTES)
            truncated = True

        flags: list[str] = []
        if ctf_mode:
            flags = _extract_flags(output)

        return ExecResult(
            command=command,
            exit_code=exit_code if isinstance(exit_code, int) else 1,
            output=output,
            truncated=truncated,
            flags_found=flags,
        )

    # ── Streaming execution ───────────────────────────────────────────────

    def stream(
        self,
        command: str,
        *,
        workdir: str = "/work",
        ctf_mode: bool = False,
    ) -> Iterator[str]:
        """Yield output lines as they arrive. Caller is responsible for timeout."""
        try:
            _, stream = self._container.exec_run(
                cmd=["bash", "-c", command],
                stdout=True,
                stderr=True,
                stream=True,
                demux=False,
                workdir=workdir,
                environment={"TERM": "dumb"},
            )
        except docker.errors.APIError as exc:
            raise ContainerError(f"exec_run (stream) failed: {exc}") from exc

        for chunk in stream:
            line = _strip_ansi(chunk.decode("utf-8", errors="replace"))
            if line:
                yield line

    # ── File I/O ──────────────────────────────────────────────────────────

    def write_file(self, container_path: str, content: str) -> None:
        """Write a string to a file inside the container via shell heredoc."""
        import shlex
        safe_path = shlex.quote(container_path)
        # Use printf to avoid issues with special chars in content
        escaped = content.replace("\\", "\\\\").replace("'", "'\\''")
        result = self.run(f"printf '%s' '{escaped}' > {safe_path}")
        if not result.succeeded:
            raise ContainerError(f"write_file failed ({result.exit_code}): {result.output}")

    def read_file(self, container_path: str) -> str:
        """Read a file from inside the container."""
        import shlex
        result = self.run(f"cat {shlex.quote(container_path)}")
        if not result.succeeded:
            raise ContainerError(f"read_file failed ({result.exit_code}): {result.output}")
        return result.output

    def file_exists(self, container_path: str) -> bool:
        """Return True if the path exists and is a regular file inside the container."""
        import shlex
        result = self.run(f"test -f {shlex.quote(container_path)}")
        return result.succeeded

    # ── Tool availability ─────────────────────────────────────────────────

    def which(self, tool: str) -> str | None:
        """Return the path to a tool inside the container, or None if missing."""
        import shlex
        result = self.run(f"which {shlex.quote(tool)}")
        return result.output.strip() if result.succeeded else None

    def tool_available(self, tool: str) -> bool:
        """Return True if the named tool is on the container's PATH."""
        return self.which(tool) is not None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from terminal output."""
    return _ANSI_RE.sub("", text)


def _truncate(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    kept = encoded[:max_bytes].decode("utf-8", errors="ignore")
    lines_kept = kept.count("\n")
    total_lines = text.count("\n")
    dropped = total_lines - lines_kept
    return kept + f"\n\n[... output truncated — {dropped} lines omitted ...]"


def _extract_flags(text: str) -> list[str]:
    """Scan output for CTF flag patterns and return unique matches in order of appearance."""
    found: list[str] = []
    for pattern in _FLAG_PATTERNS:
        found.extend(pattern.findall(text))
    return list(dict.fromkeys(found))  # deduplicate, preserve order
