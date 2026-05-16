# Docker Container Design

## Overview

All security tool execution happens inside a sandboxed Docker container. The host machine runs the Python agent system; the container runs only tool processes. Artifacts (scan outputs, exploits, evidence) persist via a volume mount.

---

## Container Lifecycle

```
Orchestrator starts engagement
    ↓
DockerManager.start_container(engagement_id)
    → docker run [flags] pentest-ai:latest
    → returns container_id, stored in session
    ↓
Agents call executor.run(command, timeout)
    → streams stdout/stderr in real time
    → stores output to /work/{agent}_{tool}_{timestamp}.txt
    ↓
Engagement ends / user stops
    ↓
DockerManager.stop_container(container_id)
    → container stopped but NOT removed (evidence preserved)
    → artifacts remain in ./work/ volume mount
```

---

## Files

```
docker/
├── Dockerfile          # Container image definition
├── entrypoint.sh       # Startup: VPN setup (CTF mode), permissions
└── tools/
    └── install.sh      # Tool installation script (called during build)
```

---

## Dockerfile

```dockerfile
FROM kalilinux/kali-rolling

# Avoid interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# System update + base packages
RUN apt-get update && apt-get install -y \
    # Core utilities
    curl wget git vim jq tmux sudo \
    # Network tools
    nmap masscan netcat-traditional socat tcpdump tshark \
    whois dnsutils net-tools iputils-ping \
    # VPN (CTF mode)
    openvpn \
    # Web tools
    nikto sqlmap \
    # Network exploit tools
    metasploit-framework exploitdb \
    # OSINT tools
    recon-ng \
    # AD tools
    ldap-utils \
    # Coder Agent tools
    gcc pwntools \
    # Dev
    python3 python3-pip python3-venv pipx golang-go \
    # Wordlists
    seclists \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Go-based tools (installed as binaries)
RUN go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ropnop/kerbrute@latest
ENV PATH="/root/go/bin:${PATH}"

# Python-based tools (via pipx for isolation)
RUN pipx install crackmapexec && \
    pipx install bloodhound && \
    pipx install ldapdomaindump && \
    pipx install impacket && \
    pipx install evil-winrm 2>/dev/null || true  # Ruby-based, may fail
ENV PATH="/root/.local/bin:${PATH}"

# Feroxbuster (Rust binary)
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
    | bash -s /usr/local/bin

# theHarvester
RUN git clone https://github.com/laramies/theHarvester /opt/theHarvester && \
    pip3 install -r /opt/theHarvester/requirements/base.txt && \
    ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester

# amass
RUN go install -v github.com/owasp-amass/amass/v4/...@master@latest || \
    apt-get install -y amass

# LinPEAS / WinPEAS
RUN mkdir -p /opt/peas && \
    curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
    -o /opt/peas/linpeas.sh && chmod +x /opt/peas/linpeas.sh && \
    curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe \
    -o /opt/peas/winpeas.exe

# John the Ripper + Hashcat
RUN apt-get update && apt-get install -y john hashcat && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Working directory for artifacts
RUN mkdir -p /work /vpn
WORKDIR /work

# Non-root user with sudo (for tools that complain about root)
RUN useradd -m -s /bin/bash pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
```

---

## entrypoint.sh

```bash
#!/bin/bash
set -e

# CTF mode: connect VPN if ovpn file present
if [ -f /vpn/connection.ovpn ]; then
    echo "[*] Starting VPN connection..."
    openvpn --config /vpn/connection.ovpn --daemon --log /work/vpn.log
    sleep 5  # wait for VPN to establish
    echo "[*] VPN connected"
fi

# Update nuclei templates on start (silently)
nuclei -update-templates -silent 2>/dev/null || true

exec "$@"
```

---

## Docker Run Configuration

```python
# konr/container/manager.py

CONTAINER_CONFIG = {
    "image": "konr:latest",
    "cap_add": ["NET_RAW", "NET_ADMIN"],
    "devices": ["/dev/net/tun:/dev/net/tun"],   # CTF mode only
    "volumes": {
        "./work": {"bind": "/work", "mode": "rw"},
        "./vpn": {"bind": "/vpn", "mode": "ro"},  # CTF mode only
    },
    "network_mode": "host",        # agents need direct network access for scanning
    "detach": True,
    "remove": False,               # preserve for evidence review
}
```

### stop() vs remove()

`ContainerManager` separates stopping from removal to preserve evidence:

```python
def stop(self) -> None:
    """Stop the container. Container stays in 'exited' state — all files preserved."""
    container.stop(timeout=10)
    self._stopped_container = self._container  # keep reference
    self._container = None

def remove(self) -> None:
    """Explicitly remove the stopped container when evidence is no longer needed."""
    target = self._stopped_container or self._container
    target.remove(force=True)
    self._stopped_container = None
    self._container = None
```

`__exit__` (context manager) calls `stop()` only — never `remove()`. The CLI `finally` block calls `stop()` and leaves the container in `exited` state to preserve evidence. Artifacts in `./work/` persist via the volume mount regardless of container state.

---

## Command Executor

**File:** `pentest_ai/docker/executor.py`

```python
class ContainerExecutor:
    def __init__(self, container_id: str, work_dir: str = "/work"):
        self.container = docker_client.containers.get(container_id)
        self.work_dir = work_dir

    async def run(
        self,
        command: str,
        timeout: int = 300,           # 5 min default
        save_output: bool = True,
    ) -> ExecutionResult:
        """Execute command in container, stream output, optionally save to /work."""
        exec_id = self.container.client.api.exec_create(
            self.container.id,
            cmd=["bash", "-c", command],
            workdir=self.work_dir,
        )

        output_chunks = []
        async for chunk in self._stream_output(exec_id, timeout):
            output_chunks.append(chunk)
            await self.event_bus.emit(Event.TOOL_OUTPUT, chunk=chunk)

        full_output = "".join(output_chunks)
        exit_code = self.container.client.api.exec_inspect(exec_id)["ExitCode"]

        if save_output:
            filename = self._generate_filename(command)
            await self._save_to_work(filename, full_output)

        return ExecutionResult(
            output=full_output,
            exit_code=exit_code,
            success=exit_code == 0,
            output_file=filename if save_output else None,
        )

    def _generate_filename(self, command: str) -> str:
        tool = command.split()[0].split("/")[-1]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{tool}_{ts}.txt"
```

**Timeouts by tool type:**
| Tool Category | Default Timeout |
|---------------|----------------|
| Quick lookups (whois, dig) | 30s |
| Port scanning (nmap fast) | 5 min |
| Full port scan (nmap -p-) | 20 min |
| Brute force (ffuf, gobuster) | 10 min |
| Exploitation tools | 5 min |
| BloodHound collection | 10 min |

---

## Volume Mount Structure

```
./work/                          # host-side, persists after container stop
├── {engagement_id}/
│   ├── recon/
│   │   ├── nmap_20260508_123401.txt
│   │   ├── amass_20260508_123500.txt
│   │   └── theHarvester_20260508_123600.txt
│   ├── web/
│   │   ├── ffuf_20260508_124000.txt
│   │   └── sqlmap_20260508_124500.txt
│   ├── ad/
│   │   ├── bloodhound_20260508_125000.zip
│   │   └── ldapdomaindump_20260508_125100/
│   ├── postexploit/
│   │   └── linpeas_20260508_130000.txt
│   └── vpn.log                  # CTF mode only
├── reports/
│   └── {engagement_name}_{date}.md
└── findings.db                  # SQLite database (host-side)

./vpn/                           # CTF mode: VPN configs
└── connection.ovpn
```

---

## Image Build Process

```bash
# Build pentest container
docker build -t pentest-ai:latest -f docker/Dockerfile .

# Or via docker-compose
docker-compose build pentest-tools
```

Build time: ~15-25 minutes (large dependency set).
Image size: ~8-12 GB (Kali base + all tools).

---

## docker-compose.yml

```yaml
version: "3.9"

services:
  pentest-tools:
    build:
      context: .
      dockerfile: docker/Dockerfile
    image: pentest-ai:latest
    cap_add:
      - NET_RAW
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./work:/work
      - ./vpn:/vpn:ro
    network_mode: host
    # Container is started/stopped by ContainerManager — not run standalone
    profiles: ["tools"]           # won't start with plain `docker-compose up`
```

---

## Security Considerations

1. **Scope enforcement at agent level** — Docker has no knowledge of scope; agents check before calling `execute_command`
2. **Host network mode** — agents need direct network access for scanning; this is intentional and documented in the threat model. Do not run the container with `--network host` on a machine you don't own.
3. **Evidence preservation** — containers are stopped, not removed; full audit trail available post-engagement
4. **VPN isolation** — VPN traffic stays inside container; host network unaffected
5. **No credentials on container** — API keys, engagement data stored on host, never mounted into container
6. **Resource limits (optional)** — can add `mem_limit`, `cpus` constraints to prevent resource exhaustion from aggressive scans

---

## CTF Mode VPN Setup

```python
# DockerManager handles VPN in CTF mode
class DockerManager:
    def start_container(self, engagement_id: str, ctf_mode: bool = False, vpn_file: str = None):
        volumes = {"./work": {"bind": "/work", "mode": "rw"}}

        if ctf_mode and vpn_file:
            # Copy ovpn file to ./vpn/ dir
            shutil.copy(vpn_file, "./vpn/connection.ovpn")
            volumes["./vpn"] = {"bind": "/vpn", "mode": "ro"}

        container = self.client.containers.run(
            image="pentest-ai:latest",
            **CONTAINER_CONFIG,
            volumes=volumes,
            detach=True,
        )
        return container.id
```

VPN connection status check:
```bash
# Agent can verify VPN via:
ip route | grep tun0
curl -s https://ifconfig.me  # verify external IP is VPN endpoint
```
