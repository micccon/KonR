FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    TERM=dumb \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/share/metasploit-framework/tools/exploit"

# ── Base system ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git vim jq unzip p7zip-full \
    ncat socat tcpdump tshark iputils-ping net-tools dnsutils \
    python3 python3-pip python3-venv \
    golang \
    gcc g++ make \
    && rm -rf /var/lib/apt/lists/*

# ── OSINT ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    theharvester \
    recon-ng \
    amass \
    dnsrecon \
    whois \
    && rm -rf /var/lib/apt/lists/*

# ── Recon ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    subfinder \
    httpx-toolkit \
    && rm -rf /var/lib/apt/lists/*

# ── Web ───────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffuf \
    gobuster \
    feroxbuster \
    sqlmap \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# dalfox not in Kali apt — install from Go
RUN go install github.com/hahwul/dalfox/v2@latest \
    && mv /root/go/bin/dalfox /usr/local/bin/dalfox

# ── Network exploitation ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    metasploit-framework \
    exploitdb \
    nuclei \
    && rm -rf /var/lib/apt/lists/*

# ── Active Directory ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    impacket-scripts \
    crackmapexec \
    netexec \
    ldap-utils \
    smbclient \
    evil-winrm \
    && rm -rf /var/lib/apt/lists/*

# kerbrute not in Kali apt — install from GitHub releases
RUN curl -sL "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
    -o /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute

RUN pip3 install --no-cache-dir --break-system-packages bloodhound

# ── Post-exploitation ─────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    john \
    hashcat \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/privesc \
    && curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
       -o /opt/privesc/linpeas.sh \
    && curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" \
       -o /opt/privesc/winpeas.exe \
    && chmod +x /opt/privesc/linpeas.sh

RUN curl -sL "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
    -o /usr/local/bin/pspy && chmod +x /usr/local/bin/pspy

# ── Coder agent support ───────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages pwntools

# ── VPN support (CTF mode) ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────────────────────
RUN mkdir -p /work /vpn
WORKDIR /work

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
