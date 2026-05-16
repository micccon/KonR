CREATE TABLE IF NOT EXISTS engagements (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    client       TEXT,
    mode         TEXT NOT NULL DEFAULT 'pentest',
    target_scope TEXT NOT NULL,
    objectives   TEXT,
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    ip            TEXT NOT NULL,
    hostname      TEXT,
    os            TEXT,
    os_version    TEXT,
    role          TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, ip)
);

CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT,
    version      TEXT,
    banner       TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    host_id       INTEGER REFERENCES hosts(id),
    service_id    INTEGER REFERENCES services(id),
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    cvss          REAL,
    cve           TEXT,
    description   TEXT,
    evidence      TEXT,
    evidence_file TEXT,
    reproduction  TEXT,
    remediation   TEXT,
    status        TEXT NOT NULL DEFAULT 'confirmed',
    agent         TEXT,
    mitre_id      TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    host_id       INTEGER REFERENCES hosts(id),
    username      TEXT,
    secret        TEXT,
    secret_type   TEXT,
    domain        TEXT,
    access_level  TEXT,
    source_tool   TEXT,
    validity      TEXT NOT NULL DEFAULT 'unknown',
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
    title            TEXT NOT NULL,
    steps            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'identified',
    mitre_techniques TEXT,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS flags (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    flag_value    TEXT NOT NULL,
    flag_type     TEXT,
    context       TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approvals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    agent         TEXT NOT NULL,
    command       TEXT NOT NULL,
    reason        TEXT,
    risk_level    TEXT,
    decision      TEXT NOT NULL,
    modified_cmd  TEXT,
    user_note     TEXT,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS session_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
    agent         TEXT NOT NULL,
    action        TEXT NOT NULL,
    summary       TEXT,
    evidence_file TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_engagement     ON hosts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_services_host        ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_engagement     ON vulnerabilities(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity       ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_creds_engagement     ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_approvals_engagement ON approvals(engagement_id);
CREATE INDEX IF NOT EXISTS idx_log_engagement       ON session_log(engagement_id);
