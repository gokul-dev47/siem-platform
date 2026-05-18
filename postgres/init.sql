-- SIEM Platform - PostgreSQL Schema
-- Author: Gokul

CREATE TABLE IF NOT EXISTS alerts (
    id           SERIAL PRIMARY KEY,
    alert_id     VARCHAR(32) UNIQUE NOT NULL,
    timestamp    TIMESTAMPTZ DEFAULT NOW(),
    severity     VARCHAR(20) NOT NULL,
    rule_name    VARCHAR(100),
    description  TEXT,
    source_ip    INET,
    count        INTEGER DEFAULT 1,
    status       VARCHAR(30) DEFAULT 'open',
    assigned_to  VARCHAR(100),
    notes        TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id         SERIAL PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    reason     TEXT,
    blocked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    blocked_by VARCHAR(100) DEFAULT 'siem-auto'
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         SERIAL PRIMARY KEY,
    timestamp  TIMESTAMPTZ DEFAULT NOW(),
    action     VARCHAR(100),
    actor      VARCHAR(100),
    resource   VARCHAR(200),
    details    JSONB
);

-- Insert some seed data so the app never shows empty
INSERT INTO alerts (alert_id, severity, rule_name, description, count, status) VALUES
  ('seed001', 'critical', 'SSH_BRUTE_FORCE', 'SSH brute force from 103.45.67.89 (23 attempts)', 23, 'open'),
  ('seed002', 'high',     'SQL_INJECTION',   'SQLi attempt on /api/v1/users from 185.234.21.4', 5, 'investigating'),
  ('seed003', 'high',     'PORT_SCAN',       'Port scan detected from 91.108.4.16 (67 ports)', 67, 'closed'),
  ('seed004', 'medium',   'XSS_ATTEMPT',     'XSS payload in POST /comment from 212.71.235.44', 3, 'open'),
  ('seed005', 'critical', 'RCE_ATTEMPT',     'RCE attempt via command injection on /api/exec', 1, 'open')
ON CONFLICT (alert_id) DO NOTHING;
