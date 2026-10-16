CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, file_name TEXT, size INTEGER, format TEXT, records INTEGER,
  status TEXT, created_at INTEGER, analyzed_at INTEGER, security_score INTEGER, ai_available INTEGER, anomalies INTEGER);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, ts INTEGER, ip TEXT, username TEXT, method TEXT,
  url TEXT, status INTEGER, port INTEGER, result TEXT, raw TEXT);
CREATE TABLE IF NOT EXISTS threats(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, ts INTEGER, ip TEXT, type TEXT, severity TEXT,
  confidence REAL, score INTEGER, reason TEXT, status TEXT, factors TEXT);
CREATE TABLE IF NOT EXISTS ip_statistics(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, ip TEXT, requests INTEGER, failed_logins INTEGER,
  successful_logins INTEGER, unique_ports INTEGER, unique_urls INTEGER, threat_count INTEGER, risk_score INTEGER,
  anomaly INTEGER, anomaly_score REAL, ai_reason TEXT, status TEXT);
CREATE INDEX IF NOT EXISTS idx_logs_s ON logs(session_id, ip);
CREATE INDEX IF NOT EXISTS idx_threats_s ON threats(session_id);
