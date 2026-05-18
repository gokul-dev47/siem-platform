# 🛡️ SIEM Platform

> A production-grade Security Information and Event Management (SIEM) system — portfolio project demonstrating blue team operations, ELK Stack, real-time threat detection, and DevSecOps.

---

## 📸 Screenshots

> Run the project, then take screenshots of each page and drop them in a `/screenshots` folder.

| Dashboard | Logs | Alerts |
|-----------|------|--------|
| ![Dashboard](screenshots/dashboard.png) | ![Logs](screenshots/logs.png) | ![Alerts](screenshots/alerts.png) |

| Rules | Attack Map | Settings |
|-------|-----------|----------|
| ![Rules](screenshots/rules.png) | ![Map](screenshots/map.png) | ![Settings](screenshots/settings.png) |

---

## 🚀 Quick Start (Ubuntu/Debian)

### Prerequisites

```bash
# Install Docker + Docker Compose
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git curl
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

### Run the Platform

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/siem-platform.git
cd siem-platform

# 2. Configure environment
cp .env.example .env
# Optional: add SLACK_WEBHOOK_URL to .env for Slack alerts

# 3. Start all services
docker compose up -d --build

# 4. Watch startup (Elasticsearch takes ~60-90 seconds)
docker compose logs -f elasticsearch siem-backend

# 5. Open in browser (once backend shows "SIEM Backend loaded")
open http://localhost          # Main dashboard
open http://localhost/health   # Service health JSON
open http://localhost/kibana   # Kibana (takes ~2 min)
```

### All Running? Here's What You'll See

```
$ docker compose ps

NAME                  STATUS          PORTS
siem-elasticsearch    Up (healthy)    0.0.0.0:9200->9200/tcp
siem-kibana           Up (healthy)    0.0.0.0:5601->5601/tcp
siem-logstash         Up (healthy)    0.0.0.0:5044->5044/tcp
siem-redis            Up (healthy)    0.0.0.0:6379->6379/tcp
siem-postgres         Up (healthy)    0.0.0.0:5432->5432/tcp
siem-backend          Up (healthy)    0.0.0.0:8000->8000/tcp
siem-log-generator    Up              (no ports, internal)
siem-nginx            Up (healthy)    0.0.0.0:80->80/tcp
```

---

## 🏗️ Architecture

```
                        ┌─────────────────────────────────────┐
                        │         Docker Network (172.20.x.x)  │
                        │                                       │
  Browser ──────────────▶  Nginx (80/443)                      │
                        │      │                                │
                        │      ├──▶ Flask Backend (:8000)       │
                        │      │        │                       │
                        │      │        ├──▶ Elasticsearch      │
                        │      │        ├──▶ Redis (alerts)     │
                        │      │        ├──▶ PostgreSQL         │
                        │      │        └──▶ Slack Webhook      │
                        │      │                                │
                        │      └──▶ Static Frontend (5 pages)  │
                        │                                       │
  Log Generator ────────────▶ Elasticsearch (direct ingest)    │
                        │      │                                │
  Logstash ─────────────────▶ Elasticsearch (Beats/TCP)        │
                        │                                       │
                        └─────────────────────────────────────┘
```

### Data Flow

1. **Log Generator** runs every 5 seconds, simulating SSH brute force, port scans, SQLi, XSS, LFI, RCE
2. Events are written directly to **Elasticsearch** (`siem-logs-YYYY.MM.DD` index)
3. Event counters are incremented in **Redis** (keyed by rule ID)
4. **Flask** APScheduler evaluates rules every 60s — if counter ≥ threshold → creates alert in **PostgreSQL**
5. Alert is broadcast via **Socket.IO WebSocket** to all connected browser clients
6. If `SLACK_WEBHOOK_URL` is set, a Slack notification is sent
7. **Kibana** connects to Elasticsearch for deep-dive analysis

---

## 📁 File Structure

```
siem-platform/
├── docker-compose.yml          # All 8 services with health checks
├── .env.example                # Environment variable template
├── .gitignore
├── README.md
│
├── backend/
│   ├── Dockerfile              # Python 3.11 + gunicorn/eventlet
│   ├── requirements.txt
│   ├── app.py                  # Flask + SocketIO + alerting engine
│   └── alert_rules.json        # 8 detection rules (configurable)
│
├── log-generator/
│   ├── Dockerfile
│   └── log_generator.py        # Simulates: SSH BF, SQLi, XSS, LFI, RCE, port scans
│
├── frontend/
│   ├── index.html              # Dashboard — stat widgets + 4 charts + live feed
│   ├── logs.html               # Searchable table with syntax highlighting
│   ├── alerts.html             # Card grid with status management
│   ├── rules.html              # Toggle + threshold editor per rule
│   ├── map.html                # Canvas attack map with animated arcs
│   ├── settings.html           # Health check + Slack/email config
│   ├── style.css               # Cyber Ops dark theme
│   └── dashboard.js            # WebSocket + Chart.js + easter egg (Ctrl+Shift+S)
│
├── logstash/
│   ├── pipeline/siem.conf      # TCP + Syslog + Beats input → ES output
│   └── config/logstash.yml
│
├── nginx/
│   └── nginx.conf              # Reverse proxy + rate limiting + WS upgrade
│
├── postgres/
│   └── init.sql                # Schema: alerts, blocked_ips, audit_log
│
└── .github/
    └── workflows/ci.yml        # GitHub Actions: lint + build on push
```

---

## 🔔 Slack Integration

1. Go to https://api.slack.com/apps → Create App → Incoming Webhooks
2. Enable Incoming Webhooks → Add New Webhook → choose channel
3. Copy the webhook URL
4. Add to `.env`:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
```

5. Restart backend:

```bash
docker compose restart siem-backend
```

Alert format sent to Slack:

```
🔴 SIEM ALERT [CRITICAL]
Rule:        SSH_BRUTE_FORCE
Severity:    critical
Count:       23
Description: SSH brute force from 103.45.67.89 (23 attempts in 60s)
```

---

## 🔎 Detection Rules

| Rule ID | Severity | Threshold | Window | Description |
|---------|----------|-----------|--------|-------------|
| SSH_BRUTE_FORCE | Critical | 5 | 60s | Failed SSH logins from same IP |
| RCE_ATTEMPT | Critical | 1 | 60s | Remote code execution payload detected |
| SQL_INJECTION | High | 1 | 60s | SQLi pattern in HTTP parameters |
| PORT_SCAN | High | 20 | 30s | SYN scan to multiple ports |
| AUTH_SPRAY | High | 15 | 300s | Multiple auth failures, different users |
| XSS_ATTEMPT | Medium | 3 | 60s | XSS payload in request |
| DIR_TRAVERSAL | Medium | 3 | 60s | Path traversal pattern |
| SUSPICIOUS_UA | Medium | 1 | 60s | sqlmap / nikto / nmap user-agent |

Edit `backend/alert_rules.json` and restart to change thresholds. Or use the Rules page in the UI.

---

## 🐳 Docker Commands Reference

```bash
# Start
docker compose up -d

# Build + start (after code changes)
docker compose up -d --build

# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f siem-backend
docker compose logs -f log-generator

# Check health
curl http://localhost/health | python3 -m json.tool

# Stop everything
docker compose down

# Stop + delete all data (clean slate)
docker compose down -v

# Restart one service
docker compose restart siem-backend

# Shell into backend
docker compose exec siem-backend bash

# Query Elasticsearch directly
curl http://localhost:9200/siem-logs-*/_count
curl http://localhost:9200/_cat/indices?v
```

---

## 📊 Kibana Setup (Optional Deep Dive)

1. Open http://localhost/kibana
2. Go to **Stack Management → Index Patterns**
3. Create pattern: `siem-logs-*`, time field: `@timestamp`
4. Go to **Discover** → select `siem-logs-*`
5. You'll see all events from the log generator

Suggested Kibana visualizations to add to your resume screenshots:
- Time series of events by severity
- Top 10 source IPs (Data Table)
- Attack type distribution (Pie chart)

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---------|-----|
| Elasticsearch won't start | Increase Docker memory to 4GB: Docker Desktop → Settings → Resources |
| "max virtual memory areas vm.max_map_count [65530] is too low" | `sudo sysctl -w vm.max_map_count=262144` |
| Backend keeps restarting | `docker compose logs siem-backend` — usually ES not ready yet, wait 60s |
| No data in dashboard | Check log-generator: `docker compose logs log-generator` |
| Port 80 in use | Change nginx ports in docker-compose.yml: `"8080:80"` |

---

## 🎯 Resume Value

This project demonstrates skills used in real security engineering roles at Indian product companies:

**Blue Team / SOC skills:**
- Log ingestion and normalization (ELK Stack — used at Razorpay, Flipkart, Swiggy)
- Real-time alerting with configurable thresholds
- OWASP Top 10 attack pattern detection (SQLi, XSS, LFI, RCE)
- Incident management workflow (Open → Investigating → Closed)

**DevSecOps skills:**
- Docker Compose with health checks and restart policies
- GitHub Actions CI/CD pipeline
- Nginx reverse proxy with rate limiting
- Service mesh with internal networking

**Development skills:**
- Python (Flask, APScheduler, Elasticsearch client)
- WebSocket real-time communication (Socket.IO)
- PostgreSQL schema design + Redis caching
- Vanilla JS + Chart.js data visualization

**Resume bullet point:**
> *Built a full-stack SIEM platform (ELK Stack + Flask + WebSocket) that ingests security logs, detects 8 attack patterns (SSH brute force, SQLi, XSS, RCE, port scans) with configurable thresholds, and delivers real-time alerts via WebSocket and Slack — containerized with Docker Compose and CI/CD via GitHub Actions.*

---

## 👤 Author

**Gokul** — Final Year CSE (Cybersecurity)  
Tamil Nadu, India  
Community: [nullchennai](https://nullchennai.in)

> *"Stay paranoid. Patch everything. Never trust user input."*

---

## 📝 License

MIT — use freely for learning and portfolio purposes.
