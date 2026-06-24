# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-06-24

### Added
- Initial release of SIEM Platform
- Real-time threat detection using ELK Stack (Elasticsearch, Logstash, Kibana)
- Flask backend with WebSocket (Socket.IO) for live alert streaming
- 8 detection rules: SSH Brute Force, RCE, SQLi, Port Scan, Auth Spray, XSS, Dir Traversal, Suspicious UA
- Log generator simulating OWASP Top 10 attack patterns
- Frontend dashboard with Chart.js visualizations and attack map
- PostgreSQL schema for alerts, blocked IPs, and audit log
- Redis caching for rule counters
- Nginx reverse proxy with rate limiting
- Docker Compose setup with health checks for all 8 services
- GitHub Actions CI/CD pipeline
- Slack webhook integration for critical alerts
