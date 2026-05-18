# SIEM Platform - Makefile
# Usage: make <target>
# NOTE: Requires docker compose v2 (docker compose, not docker-compose)

.PHONY: up down build logs health clean shell-backend es-count kibana screenshots

up:
	docker compose up -d

build:
	docker compose up -d --build

down:
	docker compose down

clean:
	docker compose down -v
	@echo "⚠️  All volumes deleted — clean slate"

logs:
	docker compose logs -f

logs-backend:
	docker compose logs -f siem-backend log-generator

ps:
	docker compose ps

health:
	@curl -s http://localhost/health | python3 -m json.tool

shell-backend:
	docker compose exec siem-backend bash

shell-es:
	docker compose exec elasticsearch bash

es-count:
	@curl -s "http://localhost:9200/siem-logs-*/_count" | python3 -m json.tool

es-indices:
	@curl -s "http://localhost:9200/_cat/indices?v&s=index"

kibana:
	@echo "Opening Kibana..."
	@xdg-open http://localhost/kibana 2>/dev/null || open http://localhost/kibana

screenshots:
	@echo "Take screenshots of:"
	@echo "  http://localhost          → Dashboard"
	@echo "  http://localhost/logs.html    → Logs"
	@echo "  http://localhost/alerts.html  → Alerts"
	@echo "  http://localhost/rules.html   → Rules"
	@echo "  http://localhost/map.html     → Attack Map"
	@echo "  http://localhost/settings.html→ Settings"
