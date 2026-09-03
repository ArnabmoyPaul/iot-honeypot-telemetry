.PHONY: help build up down logs test clean setup-host deception-score health

help:
	@echo "IoT Honeypot Telemetry Infrastructure"
	@echo ""
	@echo "Available targets:"
	@echo "  build          Build all Docker images"
	@echo "  up             Start all services"
	@echo "  down           Stop all services"
	@echo "  logs           Tail logs from all services"
	@echo "  test           Run test suite"
	@echo "  clean          Remove all containers, volumes, and images"
	@echo "  setup-host     Run host-level hardening (requires root)"
	@echo "  deception-score Run deception score evaluation"
	@echo "  health         Check service health status"

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Waiting for Elasticsearch to be ready..."
	@sleep 30
	@docker-compose exec -T elasticsearch curl -s -u elastic:$${ELASTIC_PASSWORD} http://localhost:9200/_cluster/health || echo "Elasticsearch not ready yet. Run 'make health' to check."

down:
	docker-compose down

logs:
	docker-compose logs -f

test:
	pytest tests/ -v

clean:
	docker-compose down -v --rmi all --remove-orphans
	rm -rf data/cowrie-logs/*.json data/dionaea-logs/*.json

setup-host:
	@echo "Run: sudo bash scripts/setup-host.sh"
	@echo "This script configures iptables, sysctl, and Docker daemon hardening."

deception-score:
	python3 scripts/deception-score.py

health:
	bash scripts/health-check.sh
