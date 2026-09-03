#!/bin/bash
# Health check script for all honeypot telemetry services

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SERVICES=("cowrie" "dionaea" "elasticsearch" "logstash" "kibana" "filebeat")
FAILED=0

echo "=========================================="
echo "  Honeypot Telemetry Health Check"
echo "=========================================="
echo ""

for svc in "${SERVICES[@]}"; do
    status=$(docker inspect --format='{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
    health=$(docker inspect --format='{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "N/A")

    if [ "$status" == "running" ]; then
        if [ "$health" == "N/A" ] || [ "$health" == "healthy" ]; then
            echo -e "${GREEN}[OK]${NC}   $svc is running (health: $health)"
        else
            echo -e "${YELLOW}[WARN]${NC} $svc is running but health=$health"
            ((FAILED++))
        fi
    else
        echo -e "${RED}[FAIL]${NC} $svc is $status"
        ((FAILED++))
    fi
done

echo ""
echo "------------------------------------------"

# Check disk usage
disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$disk_usage" -gt 80 ]; then
    echo -e "${YELLOW}[WARN]${NC} Disk usage: ${disk_usage}%"
else
    echo -e "${GREEN}[OK]${NC}   Disk usage: ${disk_usage}%"
fi

# Check honeypot log generation
cowrie_logs=$(find data/cowrie-logs -name '*.json' -mmin -60 2>/dev/null | wc -l)
dionaea_logs=$(find data/dionaea-logs -name '*.json' -mmin -60 2>/dev/null | wc -l)

if [ "$cowrie_logs" -gt 0 ] || [ "$dionaea_logs" -gt 0 ]; then
    echo -e "${GREEN}[OK]${NC}   Recent logs: Cowrie=$cowrie_logs, Dionaea=$dionaea_logs (last 60min)"
else
    echo -e "${YELLOW}[WARN]${NC} No recent logs detected (may be normal for low-traffic periods)"
fi

# Check Elasticsearch index count
es_indices=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200/_cat/indices/honeypot-* 2>/dev/null | wc -l)
if [ "$es_indices" -gt 0 ]; then
    echo -e "${GREEN}[OK]${NC}   Elasticsearch indices: $es_indices"
else
    echo -e "${YELLOW}[WARN]${NC} No honeypot indices in Elasticsearch"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All services healthy.${NC}"
    exit 0
else
    echo -e "${RED}$FAILED service(s) have issues.${NC}"
    exit 1
fi
