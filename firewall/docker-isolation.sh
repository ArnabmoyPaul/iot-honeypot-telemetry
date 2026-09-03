#!/bin/bash
# Additional Docker-level network isolation
# Complements iptables rules with Docker network policies

set -euo pipefail

NETWORK_NAME="honeynet"

echo "[+] Applying Docker network isolation policies..."

# Ensure network exists
docker network inspect $NETWORK_NAME >/dev/null 2>&1 || {
    echo "Error: Docker network '$NETWORK_NAME' not found. Run 'docker-compose up' first."
    exit 1
}

# Disable inter-container communication (except via explicit links)
# Note: This is handled by docker-compose network config, but we enforce here
docker network inspect $NETWORK_NAME --format '{{json .Options}}' | grep -q '"com.docker.network.bridge.enable_icc":"false"' || {
    echo "[!] Warning: ICC not disabled on honeynet. Consider recreating network with ICC=false."
}

# Verify no containers have --privileged flag
PRIVILEGED=$(docker ps --filter "label=project=honeypot" --format '{{.Names}}' | xargs -I{} docker inspect --format '{{.HostConfig.Privileged}}' {} 2>/dev/null | grep -c "true" || true)
if [ "$PRIVILEGED" -gt 0 ]; then
    echo "[!] WARNING: $PRIVILEGED container(s) running with --privileged. This is dangerous."
fi

# Check for exposed sensitive ports on 0.0.0.0
EXPOSED_ES=$(docker ps --format '{{.Ports}}' | grep -c "0.0.0.0:9200" || true)
if [ "$EXPOSED_ES" -gt 0 ]; then
    echo "[!] CRITICAL: Elasticsearch exposed on 0.0.0.0:9200. Restrict to localhost immediately!"
fi

EXPOSED_KIBANA=$(docker ps --format '{{.Ports}}' | grep -c "0.0.0.0:5601" || true)
if [ "$EXPOSED_KIBANA" -gt 0 ]; then
    echo "[!] WARNING: Kibana exposed on 0.0.0.0:5601. Should be localhost + SSH tunnel only."
fi

echo "[+] Docker isolation verification complete"
