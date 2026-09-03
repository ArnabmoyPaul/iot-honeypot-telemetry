#!/bin/bash
# CRITICAL SAFETY: Outbound containment rules for honeypot infrastructure
# Prevents compromised containers from attacking the internet
# Based on: IMC 2025 research on cloud honeypot abuse prevention

set -euo pipefail

# Docker honeynet subnet
HONEYNET="172.20.0.0/24"
# Host public interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

echo "[+] Configuring iptables containment rules on interface: $IFACE"

# Flush existing rules (be careful if running remotely!)
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# --- INPUT CHAIN ---
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
# Allow SSH to host (management) - CHANGE THIS PORT IF NEEDED
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
# Allow honeypot ports from internet
iptables -A INPUT -p tcp -m multiport --dports 2222,2223,445,21,80,3306,1883 -j ACCEPT
# Allow ICMP (ping) for basic connectivity tests
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "[HONEYPOT-INPUT-DROP] " --log-level 4
iptables -A INPUT -j DROP

# --- FORWARD CHAIN ---
# Block all forwarding by default
iptables -A FORWARD -j DROP

# --- OUTPUT CHAIN (Host) ---
# Allow all outbound from host itself (for updates, management)
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow NTP (time sync)
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
# Allow DNS to specific servers only
iptables -A OUTPUT -p udp --dport 53 -d 8.8.8.8 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -d 8.8.4.4 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d 8.8.8.8 -j ACCEPT
# Allow HTTPS for package updates, Docker pulls
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
# Allow HTTP for emergency (prefer HTTPS)
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
# Log and drop all other outbound
iptables -A OUTPUT -j LOG --log-prefix "[HONEYPOT-OUTPUT-DROP] " --log-level 4
iptables -A OUTPUT -j DROP

# --- DOCKER-ISOLATION CHAIN ---
# Create custom chain for Docker container isolation
iptables -N HONEYPOT-ISOLATION 2>/dev/null || iptables -F HONEYPOT-ISOLATION

# Allow Docker internal communication
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d $HONEYNET -j ACCEPT

# Allow containers to reach Elasticsearch (internal)
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 172.20.0.40 -p tcp --dport 9200 -j ACCEPT

# Allow containers to reach Logstash (internal)
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 172.20.0.30 -p tcp --dport 5044 -j ACCEPT

# Allow containers to reach Kibana (internal, tunneled)
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 172.20.0.50 -p tcp --dport 5601 -j ACCEPT

# Allow DNS queries (to Google DNS only)
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 8.8.8.8 -p udp --dport 53 -j ACCEPT
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 8.8.4.4 -p udp --dport 53 -j ACCEPT

# Allow NTP (time sync)
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -p udp --dport 123 -j ACCEPT

# BLOCK ALL OTHER OUTBOUND FROM HONEYPOT NETWORK
# This prevents compromised containers from scanning/attacking the internet
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 0.0.0.0/0 -j LOG --log-prefix "[HONEYPOT-ABUSE-BLOCK] " --log-level 4
iptables -A HONEYPOT-ISOLATION -s $HONEYNET -d 0.0.0.0/0 -j DROP

# Apply isolation chain to FORWARD
iptables -A FORWARD -s $HONEYNET -j HONEYPOT-ISOLATION
iptables -A FORWARD -d $HONEYNET -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save rules for persistence
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
    echo "[+] Rules saved via netfilter-persistent"
elif command -v iptables-save &> /dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo "[+] Rules saved to /etc/iptables/rules.v4"
fi

echo "[+] iptables containment configured successfully"
echo ""
echo "VERIFICATION:"
echo "  - Honeypot containers CANNOT reach the general internet"
echo "  - Honeypot containers CAN communicate with ELK stack internally"
echo "  - Host CAN reach internet for updates and management"
echo "  - All dropped packets are logged for audit"
echo ""
echo "CRITICAL: Test rules before disconnecting SSH session!"
