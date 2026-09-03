#!/bin/bash
# Host-level hardening & environment setup for Ubuntu 22.04
# Run as root on fresh EC2/Oracle Cloud instance

set -euo pipefail

LOG_FILE="/var/log/honeypot-setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[$(date)] Starting honeypot host setup..."

# --- 1. System Updates ---
echo "[+] Updating system packages..."
apt-get update && apt-get upgrade -y

# --- 2. Docker Installation (Official Repo) ---
echo "[+] Installing Docker..."
apt-get install -y ca-certificates curl gnupg lsb-release
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

usermod -aG docker "${SUDO_USER:-$USER}"

# --- 3. Utilities ---
echo "[+] Installing utilities..."
apt-get install -y iptables-persistent net-tools jq python3-pip git htop tree nmap

# --- 4. Directory Structure ---
echo "[+] Creating data directories..."
mkdir -p /opt/honeypot/{data/{cowrie-logs,dionaea-logs,dionaea-bistreams,geoip},firewall,scripts}
chmod 755 -R /opt/honeypot/data

# --- 5. GeoIP Database ---
echo "[+] GeoIP setup..."
echo "NOTE: Place GeoLite2-City.mmdb in /opt/honeypot/data/geoip/"
echo "      Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"

# --- 6. Kernel Tuning ---
echo "[+] Applying kernel tuning for high-connection workloads..."
cat >> /etc/sysctl.conf << 'EOF'
# Honeypot connection tuning
net.ipv4.ip_local_port_range = 1024 65535
net.netfilter.nf_conntrack_max = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
EOF
sysctl -p

# --- 7. IP Forwarding (required for Docker) ---
echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# --- 8. Docker Daemon Hardening ---
echo "[+] Hardening Docker daemon..."
cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "default",
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-address-pools": [
    {
      "base": "172.20.0.0/16",
      "size": 24
    }
  ]
}
EOF
systemctl restart docker

# --- 9. iptables Rules (Critical Safety) ---
echo "[+] Applying iptables containment rules..."
bash "$(dirname "$0")/../firewall/iptables-rules.sh"

# --- 10. Python Dependencies ---
echo "[+] Installing Python dependencies..."
pip3 install -r "$(dirname "$0")/../requirements.txt"

echo "[$(date)] Host setup complete. Reboot recommended."
echo ""
echo "NEXT STEPS:"
echo "  1. Reboot the system: sudo reboot"
echo "  2. Copy .env.example to .env and fill in passwords"
echo "  3. Download GeoLite2-City.mmdb to data/geoip/"
echo "  4. Run: make build && make up"
