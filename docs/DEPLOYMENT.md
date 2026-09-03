# Deployment Guide

## Prerequisites

- Cloud account (AWS EC2 or Oracle Cloud Free Tier)
- Domain knowledge: Docker, Linux networking, basic cybersecurity concepts
- Free MaxMind GeoLite2 account for GeoIP database

## Recommended: Oracle Cloud Free Tier

Oracle Cloud provides always-free ARM instances (4 OCPUs, 24GB RAM) sufficient for the full stack.

### Step 1: Create Instance
1. Sign up at [cloud.oracle.com](https://cloud.oracle.com)
2. Launch VM.Standard.A1.Flex instance
3. Select 2 OCPUs, 12GB RAM
4. Ubuntu 22.04 image, 100GB boot volume
5. Generate SSH key pair

### Step 2: Configure Security List
1. Navigate to Virtual Cloud Network -> Security Lists
2. Add ingress rules for:
   - TCP 2222 (Cowrie SSH)
   - TCP 2223 (Cowrie Telnet)
   - TCP 445 (Dionaea SMB)
   - TCP 21 (Dionaea FTP)
   - TCP 80 (Dionaea HTTP)
   - TCP 3306 (Dionaea MySQL)
   - TCP 1883 (Dionaea MQTT)
   - TCP 22 (Management SSH - restrict to your IP)

### Step 3: Host Setup
```bash
# SSH into instance
ssh -i ~/.ssh/your-key ubuntu@<instance-ip>

# Clone repository
git clone https://github.com/yourusername/iot-honeypot-telemetry.git
cd iot-honeypot-telemetry

# Run setup script
sudo bash scripts/setup-host.sh

# Reboot
sudo reboot
```

### Step 4: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit with your values
nano .env
# Set strong passwords for ELASTIC_PASSWORD, KIBANA_PASSWORD
# Set MAXMIND_LICENSE_KEY (get from maxmind.com)
```

### Step 5: Download GeoIP Database
```bash
# Place GeoLite2-City.mmdb in data/geoip/
# Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
```

### Step 6: Build and Launch
```bash
make build
make up
```

### Step 7: Verify Deployment
```bash
make health
# Or manually:
docker-compose ps
docker logs cowrie
docker logs dionaea
```

### Step 8: Access Kibana (Secure Tunnel)
```bash
# From your local machine
ssh -L 5601:localhost:5601 -N -f ubuntu@<instance-ip>
# Open browser: http://localhost:5601
```

### Step 9: Run Deception Score Check
```bash
make deception-score
# Or directly:
python3 scripts/deception-score.py
```

## AWS Deployment (Not Recommended for Budget-Constrained Users)

If using AWS:
1. Use `t2.micro` (free tier) but expect performance issues
2. Do NOT run full ELK stack - use Grafana Cloud free tier instead
3. Set billing alerts at $0.01, $0.50, $1.00
4. Monitor AWS Cost Explorer daily
5. Use dedicated AWS account (never production account)

## Post-Deployment Monitoring

- Check `scripts/health-check.sh` daily
- Review Kibana dashboards for attack patterns
- Monitor deception score trends
- Archive old logs to S3 (if using AWS) or local storage
- Rotate SSH keys monthly
