# IoT Honeypot Telemetry Infrastructure

> A containerized Cowrie + Dionaea honeypot deployment with an ELK telemetry pipeline, outbound containment via iptables, and a deception score to evaluate honeypot realism.

[![Docker](https://img.shields.io/badge/Docker-20.10%2B-blue)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-yellow)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## What this is

This repository deploys **Cowrie** (SSH/Telnet) and **Dionaea** (SMB/FTP/HTTP/MySQL/MQTT) honeypots in isolated Docker containers, ships their structured JSON logs through **Filebeat -> Logstash -> Elasticsearch -> Kibana**, and scores honeypot realism with a weighted **Deception Score** (banner, filesystem, latency, credentials).

Cowrie is configured to impersonate a Hikvision IP camera (dropbear banner, BusyBox/ARM filesystem, no default fake accounts), and Dionaea runs a custom MQTT handler to capture IoT botnet C2 traffic. All outbound traffic from the honeypot network is dropped by iptables so a compromised container cannot be used to attack anyone else.

This is Project 1 (data collection) of a related research series. Analysis of the collected logs lives in https://github.com/ArnabmoyPaul/attack-pattern-classifier.

## Repository layout

| Path | Contents |
|------|----------|
| `honeypots/cowrie/` | Cowrie config, userdb, Dockerfile, banner rotation script |
| `honeypots/dionaea/` | Dionaea config, Dockerfile, custom MQTT handler |
| `elk/` | Elasticsearch, Logstash, Kibana, Filebeat Dockerfiles, pipelines, and dashboards |
| `firewall/` | iptables containment rules and Docker network isolation checks |
| `scripts/` | Host setup, health check, and deception score calculator |
| `data/` | Mounted volumes for honeypot logs, Dionaea bistreams, and the GeoIP database |
| `docs/` | Architecture, deployment, security, and troubleshooting guides |
| `tests/` | pytest suite covering deception scoring, log parsing, dashboards, and iptables rules |
| `docker-compose.yml` | Defines the `honeynet` network and all six services |
| `Makefile` | `build`, `up`, `down`, `logs`, `test`, `clean`, `setup-host`, `deception-score`, `health` |
| `.env.example` | Required environment variables (passwords, ports, deception weights) |

## System design

Four isolation layers, from host to application:

```
LAYER 1: Host OS (Ubuntu 22.04) - iptables HONEYPOT-ISOLATION chain, userns-remap
LAYER 2: Docker network (honeynet, 172.20.0.0/24) - bridge, ICC disabled
LAYER 3: Container hardening - cap_drop: ALL, read_only, 512MB RAM / 1.0 CPU limits
LAYER 4: Application deception - dropbear banner, BusyBox filesystem, 50-200ms latency
```

Network topology:

```
Internet
   |
   | SSH(2222) / Telnet(2223) / SMB(445) / FTP(21) / HTTP(80) / MySQL(3306) / MQTT(1883)
   v
[EC2 / Oracle Cloud instance]
   |
   +-- iptables FORWARD rules: DROP outbound from 172.20.0.0/24 to the internet
   |
   v
[Docker bridge: honeynet 172.20.0.0/24]
   |
   +-- 172.20.0.10 Cowrie (SSH/Telnet honeypot)
   +-- 172.20.0.11 Dionaea (malware/payload honeypot)
   +-- 172.20.0.20 Filebeat (log shipper)
   +-- 172.20.0.30 Logstash (parser/enricher)
   +-- 172.20.0.40 Elasticsearch (storage)
   +-- 172.20.0.50 Kibana (localhost only, via SSH tunnel)
```

See `docs/ARCHITECTURE.md` for the full data flow and isolation strategy.

## Infrastructure stack

| Service | Role | Ports | Key modification |
|---------|------|-------|-------------------|
| Cowrie | SSH/Telnet emulation | 2222, 2223 | Hikvision camera persona, dropbear banner, fake accounts removed |
| Dionaea | Malware/payload capture | 445, 21, 80, 3306, 1883 | Custom MQTT handler for IoT botnet C2 |
| Filebeat | Log shipping | internal | Reads JSON logs from shared Docker volumes |
| Logstash | Parsing, GeoIP enrichment | internal | Grok/JSON parsing, builds the deception score fields |
| Elasticsearch | Storage and indexing | internal | Daily indices, 90 day retention via ILM |
| Kibana | Dashboards | 127.0.0.1:5601 | `attack-geo`, `cowrie-ssh`, `deception-score` dashboards in `elk/kibana/dashboards/` |

## Security controls

`firewall/iptables-rules.sh` sets default-deny policies and a `HONEYPOT-ISOLATION` chain that blocks all outbound traffic from `172.20.0.0/24` except internal Docker traffic, DNS to 8.8.8.8/8.8.4.4, and NTP. Dropped packets are logged with the `[HONEYPOT-ABUSE-BLOCK]` prefix. `firewall/docker-isolation.sh` additionally checks for privileged containers and services accidentally exposed on `0.0.0.0`.

Run `scripts/setup-host.sh` as root on a fresh Ubuntu 22.04 host to install Docker, apply kernel tuning, harden the Docker daemon, and apply the iptables rules.

Verify containment before exposing the honeypots to the internet:

```bash
docker exec -it cowrie curl https://google.com
# Expected: connection timeout or explicit DROP
```

## Deception score

`scripts/deception-score.py` scores honeypot realism across four weighted dimensions (weights configurable via `.env`):

```
score = 0.30 * banner + 0.30 * filesystem + 0.20 * latency + 0.20 * credentials
```

| Dimension | Weight | Realistic | Gives it away |
|-----------|--------|-----------|----------------|
| Banner | 0.30 | `dropbear_2016.74` | `SSH-2.0-Cowrie` |
| Filesystem | 0.30 | `/bin/busybox`, `/proc/cpuinfo` | `/cowrie`, `/opt/cowrie` |
| Latency | 0.20 | 50-300ms | under 10ms |
| Credentials | 0.20 | `root:123456`, `admin:admin` | `phil:123`, `richard:password` |

| Score | Risk | Expected behavior |
|-------|------|--------------------|
| 0.80-1.00 | LOW | Full engagement, command execution, payload download |
| 0.60-0.79 | MEDIUM | Partial engagement, basic recon |
| 0.40-0.59 | HIGH | Quick probe, possible fingerprinting |
| 0.00-0.39 | CRITICAL | Disconnects in under 1s, no telemetry |

Run it with `make deception-score`.

## Data collected

A deployment of this infrastructure collected 1,247,832 events across 89,456 sessions between January and March 2025. Analysis and clustering of that dataset lives in https://github.com/ArnabmoyPaul/attack-pattern-classifier, not in this repository.

## How to run

```bash
# Clone and configure environment
git clone https://github.com/ArnabmoyPaul/iot-honeypot-telemetry.git
cd iot-honeypot-telemetry
cp .env.example .env
# Edit .env: set ELASTIC_PASSWORD, KIBANA_PASSWORD, LOGSTASH_INTERNAL_PASSWORD, MAXMIND_LICENSE_KEY

# One-time host hardening (root, fresh Ubuntu 22.04 host)
sudo bash scripts/setup-host.sh
sudo reboot

# Build and start all services
make build
make up

# Check service health and realism
make health
make deception-score

# Access Kibana via SSH tunnel (it is bound to localhost only)
ssh -L 5601:localhost:5601 -N -f ubuntu@<instance-ip>
# then open http://localhost:5601

# Run the test suite
make test

# Tear everything down
make down      # stop containers
make clean     # stop, remove volumes/images, and clear local log data
```

Full deployment steps (cloud provider setup, security list rules, GeoIP database) are in `docs/DEPLOYMENT.md`. Common failure modes are in `docs/TROUBLESHOOTING.md`.

## Documentation

- `docs/ARCHITECTURE.md` - data flow, isolation strategy, deception score framework
- `docs/DEPLOYMENT.md` - cloud setup, environment configuration, verification steps
- `docs/SECURITY.md` - containment requirements, data retention, incident response, legal notes
- `docs/TROUBLESHOOTING.md` - fixes for common Elasticsearch, Cowrie, GeoIP, and iptables issues

## Background

- **"Long-Term Observations in an SSH Honeynet"** (IMC 2025) - default Cowrie accounts (`phil`, `richard`) trigger near-immediate attacker disconnection; informs the removed `userdb.txt` accounts and the credentials component of the deception score.
- **Q-Cowrie: An Adaptive Honeypot** (Springer, 2026) - adaptive deception improves attacker engagement duration; informs the dynamic banner rotation in `honeypots/cowrie/scripts/banner-mod.py`.

## Security and legal

Outbound containment (`firewall/iptables-rules.sh`) must be applied before exposing any honeypot to the internet. Use a dedicated cloud account, never a production one. See `docs/SECURITY.md` for data retention policy, responsible disclosure, and incident response steps.

**Disclaimer:** This software is intended for authorized security research only. Users are responsible for compliance with applicable laws and their cloud provider's acceptable use policy.

## License

MIT License. See [LICENSE](LICENSE) for details.
