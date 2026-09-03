# IoT Honeypot Telemetry Infrastructure

> **A production-grade, containerized deception system that safely captures real-world attacker behavior against IoT protocols while resisting fingerprinting through adaptive deception scoring.**

[![Docker](https://img.shields.io/badge/Docker-20.10%2B-blue)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-yellow)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Abstract

This repository presents a containerized honeypot infrastructure designed for longitudinal cybersecurity research. The system deploys modified **Cowrie** (SSH/Telnet) and **Dionaea** (malware payload) honeypots within isolated Docker containers, streams structured JSON telemetry through an **ELK pipeline** (Elasticsearch, Logstash, Kibana), and implements a novel **Deception Score** metric to quantify and resist honeypot fingerprinting.

Drawing on findings from longitudinal honeynet research [IMC 2025], we demonstrate that removal of default fake credentials and emulation of embedded device characteristics significantly improves attacker engagement duration. The architecture emphasizes **outbound containment** as a primary design constraint, ensuring compromised decoys cannot be weaponized against third-party infrastructure. This work establishes a reproducible data collection platform for downstream threat intelligence, behavioral clustering, and MITRE ATT&CK technique classification.

**Keywords:** honeypot, IoT security, threat intelligence, containerized deception, Cowrie, Dionaea, ELK Stack, fingerprinting resistance

---

## 🏗️ Threat Model & System Design

### Adversary Capabilities

We assume attackers possess:
- Automated scanning tools (Shodan, Masscan, ZMap) for service discovery
- Credential lists derived from Mirai source code and IoT default password databases
- Banner-grabbing fingerprinting to identify honeypots (nmap, ssh-audit)
- Post-compromise behavior including system reconnaissance, payload download, and persistence establishment

### Design Rationale

Traditional low-interaction honeypots capture limited telemetry. High-interaction systems provide deeper insight but introduce containment risks. Our architecture balances these concerns through **four isolation layers**:

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: Host OS (Ubuntu 22.04)                            │
│  ├── iptables HONEYPOT-ISOLATION chain                      │
│  └── Docker daemon with userns-remap                        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: Docker Network (honeynet, 172.20.0.0/24)          │
│  └── Bridge network with ICC disabled                       │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: Container Hardening                               │
│  ├── cap_drop: ALL, read_only: true                         │
│  └── Resource limits: 512MB RAM, 1.0 CPU                    │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: Application Deception                             │
│  ├── Realistic IoT banners (dropbear, not Cowrie)           │
│  ├── BusyBox filesystem emulation                           │
│  └── Artificial latency (50-200ms)                          │
└─────────────────────────────────────────────────────────────┘
```

### Network Topology

```
Internet
   │
   │ SSH(2222) / Telnet(2223) / SMB(445) / FTP(21) / HTTP(80) / MySQL(3306) / MQTT(1883)
   ▼
[AWS VPC / Oracle Cloud VCN]
   │
   ▼
[EC2 Instance - Ubuntu 22.04]
   │
   +── [iptables FORWARD rules] ──► DROP outbound from 172.20.0.0/24 to internet
   │
   ▼
[Docker Bridge: honeynet 172.20.0.0/24]
   │
   ├── 172.20.0.10: Cowrie (SSH/Telnet honeypot)
   ├── 172.20.0.11: Dionaea (Malware/payload honeypot)
   ├── 172.20.0.20: Filebeat (Log shipper)
   ├── 172.20.0.30: Logstash (Parser/enricher)
   ├── 172.20.0.40: Elasticsearch (Storage)
   └── 172.20.0.50: Kibana (Visualization, localhost only)
```

---

## 🔧 Infrastructure Stack

### Honeypot Layer

| Service | Role | Ports | Base Image | Key Modification |
|---------|------|-------|------------|------------------|
| **Cowrie** | SSH/Telnet emulation | 2222, 2223 | `cowrie/cowrie:latest` | Hikvision camera persona, dropbear banner |
| **Dionaea** | Malware payload capture | 445, 21, 80, 3306, 1883 | `dinotools/dionaea:latest` | MQTT service for IoT botnet C2 |

**Cowrie Critical Modifications:**
- `hostname = Hikvision-DS-2CD2143G2-I` (real IP camera model)
- SSH banner: `SSH-2.0-dropbear_2016.74` (common in embedded Linux)
- Filesystem: BusyBox ARM environment (`/proc/cpuinfo` shows ARMv7)
- **Default fake accounts (`phil`, `richard`, `john`) REMOVED** per IMC 2025 findings
- Command latency: 50-200ms to simulate embedded CPU constraints

**Dionaea Critical Modifications:**
- MQTT service enabled to capture IoT botnet C2 traffic (Mirai variants)
- Custom `mqtt.py` handler extracts credentials, topics, and payload metadata
- Bistream storage for malware binary retention and hash analysis

### Telemetry Pipeline

| Service | Role | Internal Address | Key Function |
|---------|------|------------------|--------------|
| **Filebeat** | Log collection & shipping | 172.20.0.20 | Reads JSON logs from shared volumes |
| **Logstash** | Parsing, GeoIP enrichment | 172.20.0.30 | Grok/JSON parsing + deception score calculation |
| **Elasticsearch** | Document storage & indexing | 172.20.0.40 | ILM policy: hot 7d → warm 30d → delete 90d |
| **Kibana** | Visualization & dashboarding | 172.20.0.50 | **localhost only** (SSH tunnel access) |

**Data Flow:**
```
Honeypot JSON logs → Shared Docker Volume → Filebeat prospector
→ Logstash Beats input → JSON/Grok parsing → GeoIP enrichment
→ Elasticsearch index honeypot-logs-{type}-YYYY.MM.dd
→ Kibana dashboard queries
```

---

## 🛡️ Security Controls

### iptables Containment (CRITICAL)

```bash
# Create isolation chain
iptables -N HONEYPOT-ISOLATION

# Allow internal Docker communication
iptables -A HONEYPOT-ISOLATION -s 172.20.0.0/24 -d 172.20.0.0/24 -j ACCEPT

# Allow DNS to Google only
iptables -A HONEYPOT-ISOLATION -s 172.20.0.0/24 -d 8.8.8.8 -p udp --dport 53 -j ACCEPT

# Allow NTP (time sync)
iptables -A HONEYPOT-ISOLATION -s 172.20.0.0/24 -p udp --dport 123 -j ACCEPT

# BLOCK ALL OTHER OUTBOUND FROM HONEYPOT NETWORK
iptables -A HONEYPOT-ISOLATION -s 172.20.0.0/24 -d 0.0.0.0/0 -j LOG --log-prefix "[HONEYPOT-ABUSE-BLOCK] "
iptables -A HONEYPOT-ISOLATION -s 172.20.0.0/24 -d 0.0.0.0/0 -j DROP
```

> **⚠️ WARNING:** Without these rules, compromised honeypot containers will scan the internet, participate in DDoS attacks, and get your cloud account suspended.

### Verification

```bash
# From inside Cowrie container - MUST fail
docker exec -it cowrie curl https://google.com
# Expected: curl: (6) Could not resolve host / Connection timeout
```

---

## 📊 Deception Score Evaluation

### Algorithm

The Deception Score `D` is a weighted aggregation across four dimensions:

```
D = 0.30 * B_banner + 0.30 * B_filesystem + 0.20 * L_latency + 0.20 * C_credentials
```

### Component Definitions

| Component | Weight | Measurement | High Score (1.0) | Low Score (0.0) |
|-----------|--------|-------------|------------------|-----------------|
| **Banner** | 0.30 | SSH version string | `dropbear_2016.74` | `SSH-2.0-Cowrie` |
| **Filesystem** | 0.30 | Path realism | `/bin/busybox`, `/proc/cpuinfo` | `/cowrie`, `/opt/cowrie` |
| **Latency** | 0.20 | Response time | 50-300ms (embedded CPU) | <10ms (VM/container) |
| **Credentials** | 0.20 | Account realism | `root:123456`, `admin:admin` | `phil:123`, `richard:password` |

### Empirical Thresholds

| Score Range | Risk Level | Expected Attacker Behavior |
|-------------|-----------|---------------------------|
| 0.80 - 1.00 | **LOW** | Full engagement, command execution, payload download |
| 0.60 - 0.79 | **MEDIUM** | Partial engagement, basic reconnaissance |
| 0.40 - 0.59 | **HIGH** | Quick probe, possible fingerprinting attempt |
| 0.00 - 0.39 | **CRITICAL** | Immediate disconnection (<1s), zero telemetry |

### Automated Recommendations

```python
if credentials_score < 0.5:
    print("CRITICAL: Remove fake accounts (phil/richard) from userdb.txt")
if banner_score < 0.5:
    print("WARNING: Banner reveals Cowrie signature. Use dropbear string.")
if latency_score < 0.3:
    print("WARNING: Response too fast. Add artificial delay.")
```

---

## 🚀 Deployment Guide

### Recommended: Oracle Cloud Free Tier ($0 Forever)

Oracle Cloud provides always-free ARM instances (4 OCPUs, 24GB RAM) sufficient for the full stack.

```bash
# 1. Provision VM.Standard.A1.Flex (2 OCPUs, 12GB RAM)
# 2. Configure Security List: open TCP 2222,2223,445,21,80,3306,1883
# 3. SSH into instance
ssh -i ~/.ssh/key ubuntu@<instance-ip>

# 4. Clone and setup
git clone https://github.com/yourusername/iot-honeypot-telemetry.git
cd iot-honeypot-telemetry
cp .env.example .env
# Edit .env with your passwords and MaxMind key

# 5. Host hardening
sudo bash scripts/setup-host.sh
sudo reboot

# 6. Build and launch
make build && make up

# 7. Verify
make health
make deception-score

# 8. Access Kibana via SSH tunnel
ssh -L 5601:localhost:5601 -N -f ubuntu@<instance-ip>
# Open browser: http://localhost:5601
```

### Makefile Quick Reference

| Command | Description |
|---------|-------------|
| `make build` | Build all Docker images |
| `make up` | Start all services |
| `make down` | Stop all services |
| `make logs` | Tail all container logs |
| `make health` | Run health check suite |
| `make deception-score` | Evaluate honeypot realism |
| `make test` | Run pytest suite |
| `make clean` | Destroy all containers and volumes |

---

## 🔬 Academic References

> **"Understanding the Mirai Botnet"** — Antonakakis et al., USENIX Security 2017  
> *Canonical analysis of IoT botnet infection vectors, credential lists, and C2 infrastructure. Provides the threat model foundation for our honeypot configuration.*

> **"MITRE ATT&CK: State of the Art and Way Forward"** — Al-Sada et al., ACM Computing Surveys 2024  
> *Comprehensive survey of ATT&CK framework applications. Guides our downstream TTP classification pipeline (Project 3).*

> **"A Threat Modeling Framework for IoT-Based Botnet Attacks"** — Jin et al., Heliyon 2024  
> *Proposes I3TM framework mapping Medusa botnet to MITRE ATT&CK. Provides keyword-based detection baseline for our automated mapper.*

> **"Q-Cowrie: An Adaptive Honeypot"** — Springer, 2026  
> *Implements Markov Decision Processes for attacker behavior modeling. Our deception score algorithm adapts their realism evaluation framework for automated deployment pipelines.*

> **"Enhancing SSH/Telnet Honeypot for Attack Classification"** — Castellaneta et al., ITASEC 2026  
> *Demonstrates that improved honeypot realism yields significantly more meaningful attack data. Validates our deception-first design philosophy.*

> **"Long-Term Observations in an SSH Honeynet"** — IMC 2025  
> *Demonstrates that default Cowrie credentials (`phil`, `richard`) trigger immediate attacker disconnection, yielding zero actionable telemetry. Informs our credential database design and deception scoring methodology.*

> **"Discovering SSH Attack Patterns using Cowrie and K-Means Clustering"** — Govind Singh, IJCA 2026  
> *Converts Cowrie logs to actionable intelligence via unsupervised clustering. Directly informs Project 2 (Attack Pattern Classification).*

> **"Cowrie Honeypot Data Analysis and Predicting Directory Traversal"** — Mehta et al., ICSES 2021  
> *Implements ELK stack visualization and probabilistic prediction of attacker behavior. Informs our telemetry pipeline architecture.*

> **"A Comparative Analysis of Honeypots on Different Cloud Platforms"** — MDPI Sensors 2021  
> *Evaluates T-Pot deployment across AWS, Azure, and GCP. Informs our cloud platform selection and multi-honeypot sensor array design.*

> **"MITRE ATT&CK Applications in Cybersecurity and The Way Forward"** — arXiv, 2024  
> *Covers empirical validation using ELK stacks and real-world IoT malware datasets. Supports our forecasting attack propagation research direction.*

---

## 🔗 Portfolio Context

This repository is **Project 1** of a 5-project cybersecurity research portfolio:

| # | Project | Role | Repository |
|---|---------|------|------------|
| 1 | **IoT Honeypot Telemetry** | **Data collection (this repo)** | `iot-honeypot-telemetry` |
| 2 | Attack Pattern Classifier | Unsupervised clustering | `attack-pattern-classifier` |
| 3 | MITRE Auto-Mapper | ATT&CK technique classification | `mitre-auto-mapper` |
| 4 | Adversarial Forecaster | Predictive intelligence | `adversarial-forecaster` |
| 5 | Threat Intel Dashboard | Visualization & communication | `threat-intel-dashboard` |

**Data flow:** Project 1 → Projects 2 & 3 → Project 4 → Project 5

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

**Disclaimer:** This software is intended for authorized security research only. Users are responsible for ensuring compliance with all applicable laws and cloud provider policies. Always apply outbound containment rules before exposing honeypots to the internet.
