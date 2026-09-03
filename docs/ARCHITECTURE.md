# System Architecture

## Overview

The IoT Honeypot Telemetry Infrastructure is a containerized, high-interaction deception system designed to safely capture real-world attacker behavior against Internet-of-Things (IoT) protocols while preventing outbound abuse.

## Design Principles

1. **Containment First**: All honeypot containers are strictly isolated via iptables and Docker network policies to prevent compromised instances from attacking third parties.
2. **Realism Over Quantity**: A single realistic honeypot yields more actionable intelligence than ten easily fingerprinted decoys.
3. **Structured Telemetry**: All interactions are captured as structured JSON and streamed through an ELK pipeline for real-time analysis.
4. **Deception Scoring**: Continuous evaluation of honeypot realism to resist attacker fingerprinting.

## Network Topology

```
Internet
   |
   | SSH(2222) / Telnet(2223) / SMB(445) / FTP(21) / HTTP(80) / MySQL(3306) / MQTT(1883)
   v
[AWS VPC / Oracle Cloud VCN]
   |
   v
[EC2 Instance - Ubuntu 22.04]
   |
   +-- [iptables FORWARD rules] -- DROP outbound from 172.20.0.0/24 to internet
   |
   v
[Docker Bridge: honeynet 172.20.0.0/24]
   |
   +-- 172.20.0.10: Cowrie (SSH/Telnet honeypot)
   +-- 172.20.0.11: Dionaea (Malware/payload honeypot)
   +-- 172.20.0.20: Filebeat (Log shipper)
   +-- 172.20.0.30: Logstash (Parser/enricher)
   +-- 172.20.0.40: Elasticsearch (Storage)
   +-- 172.20.0.50: Kibana (Visualization, localhost only)
```

## Data Flow

1. **Attacker probes** public-facing ports (2222, 2223, 445, etc.)
2. **Honeypot captures** interaction as structured JSON event
3. **Filebeat reads** JSON log files from shared Docker volumes
4. **Logstash parses** events, applies GeoIP enrichment, calculates deception score
5. **Elasticsearch indexes** documents with daily rotation via ILM
6. **Kibana visualizes** attack patterns, geographic distribution, deception metrics

## Isolation Strategy

### Host-Level (iptables)
- `HONEYPOT-ISOLATION` chain blocks all outbound traffic from `172.20.0.0/24`
- Exceptions: internal Docker network, DNS (8.8.8.8 only), NTP
- All drops are logged with prefix `[HONEYPOT-ABUSE-BLOCK]`

### Container-Level (Docker)
- Honeypot containers run with `cap_drop: ALL` and `read_only: true`
- No `--privileged` containers permitted
- Resource limits: 512MB RAM, 1.0 CPU per honeypot
- User namespace remapping enabled

### Application-Level (Honeypot)
- Cowrie emulates BusyBox-based ARM IoT device (Hikvision camera)
- Default fake accounts (`phil`, `richard`) removed per IMC 2025 findings
- Artificial latency (50-200ms) simulates embedded CPU constraints
- Dynamic banner rotation resists consistent fingerprinting

## Deception Score Framework

Four dimensions evaluated on [0.0, 1.0] scale:

| Dimension | Weight | Measurement |
|-----------|--------|-------------|
| Banner | 0.30 | SSH version string matches real IoT device signatures |
| Filesystem | 0.30 | BusyBox paths present, honeypot artifacts absent |
| Latency | 0.20 | Response time in realistic embedded range (50-300ms) |
| Credentials | 0.20 | Realistic IoT defaults, no known fake accounts |

Score > 0.7: Low risk of fingerprinting  
Score 0.4-0.7: Medium risk  
Score < 0.4: High risk - attackers will disconnect immediately
