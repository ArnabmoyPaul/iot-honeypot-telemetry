#!/usr/bin/env python3
"""
Deception Score Calculator
============================
Measures how likely a honeypot is to be fingerprinted by attackers.
Score: 0.0 (obvious fake) -> 1.0 (indistinguishable from real device)

Based on research findings:
- IMC 2025: Default Cowrie credentials ('phil', 'richard') cause immediate 
  attacker disconnection, yielding zero telemetry.
- Q-Cowrie: Adaptive deception via Markov Decision Processes improves 
  engagement duration by 340%.

Usage:
    python3 scripts/deception-score.py
    python3 scripts/deception-score.py --config honeypots/cowrie/cowrie.cfg
"""

import json
import time
import socket
import argparse
import os
from pathlib import Path


class DeceptionScorer:
    """Evaluates honeypot realism across four dimensions."""

    # Known fake accounts that trigger immediate attacker disconnection
    KNOWN_FAKE_ACCOUNTS = [
        'phil', 'richard', 'john', 'fred', 'test', 'user',
        'cowrie', 'honeypot', 'fake', 'dummy'
    ]

    # Realistic IoT device SSH banners (dropbear, older OpenSSH)
    REAL_BANNERS = [
        'SSH-2.0-dropbear_2016.74',
        'SSH-2.0-dropbear_2020.81',
        'SSH-2.0-OpenSSH_7.4',
        'SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3',
        'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10'
    ]

    # Signatures that immediately reveal Cowrie
    FAKE_BANNERS = [
        'SSH-2.0-Cowrie',
        'SSH-2.0-libssh',
        'Cowrie'
    ]

    # Files expected on real BusyBox-based IoT devices
    REQUIRED_FS_PATHS = [
        '/proc/cpuinfo', '/proc/meminfo', '/etc/passwd',
        '/etc/init.d/', '/bin/busybox', '/tmp/', '/var/run/',
        '/dev/null', '/sys/class/net'
    ]

    # Paths that should NEVER exist (honeypot artifacts)
    FORBIDDEN_FS_PATHS = [
        '/cowrie', '/opt/cowrie', '/home/cowrie',
        '/usr/local/cowrie', '/var/log/cowrie'
    ]

    def __init__(self, config_path='honeypots/cowrie/cowrie.cfg',
                 weights=None):
        self.config_path = config_path
        self.weights = weights or {
            'banner': float(os.getenv('DECEPTION_BANNER_WEIGHT', 0.30)),
            'filesystem': float(os.getenv('DECEPTION_FS_WEIGHT', 0.30)),
            'latency': float(os.getenv('DECEPTION_LATENCY_WEIGHT', 0.20)),
            'credentials': float(os.getenv('DECEPTION_CREDENTIAL_WEIGHT', 0.20))
        }
        self._validate_weights()

    def _validate_weights(self):
        total = sum(self.weights.values())
        if not 0.99 <= total <= 1.01:
            raise ValueError(f"Weights must sum to 1.0, got {total}")

    def score_banner(self, banner_text: str) -> float:
        """
        Evaluate SSH banner realism.
        Real IoT devices typically run dropbear or older OpenSSH.
        """
        score = 0.5  # neutral baseline

        if any(sig in banner_text for sig in self.REAL_BANNERS):
            score += 0.4
        if any(sig in banner_text for sig in self.FAKE_BANNERS):
            score -= 0.5

        # Bonus for specific device model strings
        if any(dev in banner_text for dev in ['Hikvision', 'Netgear', 'TP-Link',
                                                 'D-Link', 'Axis', 'Bosch']):
            score += 0.1

        return max(0.0, min(1.0, score))

    def score_filesystem(self, fs_root: str = '/opt/honeypot/data/cowrie-logs') -> float:
        """
        Check filesystem artifacts for honeypot leakage.
        Real IoT devices use BusyBox with limited command sets.
        """
        score = 0.5
        fs_path = Path(fs_root)

        # Check for required IoT paths
        found_required = sum(1 for p in self.REQUIRED_FS_PATHS
                            if (fs_path / p.lstrip('/')).exists())
        required_ratio = found_required / len(self.REQUIRED_FS_PATHS)
        score += required_ratio * 0.3

        # Penalize forbidden paths
        found_forbidden = sum(1 for p in self.FORBIDDEN_FS_PATHS
                             if (fs_path / p.lstrip('/')).exists())
        score -= found_forbidden * 0.25

        return max(0.0, min(1.0, score))

    def score_latency(self, host: str = 'localhost', port: int = 2222) -> float:
        """
        Measure SSH response latency.
        Real embedded IoT devices: 50-300ms (slow CPU, limited RAM)
        VMs/Containers: <10ms (too fast = suspicious)
        """
        try:
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            sock.close()
            latency_ms = (time.perf_counter() - start) * 1000

            if 50 <= latency_ms <= 300:
                return 1.0
            elif 20 <= latency_ms < 50:
                return 0.7
            elif 10 <= latency_ms < 20:
                return 0.4
            elif latency_ms < 10:
                return 0.1  # Too fast = VM/container
            else:
                return 0.5  # Unusual but not immediately suspicious
        except (socket.error, OSError):
            return 0.0  # Cannot connect

    def score_credentials(self, userdb_path: str = 'honeypots/cowrie/userdb.txt') -> float:
        """
        Check credential database for known fake accounts.
        IMC 2025 research shows 'phil'/'richard' cause <1s attacker retention.
        """
        score = 1.0
        path = Path(userdb_path)

        if not path.exists():
            return 0.0  # No credential file = completely unrealistic

        content = path.read_text().lower()

        # Heavy penalty per fake account found
        for fake in self.KNOWN_FAKE_ACCOUNTS:
            if fake in content:
                score -= 0.25

        # Bonus for realistic IoT default credentials
        iot_creds = ['root:123456', 'admin:admin', 'service:service',
                     'admin:password', 'root:root', 'guest:guest']
        for cred in iot_creds:
            if cred in content:
                score += 0.08

        return max(0.0, min(1.0, score))

    def calculate(self) -> dict:
        """Aggregate weighted deception score across all dimensions."""
        banner = self._get_banner()
        banner_score = self.score_banner(banner)
        fs_score = self.score_filesystem()
        latency_score = self.score_latency()
        cred_score = self.score_credentials()

        total = (
            banner_score * self.weights['banner'] +
            fs_score * self.weights['filesystem'] +
            latency_score * self.weights['latency'] +
            cred_score * self.weights['credentials']
        )

        return {
            'timestamp': time.time(),
            'overall_score': round(total, 3),
            'risk_level': self._risk_level(total),
            'components': {
                'banner': round(banner_score, 3),
                'filesystem': round(fs_score, 3),
                'latency': round(latency_score, 3),
                'credentials': round(cred_score, 3)
            },
            'weights': self.weights,
            'recommendations': self._generate_recommendations(
                banner_score, fs_score, latency_score, cred_score
            )
        }

    def _get_banner(self) -> str:
        """Read configured banner from cowrie.cfg or return default."""
        path = Path(self.config_path)
        if not path.exists():
            return "SSH-2.0-dropbear_2016.74"

        content = path.read_text()
        for line in content.splitlines():
            if 'ssh_version_string' in line or 'banner' in line.lower():
                return line.split('=')[-1].strip().strip('"'')
        return "SSH-2.0-dropbear_2016.74"

    def _risk_level(self, score: float) -> str:
        if score >= 0.8:
            return "LOW"
        elif score >= 0.6:
            return "MEDIUM"
        elif score >= 0.4:
            return "HIGH"
        else:
            return "CRITICAL"

    def _generate_recommendations(self, b: float, f: float, l: float, c: float) -> list:
        recs = []
        if c < 0.5:
            recs.append(
                "CRITICAL: Remove fake accounts (phil/richard) from userdb.txt. "
                "These trigger immediate attacker disconnection per IMC 2025 research."
            )
        if b < 0.5:
            recs.append(
                "WARNING: Banner reveals Cowrie signature. "
                "Use dropbear version string (e.g., SSH-2.0-dropbear_2016.74)."
            )
        if l < 0.3:
            recs.append(
                "WARNING: Response latency too fast (<10ms). "
                "Add artificial delay to simulate embedded CPU."
            )
        if f < 0.5:
            recs.append(
                "WARNING: Filesystem contains honeypot artifacts. "
                "Remove /cowrie paths and add BusyBox binaries."
            )
        if not recs:
            recs.append("OK: Honeypot configuration appears realistic.")
        return recs


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate honeypot deception realism score"
    )
    parser.add_argument(
        '--config', default='honeypots/cowrie/cowrie.cfg',
        help='Path to Cowrie configuration file'
    )
    parser.add_argument(
        '--output', default='-', choices=['-', 'json', 'elastic'],
        help='Output format (-=stdout, json=file, elastic=ES document)'
    )
    args = parser.parse_args()

    scorer = DeceptionScorer(config_path=args.config)
    result = scorer.calculate()

    if args.output == '-':
        print(json.dumps(result, indent=2))
    elif args.output == 'json':
        out_path = f"data/deception-score-{int(time.time())}.json"
        Path(out_path).write_text(json.dumps(result, indent=2))
        print(f"Saved to {out_path}")
    elif args.output == 'elastic':
        # Output newline-delimited JSON for Logstash/Elasticsearch
        print(json.dumps(result))


if __name__ == '__main__':
    main()
