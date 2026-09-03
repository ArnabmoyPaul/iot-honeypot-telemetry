#!/usr/bin/env python3
"""
Dynamic Banner Rotation Module for Cowrie Honeypot

Rotates SSH banners across a pool of realistic IoT device signatures
to resist banner-grabbing fingerprinting attacks.

Implements deception strategy from:
- IMC 2025: Attackers fingerprint honeypots via consistent banners
- Q-Cowrie: Adaptive deception increases engagement duration
"""

import random
import sys
from pathlib import Path

# Realistic IoT SSH banners (weighted by prevalence)
BANNER_POOL = [
    # Hikvision / DVR devices (high prevalence in Mirai targets)
    ("SSH-2.0-dropbear_2016.74", 0.25),
    ("SSH-2.0-dropbear_2020.81", 0.15),
    # Older routers
    ("SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7", 0.10),
    ("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", 0.10),
    # Embedded Linux devices
    ("SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3", 0.15),
    ("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10", 0.10),
    # BusyBox dropbear variants
    ("SSH-2.0-dropbear_2014.63", 0.08),
    ("SSH-2.0-dropbear_2019.78", 0.07),
]


def get_weighted_banner() -> str:
    """Select banner based on weighted probability distribution."""
    banners, weights = zip(*BANNER_POOL)
    return random.choices(banners, weights=weights, k=1)[0]


def update_cowrie_config(config_path: str, banner: str) -> None:
    """Update Cowrie configuration with new banner string."""
    path = Path(config_path)
    if not path.exists():
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)

    lines = path.read_text().splitlines()
    updated = []
    found = False

    for line in lines:
        if line.strip().startswith("version ="):
            updated.append(f"version = {banner}")
            found = True
        else:
            updated.append(line)

    if not found:
        # Insert into [ssh] section
        for i, line in enumerate(updated):
            if line.strip() == "[ssh]":
                updated.insert(i + 1, f"version = {banner}")
                break

    path.write_text("\n".join(updated) + "\n")
    print(f"Updated banner: {banner}")


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "/cowrie/cowrie-git/etc/cowrie.cfg"
    banner = get_weighted_banner()
    update_cowrie_config(config_path, banner)


if __name__ == "__main__":
    main()
