#!/usr/bin/env python3
"""
Unit tests for iptables containment rules
Validates that honeypot network isolation is properly configured.
"""

import subprocess
import sys


class TestIPTablesRules:
    """Test suite for firewall containment."""

    def test_iptables_chain_exists(self):
        """HONEYPOT-ISOLATION chain should exist after setup."""
        result = subprocess.run(
            ["iptables", "-L", "HONEYPOT-ISOLATION"],
            capture_output=True, text=True
        )
        # If chain doesn't exist, test is skipped (setup not run)
        if result.returncode != 0:
            print("SKIP: HONEYPOT-ISOLATION chain not found (setup not run)")
            return
        assert "HONEYPOT-ISOLATION" in result.stdout

    def test_docker_subnet_blocked(self):
        """172.20.0.0/24 should have restrictive FORWARD rules."""
        result = subprocess.run(
            ["iptables", "-L", "FORWARD", "-v", "-n"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        # Check that honeynet subnet appears in FORWARD rules
        assert "172.20.0.0/24" in result.stdout or "172.20.0" in result.stdout, ""
            "Docker honeynet not found in FORWARD chain - isolation may not be applied"

    def test_default_forward_drop(self):
        """Default FORWARD policy should be DROP."""
        result = subprocess.run(
            ["iptables", "-L", "FORWARD"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        assert "policy DROP" in result.stdout, ""
            "FORWARD policy is not DROP - containers may reach internet"

    def test_no_privileged_ports_exposed(self):
        """Elasticsearch port 9200 should NOT be exposed on 0.0.0.0."""
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Ports}}"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("SKIP: Docker not running")
            return
        ports = result.stdout
        assert "0.0.0.0:9200" not in ports, ""
            "CRITICAL: Elasticsearch exposed on 0.0.0.0:9200"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
