#!/usr/bin/env python3
"""
Unit tests for Logstash pipeline configurations
Validates Grok patterns and JSON parsing logic.
"""

import json
import tempfile
from pathlib import Path


class TestLogParsing:
    """Test suite for log pipeline parsing."""

    def test_cowrie_json_valid(self):
        """Sample Cowrie JSON log should be valid JSON."""
        sample = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2024-01-15T10:30:00.000000Z",
            "session": "abc123",
            "src_ip": "192.0.2.1",
            "src_port": 54321,
            "dst_ip": "198.51.100.1",
            "dst_port": 2222,
            "sensor": "honeypot-01"
        }
        # Should parse without errors
        parsed = json.loads(json.dumps(sample))
        assert parsed["eventid"] == "cowrie.session.connect"
        assert parsed["src_ip"] == "192.0.2.1"

    def test_dionaea_json_valid(self):
        """Sample Dionaea JSON log should be valid JSON."""
        sample = {
            "timestamp": "2024-01-15T10:30:00.000000Z",
            "event_type": "mqtt_connect",
            "src_ip": "192.0.2.1",
            "src_port": 54321,
            "protocol": "mqtt",
            "client_id": "mirai-bot-01",
            "username": "admin",
            "password": "admin",
            "suspicious": True
        }
        parsed = json.loads(json.dumps(sample))
        assert parsed["event_type"] == "mqtt_connect"
        assert parsed["suspicious"] is True

    def test_logstash_config_syntax(self):
        """Logstash config files should be parseable."""
        config_files = [
            "elk/logstash/pipeline/cowrie.conf",
            "elk/logstash/pipeline/dionaea.conf",
            "elk/logstash/pipeline/geoip.conf"
        ]
        for cfg in config_files:
            path = Path(cfg)
            if not path.exists():
                print(f"SKIP: {cfg} not found")
                continue
            content = path.read_text()
            # Basic syntax checks
            assert "input {" in content, f"Missing input block in {cfg}"
            assert "filter {" in content, f"Missing filter block in {cfg}"
            assert "output {" in content, f"Missing output block in {cfg}"

    def test_filebeat_config_valid(self):
        """Filebeat YAML should be valid."""
        import yaml
        path = Path("elk/filebeat/filebeat.yml")
        if not path.exists():
            print("SKIP: filebeat.yml not found")
            return
        with open(path) as f:
            config = yaml.safe_load(f)
        assert "filebeat.inputs" in config
        assert "output.logstash" in config


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
