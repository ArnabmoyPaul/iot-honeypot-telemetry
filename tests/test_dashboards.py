#!/usr/bin/env python3
"""
Unit tests for Kibana dashboard exports
Validates NDJSON structure and required visualizations.
"""

import json
from pathlib import Path


class TestDashboards:
    """Test suite for Kibana dashboard exports."""

    def test_cowrie_dashboard_exists(self):
        """Cowrie SSH dashboard should exist and be valid NDJSON."""
        path = Path("elk/kibana/dashboards/cowrie-ssh.ndjson")
        assert path.exists(), "cowrie-ssh.ndjson not found"
        lines = path.read_text().strip().split("\n")
        assert len(lines) > 0, "Dashboard file is empty"
        for line in lines:
            doc = json.loads(line)
            assert "attributes" in doc

    def test_attack_geo_dashboard_exists(self):
        """Attack geo dashboard should exist."""
        path = Path("elk/kibana/dashboards/attack-geo.ndjson")
        assert path.exists(), "attack-geo.ndjson not found"

    def test_deception_score_dashboard_exists(self):
        """Deception score dashboard should exist."""
        path = Path("elk/kibana/dashboards/deception-score.ndjson")
        assert path.exists(), "deception-score.ndjson not found"

    def test_dashboard_has_visualizations(self):
        """Dashboards should reference at least one visualization."""
        path = Path("elk/kibana/dashboards/cowrie-ssh.ndjson")
        if not path.exists():
            print("SKIP: Dashboard file not found")
            return
        content = path.read_text()
        assert "visualization" in content, ""
            "Dashboard does not reference any visualizations"

    def test_geo_dashboard_has_map(self):
        """Geo dashboard should contain tile_map or map visualization."""
        path = Path("elk/kibana/dashboards/attack-geo.ndjson")
        if not path.exists():
            print("SKIP: Geo dashboard not found")
            return
        content = path.read_text()
        assert "tile_map" in content or "map" in content, ""
            "Geo dashboard missing map visualization"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
