#!/usr/bin/env python3
"""
Unit tests for Deception Score Calculator
Validates the fingerprinting resistance algorithm against known attack patterns.
"""

import sys
import os
import json
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from deception_score import DeceptionScorer


class TestDeceptionScorer:
    """Test suite for deception score components."""

    def test_score_banner_realistic(self):
        """Real dropbear banner should score high."""
        scorer = DeceptionScorer()
        score = scorer.score_banner("SSH-2.0-dropbear_2016.74")
        assert score >= 0.8, f"Expected high score for dropbear, got {score}"

    def test_score_banner_fake_cowrie(self):
        """Cowrie signature banner should score very low."""
        scorer = DeceptionScorer()
        score = scorer.score_banner("SSH-2.0-Cowrie")
        assert score <= 0.2, f"Expected low score for Cowrie banner, got {score}"

    def test_score_banner_neutral(self):
        """Unknown banner should be neutral."""
        scorer = DeceptionScorer()
        score = scorer.score_banner("SSH-2.0-Unknown_1.0")
        assert 0.4 <= score <= 0.6, f"Expected neutral score, got {score}"

    def test_score_credentials_with_fakes(self):
        """Userdb with fake accounts should score low."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("phil:123456\n")
            f.write("richard:password\n")
            f.flush()
            path = f.name

        scorer = DeceptionScorer()
        score = scorer.score_credentials(path)
        os.unlink(path)
        assert score < 0.5, f"Expected low score with fake accounts, got {score}"

    def test_score_credentials_realistic(self):
        """Userdb with only IoT defaults should score high."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("root:123456\n")
            f.write("admin:admin\n")
            f.write("service:service\n")
            f.flush()
            path = f.name

        scorer = DeceptionScorer()
        score = scorer.score_credentials(path)
        os.unlink(path)
        assert score >= 0.7, f"Expected high score with realistic creds, got {score}"

    def test_score_credentials_missing_file(self):
        """Missing userdb should return 0."""
        scorer = DeceptionScorer()
        score = scorer.score_credentials("/nonexistent/path.txt")
        assert score == 0.0, f"Expected 0.0 for missing file, got {score}"

    def test_calculate_structure(self):
        """Full calculation should return structured result."""
        scorer = DeceptionScorer()
        result = scorer.calculate()

        assert "overall_score" in result
        assert "components" in result
        assert "recommendations" in result
        assert "risk_level" in result
        assert 0.0 <= result["overall_score"] <= 1.0

    def test_risk_level_classification(self):
        """Risk levels should map correctly to score ranges."""
        scorer = DeceptionScorer()

        assert scorer._risk_level(0.85) == "LOW"
        assert scorer._risk_level(0.65) == "MEDIUM"
        assert scorer._risk_level(0.45) == "HIGH"
        assert scorer._risk_level(0.25) == "CRITICAL"

    def test_weight_validation(self):
        """Invalid weights should raise ValueError."""
        try:
            DeceptionScorer(weights={
                'banner': 0.5,
                'filesystem': 0.5,
                'latency': 0.5,
                'credentials': 0.5
            })
            assert False, "Should have raised ValueError for invalid weights"
        except ValueError:
            pass

    def test_recommendations_critical(self):
        """Low credential score should trigger critical recommendation."""
        scorer = DeceptionScorer()
        recs = scorer._generate_recommendations(0.8, 0.8, 0.8, 0.3)
        assert any("CRITICAL" in r for r in recs), "Expected CRITICAL recommendation"

    def test_recommendations_ok(self):
        """High scores should return OK recommendation."""
        scorer = DeceptionScorer()
        recs = scorer._generate_recommendations(0.8, 0.8, 0.8, 0.8)
        assert any("OK" in r for r in recs), "Expected OK recommendation"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
