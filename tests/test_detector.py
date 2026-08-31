"""
Unit tests for the LogSentinel detection engine.
"""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "logsentinel"
sys.path.insert(0, str(SRC_DIR))

from detector import detect_brute_force, detect_failed_logins


class TestDetector(unittest.TestCase):
    """Verify authentication threat detection logic."""

    def setUp(self):
        """Prepare synthetic authentication events for testing."""

        self.events = [
            {
                "timestamp": "2026-07-10 08:00:00",
                "user": "admin",
                "ip_address": "10.0.0.5",
                "status": "FAILED",
            },
            {
                "timestamp": "2026-07-10 08:00:20",
                "user": "admin",
                "ip_address": "10.0.0.5",
                "status": "FAILED",
            },
            {
                "timestamp": "2026-07-10 08:00:40",
                "user": "admin",
                "ip_address": "10.0.0.5",
                "status": "FAILED",
            },
            {
                "timestamp": "2026-07-10 08:01:00",
                "user": "admin",
                "ip_address": "10.0.0.5",
                "status": "FAILED",
            },
            {
                "timestamp": "2026-07-10 08:01:20",
                "user": "admin",
                "ip_address": "10.0.0.5",
                "status": "FAILED",
            },
            {
                "timestamp": "2026-07-10 08:02:00",
                "user": "mary",
                "ip_address": "192.168.1.20",
                "status": "SUCCESS",
            },
        ]

    def test_detect_failed_logins(self):
        """Verify that failed authentication events are tallied."""

        result = detect_failed_logins(self.events)

        self.assertEqual(result, 5)

    def test_detect_brute_force(self):
        """Verify that repeated failures generate an alert."""

        alerts = detect_brute_force(self.events, threshold=5)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "admin")
        self.assertEqual(alerts[0]["ip_address"], "10.0.0.5")
        self.assertEqual(alerts[0]["risk_level"], "HIGH")

    def test_no_alert_below_threshold(self):
        """Verify that activity under the threshold stays silent."""

        alerts = detect_brute_force(self.events[:4], threshold=5)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
