"""
Pytest-based tests for LogSentinel detection engine.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "logsentinel"
sys.path.insert(0, str(SRC_DIR))

from detector import detect_brute_force, detect_failed_logins


@pytest.fixture
def normal_events():
    """Provide a standard set of authentication events for testing."""

    return [
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


def test_detect_failed_logins_normal(normal_events):
    """Verify that failed authentication events are tallied from normal input."""

    result = detect_failed_logins(normal_events)
    assert result == 5


def test_detect_failed_logins_empty():
    """Verify that an empty event list returns zero failed logins."""

    result = detect_failed_logins([])
    assert result == 0


def test_detect_brute_force_normal(normal_events):
    """Verify that repeated failures generate an alert from normal input."""

    alerts = detect_brute_force(normal_events, threshold=5)
    assert len(alerts) == 1
    assert alerts[0]["user"] == "admin"
    assert alerts[0]["ip_address"] == "10.0.0.5"
    assert alerts[0]["risk_level"] == "HIGH"


def test_detect_brute_force_empty():
    """Verify that an empty event list returns no alerts."""

    alerts = detect_brute_force([])
    assert alerts == []


def test_detect_brute_force_below_threshold():
    """Verify that activity under the threshold stays silent."""

    events = [
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
    ]
    alerts = detect_brute_force(events, threshold=5)
    assert alerts == []


def test_detect_brute_force_malformed_events():
    """Verify that events with missing or empty fields are handled safely."""

    events = [
        {
            "timestamp": "2026-07-10 08:00:00",
            "user": "",
            "ip_address": "10.0.0.5",
            "status": "FAILED",
        },
        {
            "timestamp": "2026-07-10 08:00:20",
            "user": "",
            "ip_address": "10.0.0.5",
            "status": "FAILED",
        },
    ]
    alerts = detect_brute_force(events, threshold=2)
    assert len(alerts) == 1
    assert alerts[0]["user"] == ""
    assert alerts[0]["ip_address"] == "10.0.0.5"
    assert alerts[0]["risk_level"] == "HIGH"
