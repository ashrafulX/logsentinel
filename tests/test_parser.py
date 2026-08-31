"""
Pytest-based tests for LogSentinel log parsing.
"""

import csv
import tempfile
from pathlib import Path

import pytest

from logsentinel.parser import load_log_file


def test_load_log_file_normal():
    """Verify that a well-formed CSV log file is parsed correctly."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "user", "ip_address", "status"])
        writer.writeheader()
        writer.writerow({
            "timestamp": "2026-07-10 08:00:00",
            "user": "admin",
            "ip_address": "10.0.0.5",
            "status": "FAILED",
        })
        writer.writerow({
            "timestamp": "2026-07-10 08:01:00",
            "user": "mary",
            "ip_address": "192.168.1.20",
            "status": "SUCCESS",
        })
        temp_path = f.name

    try:
        events = load_log_file(Path(temp_path))
        assert len(events) == 2
        assert events[0]["user"] == "admin"
        assert events[0]["status"] == "FAILED"
        assert events[1]["user"] == "mary"
        assert events[1]["status"] == "SUCCESS"
    finally:
        Path(temp_path).unlink()


def test_load_log_file_empty():
    """Verify that an empty CSV file returns an empty list."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("timestamp,user,ip_address,status\n")
        temp_path = f.name

    try:
        events = load_log_file(Path(temp_path))
        assert events == []
    finally:
        Path(temp_path).unlink()


def test_load_log_file_malformed():
    """Verify that a CSV with missing columns does not crash."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("timestamp,user,ip_address,status\n")
        f.write("2026-07-10 08:00:00,admin,10.0.0.5\n")
        f.write("bad_line_without_proper_commas\n")
        temp_path = f.name

    try:
        events = load_log_file(Path(temp_path))
        assert len(events) == 2
        assert events[0]["status"] is None
        assert events[1]["timestamp"] == "bad_line_without_proper_commas"
    finally:
        Path(temp_path).unlink()
