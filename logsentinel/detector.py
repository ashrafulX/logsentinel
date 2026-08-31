"""
Authentication threat detection engine.
"""

from collections import defaultdict


def detect_failed_logins(events):
    """
    Count failed authentication attempts.

    Args:
        events (list): Authentication log events.

    Returns:
        int: Total number of failed login attempts.
    """

    return sum(
        1
        for event in events
        if event["status"].strip().upper() == "FAILED"
    )


def detect_brute_force(events, threshold=5):
    """
    Identify user and IP combinations with excessive failed logins.

    Args:
        events (list): Authentication log events.
        threshold (int): Minimum failed attempts to flag as suspicious.

    Returns:
        list: Alerts for suspicious activity.
    """

    failed_attempts = defaultdict(int)

    for event in events:
        status = event["status"].strip().upper()

        if status == "FAILED":
            key = (
                event["user"].strip(),
                event["ip_address"].strip()
            )
            failed_attempts[key] += 1

    alerts = []

    for (user, ip_address), count in failed_attempts.items():
        if count >= threshold:
            alerts.append(
                {
                    "user": user,
                    "ip_address": ip_address,
                    "failed_attempts": count,
                    "risk_level": "HIGH",
                    "reason": (
                        f"{count} failed login attempts detected "
                        f"for user '{user}' from {ip_address}."
                    ),
                }
            )

    return alerts
