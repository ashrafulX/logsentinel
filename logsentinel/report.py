"""
Security report generator and exporter.
"""


def build_report(total_events, failed_logins, alerts):
    """
    Create a formatted text security report.

    Args:
        total_events (int): Total number of authentication events.
        failed_logins (int): Count of failed login attempts.
        alerts (list): Detected brute-force alerts.

    Returns:
        str: Formatted report text.
    """

    successful_logins = total_events - failed_logins

    lines = [
        "========== SECURITY SUMMARY ==========",
        f"Total Events       : {total_events}",
        f"Successful Logins  : {successful_logins}",
        f"Failed Logins      : {failed_logins}",
        f"Security Alerts    : {len(alerts)}",
        "======================================",
    ]

    if alerts:
        lines.append("")
        lines.append("========== HIGH-RISK ALERTS ==========")

        for alert_number, alert in enumerate(alerts, start=1):
            lines.extend(
                [
                    "",
                    f"Alert #{alert_number}",
                    f"User               : {alert['user']}",
                    f"IP Address         : {alert['ip_address']}",
                    f"Failed Attempts    : {alert['failed_attempts']}",
                    f"Risk Level         : {alert['risk_level']}",
                    f"Reason             : {alert['reason']}",
                ]
            )

        lines.append("")
        lines.append("======================================")
    else:
        lines.extend(["", "No brute-force activity detected."])

    return "\n".join(lines)


def generate_summary(total_events, failed_logins, alerts):
    """
    Print the security report to standard output.
    """

    report = build_report(total_events, failed_logins, alerts)
    print(f"\n{report}")


def save_report(total_events, failed_logins, alerts, output_file):
    """
    Write the security report to a file.

    Args:
        total_events (int): Total number of authentication events.
        failed_logins (int): Count of failed login attempts.
        alerts (list): Detected brute-force alerts.
        output_file: Destination file path.
    """

    report = build_report(total_events, failed_logins, alerts)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as report_file:
        report_file.write(report)
