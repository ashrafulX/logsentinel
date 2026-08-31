"""
CSV authentication log reader.
"""

import csv


def load_log_file(file_path):
    """
    Read authentication events from a CSV file.

    Args:
        file_path: Path to the CSV log file.

    Returns:
        list: Authentication events as dictionaries.
    """

    events = []

    with open(file_path, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            events.append(row)

    return events
