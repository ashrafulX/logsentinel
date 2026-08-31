"""
CSV authentication log reader.
"""

import csv


def load_log_file(file_path):
    """
    Read authentication events from a CSV file.

    The parser is tolerant of common CSV issues:
    - Strips a UTF-8 BOM from the header row if present
    - Normalizes column names by stripping whitespace
    - Skips completely empty rows

    Args:
        file_path: Path to the CSV log file.

    Returns:
        list: Authentication events as dictionaries.

    Raises:
        ValueError: If the CSV is missing required columns.
    """

    events = []

    with open(file_path, "r", newline="", encoding="utf-8-sig") as csv_file:
        reader = csv.DictReader(csv_file)

        if reader.fieldnames is None:
            return events

        normalized_fieldnames = [name.strip() for name in reader.fieldnames]
        reader.fieldnames = normalized_fieldnames

        required_columns = {"timestamp", "user", "ip_address", "status"}
        missing_columns = required_columns - set(normalized_fieldnames)

        if missing_columns:
            raise ValueError(
                f"The CSV is missing required columns: {', '.join(sorted(missing_columns))}"
            )

        for row in reader:
            cleaned_row = {
                key.strip(): (value.strip() if value is not None else value)
                for key, value in row.items()
                if key is not None
            }
            if any(cleaned_row.values()):
                events.append(cleaned_row)

    return events
