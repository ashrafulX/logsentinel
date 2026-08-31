import csv
import logging
import tempfile
from pathlib import Path

from django.shortcuts import render

from logsentinel.parser import load_log_file
from logsentinel.detector import detect_failed_logins, detect_brute_force

from .forms import LogUploadForm

logger = logging.getLogger(__name__)


def index(request):
    context = {}
    if request.method == "POST":
        uploaded_file = request.FILES.get("csv_file")
        if not uploaded_file:
            context["error"] = "Please select a CSV file."
            context["form"] = LogUploadForm()
            return render(request, "analyzer/index.html", context)

        form = LogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                suffix = Path(uploaded_file.name).suffix or ".csv"
                with tempfile.NamedTemporaryFile(mode="wb", suffix=suffix, delete=False) as f:
                    for chunk in uploaded_file.chunks():
                        f.write(chunk)
                    temp_path = f.name

                try:
                    events = load_log_file(Path(temp_path))
                except ValueError as exc:
                    context["error"] = str(exc)
                    context["form"] = form
                    return render(request, "analyzer/index.html", context)
                finally:
                    Path(temp_path).unlink(missing_ok=True)

                if not events:
                    context["error"] = "The uploaded CSV file is empty."
                else:
                    failed_logins = detect_failed_logins(events)
                    alerts = detect_brute_force(events)
                    total_events = len(events)

                    context["result"] = {
                        "total_events": total_events,
                        "failed_logins": failed_logins,
                        "successful_logins": total_events - failed_logins,
                        "security_alerts": len(alerts),
                        "alerts": alerts,
                    }
            except Exception as exc:
                logger.exception("LogSentinel analysis failed")
                context["error"] = "Unable to analyze this file. Please check the CSV format."
        else:
            context["error"] = "Please upload a valid CSV file."

        context["form"] = form
    else:
        context["form"] = LogUploadForm()

    return render(request, "analyzer/index.html", context)
