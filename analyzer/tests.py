from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from pathlib import Path


class AnalyzerViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_homepage_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "LogSentinel")

    def test_upload_form_displayed(self):
        response = self.client.get("/")
        self.assertContains(response, "Upload Authentication Logs")

    def test_valid_csv_submission(self):
        csv_content = "timestamp,user,ip_address,status\n2026-07-10 08:00:00,admin,10.0.0.5,FAILED\n"
        uploaded = SimpleUploadedFile("test.csv", csv_content.encode("utf-8"), content_type="text/csv")
        response = self.client.post("/", {"csv_file": uploaded})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Total Events")

    def test_empty_upload_handled(self):
        response = self.client.post("/", {})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Please select a CSV file.")

    def test_empty_csv_handled(self):
        csv_content = "timestamp,user,ip_address,status\n"
        uploaded = SimpleUploadedFile("empty.csv", csv_content.encode("utf-8"), content_type="text/csv")
        response = self.client.post("/", {"csv_file": uploaded})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The uploaded CSV file is empty.")

    def test_invalid_csv_handled(self):
        bad_content = "not,a,valid,csv\nbad_line\n"
        uploaded = SimpleUploadedFile("bad.csv", bad_content.encode("utf-8"), content_type="text/csv")
        response = self.client.post("/", {"csv_file": uploaded})
        self.assertEqual(response.status_code, 200)
