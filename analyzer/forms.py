from django import forms


class LogUploadForm(forms.Form):
    csv_file = forms.FileField(label="Choose CSV File")
