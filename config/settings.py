from decouple import config
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


SECRET_KEY = config("SECRET_KEY")
DEBUG = True
ALLOWED_HOSTS = ["*"]


INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "analyzer",
]


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


ROOT_URLCONF = "config.urls"


TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]


STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
