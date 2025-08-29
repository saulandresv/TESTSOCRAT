import os
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
DEBUG = os.getenv("DEBUG", "True") == "True"

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Apps de terceros
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    "django_ratelimit",
    # Tus apps
    "accounts",
    "access",
    "clients",
    "certs",
    "analysis",
    "reports",
    "notifications",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "analysis.middleware.RateLimitMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# Base de datos MySQL
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.getenv("MYSQL_DATABASE", "socrates"),
        "USER": os.getenv("MYSQL_USER", "socrates"),
        "PASSWORD": os.getenv("MYSQL_PASSWORD", "devpass"),
        "HOST": os.getenv("MYSQL_HOST", "mysql"),
        "PORT": os.getenv("MYSQL_PORT", "3306"),
        "OPTIONS": {"charset": "utf8mb4"},
    }
}

# Validadores de contraseña
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Internacionalización
LANGUAGE_CODE = "es-cl"
TIME_ZONE = "America/Santiago"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Media files (uploads and reports)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Django REST Framework
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/hour",
        "user": "1000/hour",
        "login": "5/minute",
        "analysis": "20/minute",
        "certificate": "50/minute",
        "reports": "10/hour",
    },
}

# Configuración JWT
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
}

# CORS
CORS_ALLOW_ALL_ORIGINS = True

# drf-spectacular
SPECTACULAR_SETTINGS = {
    "TITLE": "API Proyecto Sócrates",
    "DESCRIPTION": "Documentación de la API del Proyecto Sócrates",
    "VERSION": "1.0.0",
}

AUTH_USER_MODEL = "accounts.User"

# Celery Configuration
CELERY_BROKER_URL = 'redis://redis:6379/0'
CELERY_RESULT_BACKEND = 'redis://redis:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# Celery Beat Schedule
CELERY_BEAT_SCHEDULE = {
    'run-scheduled-analysis': {
        'task': 'analysis.tasks.run_scheduled_analysis',
        'schedule': 3600.0,  # Run every hour
    },
    'check-certificate-vitality': {
        'task': 'analysis.tasks.check_certificate_vitality',
        'schedule': 300.0,  # Run every 5 minutes
    },
    'generate-expiry-alerts': {
        'task': 'analysis.tasks.generate_certificate_expiry_alerts',
        'schedule': 86400.0,  # Run daily
    },
    'cleanup-old-analysis': {
        'task': 'analysis.tasks.cleanup_old_analysis',
        'schedule': 86400.0,  # Run daily
    },
    'update-certificate-frequencies': {
        'task': 'analysis.tasks.update_certificate_frequencies',
        'schedule': 3600.0,  # Run every hour
    },
    # Notificaciones
    'check-certificate-expiration': {
        'task': 'notifications.tasks.check_certificate_expiration_alerts',
        'schedule': 3600.0,  # Run every hour
    },
    'check-vulnerability-alerts': {
        'task': 'notifications.tasks.check_vulnerability_alerts',
        'schedule': 1800.0,  # Run every 30 minutes
    },
    'check-certificate-down': {
        'task': 'notifications.tasks.check_certificate_down_alerts',
        'schedule': 900.0,  # Run every 15 minutes
    },
    'weekly-reports': {
        'task': 'notifications.tasks.send_weekly_summary_reports',
        'schedule': 604800.0,  # Run weekly (Sunday)
    },
    'monthly-reports': {
        'task': 'notifications.tasks.send_monthly_summary_reports',
        'schedule': 2592000.0,  # Run monthly (1st day)
    },
    # Reportes automatizados
    'generate-monthly-reports': {
        'task': 'reports.tasks.generate_monthly_client_reports',
        'schedule': 2592000.0,  # Run monthly
    },
    'cleanup-old-reports': {
        'task': 'reports.tasks.cleanup_old_reports',
        'schedule': 604800.0,  # Run weekly
    },
}

# Rate Limiting Configuration
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Logging para rate limiting
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'rate_limit_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'rate_limiting.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'analysis.middleware': {
            'handlers': ['rate_limit_file', 'console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'notifications': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
