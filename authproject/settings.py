# authproject/settings.py

import os
from pathlib import Path
from decouple import config
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Core ---
SECRET_KEY = config('SECRET_KEY', default='django-insecure-)&0ag4ic8p+$0mdou^7stjs^-11wptttwmhzafe)i#71-sm914')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = ['*']

# --- Apps ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'authentication',
]

# --- Middleware (WhiteNoise added for static files) ---
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Added for static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'authproject.urls'

# --- Templates ---
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'authproject.wsgi.application'

# --- Database Configuration ---
# Railway MySQL in production, local MySQL in development
if 'DATABASE_URL' in os.environ:
    # Production database (Railway MySQL)
    DATABASES = {
        'default': dj_database_url.parse(os.environ.get('DATABASE_URL'))
    }
else:
    # Development database (your local MySQL)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.mysql',
            'NAME': config('DB_NAME', default='authapp'),
            'USER': config('DB_USER', default='robolog'),
            'PASSWORD': config('DB_PASSWORD', default='Robolog@2020!'),
            'HOST': config('DB_HOST', default='127.0.0.1'),
            'PORT': config('DB_PORT', default='3306'),
            'OPTIONS': {
                'charset': 'utf8mb4',
                'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            },
            'CONN_MAX_AGE': 60,
        }
    }

# --- Custom User ---
AUTH_USER_MODEL = "authentication.CustomUser"

# --- Password validation ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- DRF ---
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'authentication.authentication.CustomTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# --- CORS Configuration ---
if DEBUG:
    # Development CORS settings
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    CORS_ALLOW_ALL_ORIGINS = True
else:
    # Production CORS settings - update with your frontend domain
    CORS_ALLOWED_ORIGINS = [
        "https://your-frontend-domain.com",  # Update this
        "https://robologiot.co.in",  # Your domain
    ]
    CORS_ALLOW_ALL_ORIGINS = False

CORS_ALLOW_CREDENTIALS = True

# --- Email Configuration ---
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='aractservice@gmail.com')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='rajpeniahitvotwy')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='aractservice@gmail.com')

# --- OTP / Token config ---
OTP_EXPIRY_MINUTES = 10
OTP_LENGTH = 6
MAX_OTP_ATTEMPTS = 5
OTP_RESEND_DELAY_SECONDS = 60
STAFF_TOKEN_EXPIRY = None
USER_TOKEN_EXPIRY = 7 * 24 * 60 * 60

# --- Cache ---
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'auth_cache_table',
    }
}

# --- Sessions ---
SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# --- i18n / tz ---
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

# --- Static & Media Files ---
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Only include STATICFILES_DIRS if the directory exists
static_dir = os.path.join(BASE_DIR, 'static')
if os.path.exists(static_dir):
    STATICFILES_DIRS = [static_dir]

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# --- Admin Customization ---
ADMIN_SITE_HEADER = "ARACT BATT PULSE Admin"
ADMIN_SITE_TITLE = "ARACT BATT PULSE"
ADMIN_INDEX_TITLE = "Battery Monitoring System Dashboard"

# --- Company ---
COMPANY_NAME = config('COMPANY_NAME', default='ARACT BATT PULSE')

# --- Security Settings for Production ---
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True

# --- Defaults ---
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Logging ---
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
        'console': {'level': 'DEBUG', 'class': 'logging.StreamHandler', 'formatter': 'simple'},
    },
    'root': {'handlers': ['console'], 'level': 'INFO'},
    'loggers': {
        'authentication': {'handlers': ['console'], 'level': 'DEBUG', 'propagate': False},
    },
}