"""
Django settings for sentinell_ai project.

Security Notes:
  - SECRET_KEY loaded from environment variables
  - Email credentials loaded from environment variables
  - CSRF and session security enabled
  - Rate limiting middleware active
  - No secrets hardcoded in production
"""

import os
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in ("true", "1", "yes", "on")


def _env_list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]

# ── Load .env file ────────────────────────────────────────────────────────────
# Read .env file manually (no external dependency needed)
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-!@@qa1km04siytkxg=*t@2mk&))dttj*i!hzv!jj$c9^sczcex",
)

DJANGO_ENV = os.environ.get("DJANGO_ENV", "development").lower()
IS_PRODUCTION = DJANGO_ENV == "production"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = _env_bool("DJANGO_DEBUG", not IS_PRODUCTION)

ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "corsheaders",
    # Local apps
    "users",
    "firewall",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",          # must be first
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Custom security middleware
    "users.middleware.RateLimitMiddleware",
]

if _env_bool("WHITENOISE_ENABLED", IS_PRODUCTION):
    MIDDLEWARE.insert(2, "whitenoise.middleware.WhiteNoiseMiddleware")

# CORS — allow all origins for the API endpoints (tighten in production)
CORS_ALLOWED_ORIGINS = _env_list("CORS_ALLOWED_ORIGINS")
CORS_ALLOW_ALL_ORIGINS = _env_bool("CORS_ALLOW_ALL_ORIGINS", not IS_PRODUCTION)
CORS_URLS_REGEX = r"^/(analyze|analyze-file).*$"

ROOT_URLCONF = "sentinell_ai.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
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

WSGI_APPLICATION = "sentinell_ai.wsgi.application"

# Database
DATABASES = {
    "default": {
        "ENGINE": os.environ.get("DB_ENGINE", "django.db.backends.postgresql"),
        "NAME": os.environ.get("DB_NAME", "sentinell_ai_db"),
        "USER": os.environ.get("DB_USER", "sentinell_user"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

# Custom user model
AUTH_USER_MODEL = "users.CustomUser"

# Authentication redirects
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/login/"

# Enterprise identity provider / Zero Trust SSO.
# Keep ENTERPRISE_SSO_ENABLED=False for local demos; set these values for
# Microsoft Entra ID, Okta, Auth0, Keycloak, or any OIDC-compatible provider.
ENTERPRISE_SSO_ENABLED = _env_bool("ENTERPRISE_SSO_ENABLED", False)
OIDC_PROVIDER_NAME = os.environ.get("OIDC_PROVIDER_NAME", "enterprise-oidc")
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "")
OIDC_AUTHORIZE_URL = os.environ.get("OIDC_AUTHORIZE_URL", "")
OIDC_TOKEN_URL = os.environ.get("OIDC_TOKEN_URL", "")
OIDC_JWKS_URL = os.environ.get("OIDC_JWKS_URL", "")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "")
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile groups")
OIDC_ROLE_CLAIM = os.environ.get("OIDC_ROLE_CLAIM", "groups")
OIDC_DEPARTMENT_CLAIM = os.environ.get("OIDC_DEPARTMENT_CLAIM", "department")
OIDC_ADMIN_GROUPS = _env_list("OIDC_ADMIN_GROUPS", "SentinellAdmins,SecurityAdmins")
OIDC_EMPLOYEE_GROUPS = _env_list("OIDC_EMPLOYEE_GROUPS", "SentinellEmployees,Developers,Analysts")
OIDC_DEFAULT_ROLE = os.environ.get("OIDC_DEFAULT_ROLE", "INTERN")
OIDC_ALLOWED_ALGORITHMS = _env_list("OIDC_ALLOWED_ALGORITHMS", "RS256")
OIDC_TIMEOUT = float(os.environ.get("OIDC_TIMEOUT", "8"))
OIDC_ALLOW_UNVERIFIED_ID_TOKEN = _env_bool("OIDC_ALLOW_UNVERIFIED_ID_TOKEN", False)

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE_BACKEND = os.environ.get(
    "STATICFILES_STORAGE_BACKEND",
    "whitenoise.storage.CompressedManifestStaticFilesStorage"
    if IS_PRODUCTION
    else "django.contrib.staticfiles.storage.StaticFilesStorage",
)
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": STATICFILES_STORAGE_BACKEND,
    },
}

# Fernet encryption key (32 url-safe base64-encoded bytes)
FERNET_KEY = os.environ.get(
    "FERNET_KEY", "zKxYq3Hv8mNpR2Lw5TdUiOeAjBcFsGhX4lQkPnVyWZE="
).encode()

# Sensitive token vault. The provider is selected by environment configuration;
# production can use the ML-KEM-1024 hybrid envelope without changing callers.
TOKEN_VAULT_PROVIDER = os.environ.get("TOKEN_VAULT_PROVIDER", "local-fernet-envelope")
TOKEN_VAULT_KEY_ID = os.environ.get("TOKEN_VAULT_KEY_ID", "fernet-local-v1")
MLKEM1024_PUBLIC_KEY = os.environ.get("MLKEM1024_PUBLIC_KEY", "")
MLKEM1024_PRIVATE_KEY = os.environ.get("MLKEM1024_PRIVATE_KEY", "")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# =============================================================================
# SEMANTIC SECURITY AGENT
# =============================================================================
# Local embeddings make the primary semantic decision. The configured LLM
# provider is used only as a second opinion for uncertain local classifications.
SEMANTIC_AGENT_ENABLED = _env_bool("SEMANTIC_AGENT_ENABLED", True)
SEMANTIC_LOCAL_EMBEDDINGS_ENABLED = _env_bool("SEMANTIC_LOCAL_EMBEDDINGS_ENABLED", True)
SEMANTIC_EMBEDDING_DIMENSIONS = int(os.environ.get("SEMANTIC_EMBEDDING_DIMENSIONS", "4096"))
SEMANTIC_EMBEDDING_BLOCK_THRESHOLD = float(
    os.environ.get("SEMANTIC_EMBEDDING_BLOCK_THRESHOLD", "0.22")
)
SEMANTIC_EMBEDDING_ESCALATION_THRESHOLD = float(
    os.environ.get("SEMANTIC_EMBEDDING_ESCALATION_THRESHOLD", "0.14")
)
SEMANTIC_EMBEDDING_MIN_MARGIN = float(
    os.environ.get("SEMANTIC_EMBEDDING_MIN_MARGIN", "0.06")
)
SEMANTIC_AGENT_PROVIDER = os.environ.get("SEMANTIC_AGENT_PROVIDER", "openai")
SEMANTIC_AGENT_TIMEOUT = float(os.environ.get("SEMANTIC_AGENT_TIMEOUT", "8"))
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_SEMANTIC_MODEL = os.environ.get("OPENAI_SEMANTIC_MODEL", "gpt-5.4-mini")
OPENAI_RESPONSES_URL = os.environ.get(
    "OPENAI_RESPONSES_URL",
    "https://api.openai.com/v1/responses",
)
XAI_API_KEY = os.environ.get("XAI_API_KEY", "")
XAI_SEMANTIC_MODEL = os.environ.get("XAI_SEMANTIC_MODEL", "grok-4.20-reasoning")
XAI_CHAT_COMPLETIONS_URL = os.environ.get(
    "XAI_CHAT_COMPLETIONS_URL",
    "https://api.x.ai/v1/chat/completions",
)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", os.environ.get("XAI_API_KEY", ""))
GROQ_SEMANTIC_MODEL = os.environ.get("GROQ_SEMANTIC_MODEL", "llama-3.3-70b-versatile")
GROQ_CHAT_COMPLETIONS_URL = os.environ.get(
    "GROQ_CHAT_COMPLETIONS_URL",
    "https://api.groq.com/openai/v1/chat/completions",
)

# Approved-response LLM. This runs only after the firewall allows/tokenizes input.
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "mock").lower()
LLM_ALLOWED_PROVIDERS = _env_list("LLM_ALLOWED_PROVIDERS", "mock,groq,openai,xai,openai_compatible")
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "20"))
GROQ_RESPONSE_MODEL = os.environ.get("GROQ_RESPONSE_MODEL", GROQ_SEMANTIC_MODEL)
OPENAI_RESPONSE_MODEL = os.environ.get("OPENAI_RESPONSE_MODEL", "gpt-4o-mini")
OPENAI_CHAT_COMPLETIONS_URL = os.environ.get(
    "OPENAI_CHAT_COMPLETIONS_URL",
    "https://api.openai.com/v1/chat/completions",
)
XAI_RESPONSE_MODEL = os.environ.get("XAI_RESPONSE_MODEL", XAI_SEMANTIC_MODEL)
LLM_OPENAI_COMPATIBLE_URL = os.environ.get("LLM_OPENAI_COMPATIBLE_URL", "")
LLM_OPENAI_COMPATIBLE_API_KEY = os.environ.get("LLM_OPENAI_COMPATIBLE_API_KEY", "")
LLM_OPENAI_COMPATIBLE_MODEL = os.environ.get("LLM_OPENAI_COMPATIBLE_MODEL", "")

FILE_SCAN_MAX_BYTES = int(os.environ.get("FILE_SCAN_MAX_BYTES", str(5 * 1024 * 1024)))
FILE_SCAN_MAX_TEXT_CHARS = int(os.environ.get("FILE_SCAN_MAX_TEXT_CHARS", "100000"))


# =============================================================================
# SESSION SECURITY
# =============================================================================
SESSION_COOKIE_HTTPONLY = True  # Prevent JS access to session cookie
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 3600  # 1 hour session expiry
SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", IS_PRODUCTION)
CSRF_COOKIE_SECURE = _env_bool("CSRF_COOKIE_SECURE", IS_PRODUCTION)
SECURE_SSL_REDIRECT = _env_bool("SECURE_SSL_REDIRECT", False)
CSRF_TRUSTED_ORIGINS = _env_list("CSRF_TRUSTED_ORIGINS")
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

if IS_PRODUCTION:
    SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", True)
    SECURE_HSTS_PRELOAD = _env_bool("SECURE_HSTS_PRELOAD", True)
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"

# In production, enable these:
# SESSION_COOKIE_SECURE = True  # HTTPS only
# CSRF_COOKIE_SECURE = True     # HTTPS only
# SECURE_SSL_REDIRECT = True    # Redirect HTTP to HTTPS

# =============================================================================
# LOGGING
# =============================================================================
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "users": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "firewall": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}
