import base64

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


PLACEHOLDER_MARKERS = (
    "replace-with",
    "change-me",
    "django-insecure",
    "example.com",
)
INSECURE_EXACT_VALUES = {
    "zKxYq3Hv8mNpR2Lw5TdUiOeAjBcFsGhX4lQkPnVyWZE=",
}


class Command(BaseCommand):
    help = "Validate security-critical production environment settings."

    def handle(self, *args, **options):
        errors = []
        warnings = []

        self._require_secret(errors, "DJANGO_SECRET_KEY", settings.SECRET_KEY, min_length=50)
        self._require_secret(errors, "DB_PASSWORD", settings.DATABASES["default"].get("PASSWORD", ""), min_length=12)
        self._validate_fernet(errors)

        if settings.DEBUG:
            errors.append("DJANGO_DEBUG must be False.")
        if settings.CORS_ALLOW_ALL_ORIGINS:
            errors.append("CORS_ALLOW_ALL_ORIGINS must be False.")
        if not settings.ALLOWED_HOSTS or "*" in settings.ALLOWED_HOSTS:
            errors.append("DJANGO_ALLOWED_HOSTS must contain explicit host names.")
        if not settings.SESSION_COOKIE_SECURE:
            warnings.append("SESSION_COOKIE_SECURE is False; enable it behind HTTPS.")
        if not settings.CSRF_COOKIE_SECURE:
            warnings.append("CSRF_COOKIE_SECURE is False; enable it behind HTTPS.")
        if not settings.SECURE_SSL_REDIRECT:
            warnings.append("SECURE_SSL_REDIRECT is False; ensure the reverse proxy enforces HTTPS.")
        if not settings.CSRF_TRUSTED_ORIGINS:
            errors.append("CSRF_TRUSTED_ORIGINS must contain the production HTTPS origin.")

        if settings.TOKEN_VAULT_PROVIDER == "ml-kem-1024-aesgcm-v1":
            self._require_secret(errors, "MLKEM1024_PUBLIC_KEY", settings.MLKEM1024_PUBLIC_KEY, min_length=100)
            self._require_secret(errors, "MLKEM1024_PRIVATE_KEY", settings.MLKEM1024_PRIVATE_KEY, min_length=40)

        provider = settings.SEMANTIC_AGENT_PROVIDER.lower()
        provider_keys = {
            "groq": settings.GROQ_API_KEY,
            "xai": settings.XAI_API_KEY,
            "openai": settings.OPENAI_API_KEY,
        }
        if settings.SEMANTIC_AGENT_ENABLED and provider in provider_keys:
            self._require_secret(errors, f"{provider.upper()}_API_KEY", provider_keys[provider], min_length=20)
        self._validate_semantic_thresholds(errors)

        if settings.ENTERPRISE_SSO_ENABLED:
            for name in ("OIDC_ISSUER", "OIDC_AUTHORIZE_URL", "OIDC_TOKEN_URL", "OIDC_JWKS_URL", "OIDC_CLIENT_ID"):
                value = getattr(settings, name)
                if not value or self._is_placeholder(value):
                    errors.append(f"{name} must be configured when enterprise SSO is enabled.")
            self._require_secret(errors, "OIDC_CLIENT_SECRET", settings.OIDC_CLIENT_SECRET, min_length=16)

        for warning in warnings:
            self.stdout.write(self.style.WARNING(f"WARNING: {warning}"))
        if errors:
            for error in errors:
                self.stderr.write(self.style.ERROR(f"ERROR: {error}"))
            raise CommandError(f"Deployment validation failed with {len(errors)} error(s).")

        self.stdout.write(self.style.SUCCESS("Deployment environment validation passed."))

    @staticmethod
    def _validate_semantic_thresholds(errors):
        escalation = settings.SEMANTIC_EMBEDDING_ESCALATION_THRESHOLD
        block = settings.SEMANTIC_EMBEDDING_BLOCK_THRESHOLD
        margin = settings.SEMANTIC_EMBEDDING_MIN_MARGIN
        if not 0.0 <= escalation < block <= 1.0:
            errors.append(
                "Semantic thresholds must satisfy 0 <= escalation threshold "
                "< block threshold <= 1."
            )
        if not 0.0 <= margin <= 1.0:
            errors.append("SEMANTIC_EMBEDDING_MIN_MARGIN must be between 0 and 1.")

    def _validate_fernet(self, errors):
        raw = settings.FERNET_KEY.decode() if isinstance(settings.FERNET_KEY, bytes) else settings.FERNET_KEY
        if self._is_placeholder(raw):
            errors.append("FERNET_KEY contains a placeholder value.")
            return
        try:
            decoded = base64.urlsafe_b64decode(raw)
        except Exception:
            errors.append("FERNET_KEY is not valid URL-safe base64.")
            return
        if len(decoded) != 32:
            errors.append("FERNET_KEY must decode to exactly 32 bytes.")

    def _require_secret(self, errors, name, value, *, min_length):
        text = str(value or "").strip()
        if not text:
            errors.append(f"{name} is required.")
        elif len(text) < min_length:
            errors.append(f"{name} must be at least {min_length} characters.")
        elif self._is_placeholder(text):
            errors.append(f"{name} contains a placeholder or development value.")

    @staticmethod
    def _is_placeholder(value):
        text = str(value).strip()
        if text in INSECURE_EXACT_VALUES:
            return True
        lowered = text.lower()
        return any(marker in lowered for marker in PLACEHOLDER_MARKERS)
