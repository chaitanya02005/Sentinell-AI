import json
import logging
import secrets
import urllib.parse
import urllib.request
from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.urls import reverse
from django.utils import timezone

from .models import CustomUser

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OIDCProfile:
    subject: str
    email: str
    full_name: str
    role: str
    tenant_id: str
    department: str
    claims: dict


def enterprise_sso_available() -> bool:
    return bool(
        getattr(settings, "ENTERPRISE_SSO_ENABLED", False)
        and getattr(settings, "OIDC_CLIENT_ID", "")
        and getattr(settings, "OIDC_AUTHORIZE_URL", "")
        and getattr(settings, "OIDC_TOKEN_URL", "")
    )


def build_authorization_url(request) -> str:
    if not enterprise_sso_available():
        raise ImproperlyConfigured("Enterprise SSO is not configured.")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce

    redirect_uri = _redirect_uri(request)
    params = {
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": settings.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
    }
    return f"{settings.OIDC_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def authenticate_callback(request):
    expected_state = request.session.pop("oidc_state", "")
    expected_nonce = request.session.pop("oidc_nonce", "")
    actual_state = request.GET.get("state", "")
    code = request.GET.get("code", "")
    error = request.GET.get("error", "")

    if error:
        raise SuspiciousOperation(f"OIDC provider returned error: {error}")
    if not code or not expected_state or not secrets.compare_digest(actual_state, expected_state):
        raise SuspiciousOperation("Invalid OIDC state or authorization code.")

    tokens = exchange_code_for_tokens(code, _redirect_uri(request))
    claims = verify_id_token(tokens.get("id_token", ""), expected_nonce)
    profile = profile_from_claims(claims)
    user = upsert_enterprise_user(profile)
    logger.info("Enterprise SSO login: email=%s role=%s provider=%s", user.email, user.role, user.auth_provider)
    return user


def exchange_code_for_tokens(code: str, redirect_uri: str) -> dict:
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.OIDC_CLIENT_ID,
        "client_secret": settings.OIDC_CLIENT_SECRET,
    }
    data = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(
        settings.OIDC_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=settings.OIDC_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_id_token(id_token: str, expected_nonce: str) -> dict:
    if not id_token:
        raise SuspiciousOperation("OIDC token response did not include an id_token.")

    try:
        import jwt
    except ImportError as exc:
        raise ImproperlyConfigured("Install PyJWT to verify OIDC id_tokens.") from exc

    options = {
        "require": ["sub", "exp", "iat"],
        "verify_signature": not settings.OIDC_ALLOW_UNVERIFIED_ID_TOKEN,
    }
    if settings.OIDC_ALLOW_UNVERIFIED_ID_TOKEN:
        claims = jwt.decode(id_token, options=options)
    else:
        jwks_client = jwt.PyJWKClient(settings.OIDC_JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=settings.OIDC_ALLOWED_ALGORITHMS,
            audience=settings.OIDC_CLIENT_ID,
            issuer=settings.OIDC_ISSUER or None,
            options=options,
        )

    nonce = claims.get("nonce", "")
    if expected_nonce and nonce and not secrets.compare_digest(str(nonce), expected_nonce):
        raise SuspiciousOperation("OIDC nonce mismatch.")
    return claims


def profile_from_claims(claims: dict) -> OIDCProfile:
    subject = str(claims.get("sub", "")).strip()
    email = str(claims.get("email", "")).strip().lower()
    if not subject or not email:
        raise SuspiciousOperation("OIDC claims must include sub and email.")

    full_name = (
        str(claims.get("name", "")).strip()
        or str(claims.get("preferred_username", "")).strip()
        or email.split("@")[0]
    )
    return OIDCProfile(
        subject=subject,
        email=email,
        full_name=full_name,
        role=role_from_claims(claims),
        tenant_id=str(claims.get("tid") or claims.get("tenant_id") or claims.get("iss") or "").strip(),
        department=str(claims.get(settings.OIDC_DEPARTMENT_CLAIM, "") or "").strip(),
        claims=_safe_claims(claims),
    )


def role_from_claims(claims: dict) -> str:
    values = _claim_values(claims.get(settings.OIDC_ROLE_CLAIM))
    groups = {value.lower() for value in values}
    admin_groups = {value.lower() for value in settings.OIDC_ADMIN_GROUPS}
    employee_groups = {value.lower() for value in settings.OIDC_EMPLOYEE_GROUPS}

    if groups & admin_groups:
        return CustomUser.ADMIN
    if groups & employee_groups:
        return CustomUser.EMPLOYEE
    default_role = settings.OIDC_DEFAULT_ROLE.upper()
    return default_role if default_role in {CustomUser.ADMIN, CustomUser.EMPLOYEE, CustomUser.INTERN} else CustomUser.INTERN


def upsert_enterprise_user(profile: OIDCProfile) -> CustomUser:
    provider = settings.OIDC_PROVIDER_NAME
    user = (
        CustomUser.objects.filter(auth_provider=provider, external_subject=profile.subject).first()
        or CustomUser.objects.filter(email=profile.email).first()
    )

    if user is None:
        username = _unique_username(profile.email.split("@")[0])
        user = CustomUser(username=username, email=profile.email)
        user.set_unusable_password()

    user.email = profile.email
    user.full_name = profile.full_name
    user.role = profile.role
    user.auth_provider = provider
    user.external_subject = profile.subject
    user.tenant_id = profile.tenant_id
    user.department = profile.department
    user.identity_claims = profile.claims
    user.last_sso_login = timezone.now()
    user.is_active = True
    user.save()
    return user


def _redirect_uri(request) -> str:
    configured = getattr(settings, "OIDC_REDIRECT_URI", "")
    if configured:
        return configured
    return request.build_absolute_uri(reverse("oidc_callback"))


def _claim_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _safe_claims(claims: dict) -> dict:
    blocked = {"at_hash", "c_hash", "access_token", "refresh_token"}
    return {key: value for key, value in claims.items() if key not in blocked}


def _unique_username(base: str) -> str:
    candidate = "".join(ch for ch in base.lower() if ch.isalnum() or ch in "._-")[:120] or "sso-user"
    username = candidate
    counter = 1
    while CustomUser.objects.filter(username=username).exists():
        username = f"{candidate[:110]}{counter}"
        counter += 1
    return username
