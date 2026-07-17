from django.test import RequestFactory, TestCase, override_settings

from users.models import CustomUser
from users.oidc import (
    build_authorization_url,
    enterprise_sso_available,
    profile_from_claims,
    role_from_claims,
    upsert_enterprise_user,
)


@override_settings(
    ENTERPRISE_SSO_ENABLED=True,
    OIDC_PROVIDER_NAME="test-oidc",
    OIDC_CLIENT_ID="sentinell-client",
    OIDC_AUTHORIZE_URL="https://idp.example.com/authorize",
    OIDC_TOKEN_URL="https://idp.example.com/token",
    OIDC_REDIRECT_URI="http://testserver/oidc/callback/",
    OIDC_ROLE_CLAIM="groups",
    OIDC_ADMIN_GROUPS=["SentinellAdmins"],
    OIDC_EMPLOYEE_GROUPS=["SentinellEmployees"],
    OIDC_DEFAULT_ROLE="INTERN",
)
class EnterpriseSSOTests(TestCase):
    def test_enterprise_sso_availability_requires_config(self):
        self.assertTrue(enterprise_sso_available())

    def test_build_authorization_url_sets_state_and_nonce(self):
        request = RequestFactory().get("/oidc/login/")
        request.session = {}

        url = build_authorization_url(request)

        self.assertIn("https://idp.example.com/authorize?", url)
        self.assertIn("client_id=sentinell-client", url)
        self.assertIn("response_type=code", url)
        self.assertIn("oidc_state", request.session)
        self.assertIn("oidc_nonce", request.session)

    def test_admin_group_maps_to_admin_role(self):
        role = role_from_claims({"groups": ["SentinellAdmins"]})
        self.assertEqual(role, CustomUser.ADMIN)

    def test_employee_group_maps_to_employee_role(self):
        role = role_from_claims({"groups": ["SentinellEmployees"]})
        self.assertEqual(role, CustomUser.EMPLOYEE)

    def test_unknown_group_uses_default_role(self):
        role = role_from_claims({"groups": ["Unknown"]})
        self.assertEqual(role, CustomUser.INTERN)

    def test_profile_from_claims_extracts_zero_trust_context(self):
        profile = profile_from_claims({
            "sub": "idp-user-123",
            "email": "analyst@example.com",
            "name": "Security Analyst",
            "groups": ["SentinellEmployees"],
            "tid": "tenant-1",
            "department": "Security",
        })

        self.assertEqual(profile.subject, "idp-user-123")
        self.assertEqual(profile.email, "analyst@example.com")
        self.assertEqual(profile.role, CustomUser.EMPLOYEE)
        self.assertEqual(profile.tenant_id, "tenant-1")
        self.assertEqual(profile.department, "Security")

    def test_upsert_enterprise_user_creates_and_updates_user(self):
        profile = profile_from_claims({
            "sub": "idp-user-456",
            "email": "admin@example.com",
            "name": "Admin User",
            "groups": ["SentinellAdmins"],
            "tid": "tenant-2",
            "department": "Security",
        })

        user = upsert_enterprise_user(profile)
        self.assertEqual(user.auth_provider, "test-oidc")
        self.assertEqual(user.external_subject, "idp-user-456")
        self.assertEqual(user.role, CustomUser.ADMIN)
        self.assertFalse(user.has_usable_password())

        updated_profile = profile_from_claims({
            "sub": "idp-user-456",
            "email": "admin@example.com",
            "name": "Admin User",
            "groups": ["SentinellEmployees"],
            "tid": "tenant-2",
            "department": "Compliance",
        })
        updated_user = upsert_enterprise_user(updated_profile)

        self.assertEqual(updated_user.id, user.id)
        self.assertEqual(updated_user.role, CustomUser.EMPLOYEE)
        self.assertEqual(updated_user.department, "Compliance")
        self.assertEqual(updated_user.identity_context["auth_provider"], "test-oidc")
