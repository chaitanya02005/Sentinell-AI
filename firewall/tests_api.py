"""
firewall/tests_api.py
=====================
Test cases for the DLP API endpoints and detect_sensitive().

Run with:
    python manage.py test firewall.tests_api
"""

import json
import io
import base64
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import mlkem
from django.test import TestCase, Client

from firewall.llm_gateway import GatewayLLMResponse
from firewall.models import PolicyRule, PromptLog, ResponseLog, TokenMap
from firewall.vault import open_value
from users.models import CustomUser, ExtensionToken


class DetectSensitiveTests(TestCase):
    """Unit tests for the detect_sensitive() function."""

    def setUp(self):
        from firewall.detector import detect_sensitive
        self.detect = detect_sensitive

    def test_email_is_blocked(self):
        self.assertEqual(self.detect("Contact me at john@gmail.com"), "BLOCK")

    def test_phone_is_blocked(self):
        self.assertEqual(self.detect("Call me on 9876543210"), "BLOCK")

    def test_bank_account_is_blocked(self):
        self.assertEqual(self.detect("Account number: 123456789012"), "BLOCK")

    def test_ifsc_triggers_block(self):
        # IFSC matches financial_account / embedded pattern
        self.assertEqual(self.detect("IFSC: SBIN0001234"), "BLOCK")

    def test_credit_card_is_blocked(self):
        self.assertEqual(self.detect("Card: 4111 1111 1111 1111"), "BLOCK")

    def test_api_key_is_blocked(self):
        self.assertEqual(self.detect("My key is example-api-key-abc123456789abcdef"), "BLOCK")

    def test_normal_sentence_is_safe(self):
        self.assertEqual(self.detect("What is the weather like today?"), "SAFE")

    def test_empty_string_is_safe(self):
        self.assertEqual(self.detect(""), "SAFE")

    def test_generic_question_is_safe(self):
        self.assertEqual(self.detect("Explain how neural networks work."), "SAFE")

    def test_password_is_blocked(self):
        self.assertEqual(self.detect("password=SuperSecret123"), "BLOCK")


class DashboardControlPlaneTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username="dashboard-admin",
            email="dashboard@example.com",
            password="Dashboard123!",
            role=CustomUser.ADMIN,
        )
        PromptLog.objects.create(
            user=self.user,
            original_prompt="encrypted",
            processed_prompt="safe",
            detected_types=["email"],
            action="TOKENIZE",
            reasons=["Email masked"],
            risk_score=40,
            risk_level="MODERATE",
            agent_trace={"semantic_security_agent": {"mode": "groq"}},
            ai_response="ok",
        )
        ResponseLog.objects.create(
            user=self.user,
            source="gemini",
            original_response="encrypted",
            processed_response="[BLOCKED]",
            detected_types=["api_key"],
            action="BLOCK",
            reasons=["Credential blocked"],
            risk_score=90,
            risk_level="CRITICAL",
            agent_trace={},
        )
        PolicyRule.objects.create(name="Dashboard test rule", enabled=True, action="BLOCK")

    def test_dashboard_renders_operational_security_metrics(self):
        self.client.force_login(self.user)
        response = self.client.get("/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Security Overview")
        self.assertContains(response, "Health Score")
        self.assertContains(response, "Post-Quantum Vault")
        self.assertNotContains(response, "Run Security Check")
        self.assertNotContains(response, "Live Security Events")
        self.assertNotContains(response, "Protection Stack")
        self.assertEqual(response.context["total_checks"], 2)
        self.assertEqual(response.context["interventions"], 2)
        self.assertEqual(response.context["blocked_responses"], 1)

    def test_employee_dashboard_stays_focused_and_hides_admin_actions(self):
        employee = CustomUser.objects.create_user(
            username="dashboard-employee",
            email="dashboard-employee@example.com",
            password="Employee123!",
            role=CustomUser.EMPLOYEE,
        )
        self.client.force_login(employee)

        response = self.client.get("/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Security Overview")
        self.assertNotContains(response, "Run Security Check")
        self.assertNotContains(response, "Live Security Events")
        self.assertNotContains(response, "Protection Stack")
        self.assertNotContains(response, 'class="quiet-action"')

    def test_login_page_does_not_expose_demo_credentials_or_product_pitch(self):
        response = self.client.get("/login/")

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Demo Logins")
        self.assertNotContains(response, "advanced middleware")
        self.assertNotContains(response, "Intelligent Regex Detection")


class AuditLogDeletionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = CustomUser.objects.create_user(
            username="log-admin",
            email="log-admin@example.com",
            password="Admin123!",
            role=CustomUser.ADMIN,
        )
        self.employee = CustomUser.objects.create_user(
            username="log-employee",
            email="log-employee@example.com",
            password="Employee123!",
            role=CustomUser.EMPLOYEE,
        )
        self.log = PromptLog.objects.create(
            user=self.employee,
            original_prompt="encrypted",
            processed_prompt="safe",
            detected_types=[],
            action="ALLOW",
            reasons=[],
            risk_score=0,
            risk_level="LOW",
            agent_trace={},
            ai_response="ok",
        )

    def test_admin_can_delete_audit_log(self):
        self.client.force_login(self.admin)

        response = self.client.post(f"/logs/{self.log.id}/delete/")

        self.assertRedirects(response, "/logs/")
        self.assertFalse(PromptLog.objects.filter(pk=self.log.id).exists())

    def test_employee_cannot_delete_audit_log(self):
        self.client.force_login(self.employee)

        response = self.client.post(f"/logs/{self.log.id}/delete/")

        self.assertRedirects(response, "/dashboard/")
        self.assertTrue(PromptLog.objects.filter(pk=self.log.id).exists())

    def test_delete_endpoint_rejects_get(self):
        self.client.force_login(self.admin)

        response = self.client.get(f"/logs/{self.log.id}/delete/")

        self.assertEqual(response.status_code, 405)
        self.assertTrue(PromptLog.objects.filter(pk=self.log.id).exists())


class AnalyzeEndpointTests(TestCase):
    """Integration tests for POST /analyze."""

    def setUp(self):
        self.client = Client()

    def test_safe_text(self):
        resp = self.client.post(
            "/analyze",
            data=json.dumps({"text": "Hello, how are you?"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "SAFE"})

    def test_email_blocked(self):
        resp = self.client.post(
            "/analyze",
            data=json.dumps({"text": "Reach me at alice@example.com"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "BLOCK"})

    def test_phone_blocked(self):
        resp = self.client.post(
            "/analyze",
            data=json.dumps({"text": "My number is 9123456780"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "BLOCK"})

    def test_missing_text_field(self):
        resp = self.client.post(
            "/analyze",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_invalid_json(self):
        resp = self.client.post(
            "/analyze",
            data="not json",
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class AnalyzeFileEndpointTests(TestCase):
    """Integration tests for POST /analyze-file."""

    def setUp(self):
        self.client = Client()

    def test_txt_safe(self):
        f = io.BytesIO(b"The sky is blue and the grass is green.")
        f.name = "note.txt"
        resp = self.client.post("/analyze-file", {"document": f})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "SAFE"})

    def test_txt_blocked_email(self):
        f = io.BytesIO(b"Please contact support@company.com for help.")
        f.name = "email.txt"
        resp = self.client.post("/analyze-file", {"document": f})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "BLOCK"})

    def test_txt_blocked_phone(self):
        f = io.BytesIO(b"Call us at 9988776655 anytime.")
        f.name = "contact.txt"
        resp = self.client.post("/analyze-file", {"document": f})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "BLOCK"})

    def test_no_file_returns_400(self):
        resp = self.client.post("/analyze-file", {})
        self.assertEqual(resp.status_code, 400)

    def test_unsupported_format_returns_422(self):
        f = io.BytesIO(b"\x00\x01\x02")
        f.name = "archive.bin"
        resp = self.client.post("/analyze-file", {"document": f})
        self.assertEqual(resp.status_code, 422)


class AuthenticatedFileFirewallTests(TestCase):
    """Authenticated file scanning for extension and gateway flows."""

    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username="file_employee",
            email="file-employee@example.com",
            password="StrongPass123!",
            role=CustomUser.EMPLOYEE,
        )
        _, self.token = ExtensionToken.issue_for_user(self.user)

    def post_file(self, url, content, name="upload.txt"):
        f = io.BytesIO(content)
        f.name = name
        return self.client.post(
            url,
            {"document": f, "source": "test_file_scan"},
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def test_extension_file_scan_allows_safe_text_file(self):
        resp = self.post_file(
            "/firewall/check-file",
            b"Meeting notes about zero trust architecture.",
            "notes.txt",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "ALLOW")
        self.assertTrue(body["safe_to_upload"])
        self.assertEqual(body["file"]["name"], "notes.txt")

    def test_extension_file_scan_blocks_tokenizable_pii_upload(self):
        resp = self.post_file(
            "/firewall/check-file",
            b"Customer email: person@example.com",
            "customer.csv",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "TOKENIZE")
        self.assertFalse(body["safe_to_upload"])
        self.assertIn("p***@***.com", body["processed_text"])
        self.assertNotIn("person@example.com", body["processed_text"])
        self.assertTrue(TokenMap.objects.filter(user=self.user).exists())

    def test_extension_file_scan_blocks_secret_file(self):
        resp = self.post_file(
            "/firewall/check-file",
            b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ".env",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "BLOCK")
        self.assertFalse(body["safe_to_upload"])

    def test_gateway_file_scan_wraps_result_for_company_apps(self):
        resp = self.post_file(
            "/gateway/files/scan",
            b"Explain security architecture without secrets.",
            "design.md",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "OK")
        self.assertTrue(body["gateway"]["forwardable"])
        self.assertEqual(body["file_scan"]["action"], "ALLOW")


class ExtensionResponseFirewallTests(TestCase):
    """Integration tests for AI response-side monitoring."""

    def setUp(self):
        private_key = mlkem.MLKEM1024PrivateKey.generate()
        public_key = private_key.public_key()
        self.vault_settings = self.settings(
            TOKEN_VAULT_PROVIDER="ml-kem-1024-aesgcm-v1",
            TOKEN_VAULT_KEY_ID="mlkem1024-test",
            MLKEM1024_PUBLIC_KEY=base64.urlsafe_b64encode(public_key.public_bytes_raw()).decode("ascii"),
            MLKEM1024_PRIVATE_KEY=base64.urlsafe_b64encode(private_key.private_bytes_raw()).decode("ascii"),
        )
        self.vault_settings.enable()
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username="employee",
            email="employee@example.com",
            password="StrongPass123!",
            role=CustomUser.EMPLOYEE,
        )
        _, self.token = ExtensionToken.issue_for_user(self.user)

    def tearDown(self):
        self.vault_settings.disable()

    def post_response(self, text):
        return self.client.post(
            "/firewall/check-response",
            data=json.dumps({"text": text, "source": "test_extension"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def test_safe_response_allowed(self):
        resp = self.post_response("Zero trust means every access request is verified.")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "ALLOW")
        self.assertEqual(body["risk_level"], "LOW")

    def test_safe_generated_source_code_is_allowed(self):
        resp = self.post_response(
            "Practice by writing small programs. For example:\n"
            "def greet(name):\n"
            "    return f'Hello {name}'"
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "ALLOW")
        self.assertIn("source_code", body["detected_types"])
        self.assertEqual(body["risk_level"], "LOW")

    def test_generated_source_code_with_secret_is_blocked(self):
        resp = self.post_response(
            "const apiKey = 'sk-1234567890abcdef1234567890abcdef';"
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "BLOCK")
        self.assertIn("source_code", body["detected_types"])
        self.assertIn("api_key", body["detected_types"])

    def test_response_pii_is_redacted(self):
        resp = self.post_response("The user email is person@example.com.")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "REDACT")
        self.assertIn("p***@***.com", body["processed_response"])
        self.assertNotIn("person@example.com", body["processed_response"])

        token = TokenMap.objects.get(user=self.user)
        self.assertEqual(token.vault_provider, "ml-kem-1024-aesgcm-v1")
        self.assertEqual(token.vault_version, 2)
        self.assertEqual(open_value(token.encrypted_value), "person@example.com")

    def test_response_secret_is_blocked(self):
        resp = self.post_response("Use API key sk-1234567890abcdef1234567890abcdef.")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "BLOCK")
        self.assertIn("unsafe AI output hidden", body["processed_response"])

    def test_response_verbose_debug_env_dump_is_blocked(self):
        resp = self.post_response("""
        Here's a mock HTTP 500 JSON response:
        {
          "error": {"code": "VERBOSE_DEBUG_ERROR"},
          "environment": {
            "DATABASE_URL": "postgres://user:password@localhost/database",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "JWT_SECRET_KEY": "placeholder-only"
          }
        }
        """)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "BLOCK")
        self.assertIn("debug_env_dump", body["detected_types"])
        self.assertIn("unsafe AI output hidden", body["processed_response"])

    def test_response_redacted_debug_env_shape_is_blocked(self):
        resp = self.post_response("""
        {
          "error": {"code": "VERBOSE_DEBUG_ERROR"},
          "environment": {
            "DB_PASSWORD": "[REDACTED]",
            "JWT_SECRET": "[REDACTED]",
            "API_KEY": "[REDACTED]"
          }
        }
        """)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["action"], "BLOCK")
        self.assertIn("debug_env_dump", body["detected_types"])


class GatewayChatTests(TestCase):
    """Integration tests for the enterprise gateway API."""

    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username="gateway_employee",
            email="gateway@example.com",
            password="StrongPass123!",
            role=CustomUser.EMPLOYEE,
        )
        _, self.token = ExtensionToken.issue_for_user(self.user)

    def post_gateway(self, prompt, **extra):
        payload = {"prompt": prompt, "source": "test_gateway"}
        payload.update(extra)
        return self.client.post(
            "/gateway/chat",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    @patch("firewall.gateway_api.generate_gateway_response")
    def test_gateway_allows_safe_prompt_and_response(self, mock_generate):
        mock_generate.return_value = GatewayLLMResponse(
            provider="mock",
            model="sentinell-mock-ai",
            content="Zero trust verifies every request.",
        )
        resp = self.post_gateway("Explain zero trust.")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "OK")
        self.assertEqual(body["gateway"]["provider"], "mock")
        self.assertEqual(body["prompt"]["action"], "ALLOW")
        self.assertEqual(body["response"]["action"], "ALLOW")
        mock_generate.assert_called_once()

    @patch("firewall.gateway_api.generate_gateway_response")
    def test_gateway_blocks_prompt_before_ai_call(self, mock_generate):
        resp = self.post_gateway("Use API key sk-1234567890abcdef1234567890abcdef.")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "BLOCKED")
        self.assertEqual(body["prompt"]["action"], "BLOCK")
        self.assertIsNone(body["response"])
        mock_generate.assert_not_called()

    @patch("firewall.gateway_api.generate_gateway_response")
    def test_gateway_accepts_provider_neutral_messages(self, mock_generate):
        mock_generate.return_value = GatewayLLMResponse(
            provider="groq",
            model="llama-3.3-70b-versatile",
            content="I can help with that.",
        )
        resp = self.client.post(
            "/gateway/chat",
            data=json.dumps({
                "provider": "groq",
                "model": "llama-3.3-70b-versatile",
                "source": "crm_app",
                "messages": [
                    {"role": "system", "content": "You help support teams."},
                    {"role": "user", "content": "My email is person@example.com. Draft a reply."},
                ],
                "metadata": {"tenant": "demo"},
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "OK")
        self.assertEqual(body["gateway"]["provider"], "groq")
        self.assertEqual(body["prompt"]["action"], "TOKENIZE")
        self.assertIn("p***@***.com", body["prompt"]["processed_messages"][1]["content"])
        self.assertNotIn("person@example.com", body["prompt"]["processed_messages"][1]["content"])
        self.assertEqual(mock_generate.call_args.args[0].provider, "groq")
        self.assertEqual(mock_generate.call_args.args[0].messages[1]["role"], "user")

    @patch("firewall.gateway_api.generate_gateway_response")
    def test_openai_compatible_endpoint_returns_chat_completion_shape(self, mock_generate):
        mock_generate.return_value = GatewayLLMResponse(
            provider="mock",
            model="sentinell-mock-ai",
            content="Zero trust verifies every request.",
        )

        resp = self.client.post(
            "/gateway/v1/chat/completions",
            data=json.dumps({
                "model": "sentinell-mock-ai",
                "messages": [{"role": "user", "content": "Explain zero trust."}],
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["object"], "chat.completion")
        self.assertEqual(body["choices"][0]["message"]["role"], "assistant")
        self.assertEqual(body["choices"][0]["message"]["content"], "Zero trust verifies every request.")
        self.assertEqual(body["sentinell"]["prompt"]["action"], "ALLOW")

    def test_gateway_providers_lists_available_adapters(self):
        resp = self.client.get(
            "/gateway/providers",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

        self.assertEqual(resp.status_code, 200)
        provider_ids = {provider["id"] for provider in resp.json()["providers"]}
        self.assertIn("mock", provider_ids)
        self.assertIn("groq", provider_ids)

    @patch("firewall.gateway_api.generate_gateway_response")
    def test_gateway_demo_forwards_masked_prompt_to_private_llm(self, mock_generate):
        mock_generate.return_value = GatewayLLMResponse(
            provider="openai_compatible",
            model="llama3.2",
            content="Draft ready.",
        )
        self.client.force_login(self.user)

        response = self.client.post(
            "/gateway-demo/",
            data={
                "provider": "openai_compatible",
                "model": "llama3.2",
                "prompt": "My email is person@example.com. Draft a support reply.",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Prompt Sent To Ollama")
        self.assertContains(response, "p***@***.com")
        forwarded = mock_generate.call_args.args[0].messages[0]["content"]
        self.assertIn("p***@***.com", forwarded)
        self.assertNotIn("person@example.com", forwarded)
