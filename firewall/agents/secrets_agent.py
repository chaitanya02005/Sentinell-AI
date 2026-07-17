from __future__ import annotations

from .base import agent_report, values_for_types


SECRET_TYPES = {
    "api_key",
    "cloud_key",
    "password",
    "private_key",
    "encryption_key",
    "secret_token",
    "embedded_secret_key",
    "debug_env_dump",
    "credit_card",
    "financial_account",
    "ssn",
}


class SecretsAgent:
    """Detects credentials, secrets, and financial identifiers."""

    name = "secrets_agent"

    def run(self, detections) -> dict:
        types = values_for_types(detections, SECRET_TYPES)
        if not types:
            return agent_report(
                name=self.name,
                found=False,
                action="ALLOW",
                confidence=0.97,
                reason="No credentials, keys, or high-risk financial values were detected.",
            )

        return agent_report(
            name=self.name,
            found=True,
            types=types,
            action="BLOCK",
            confidence=0.96,
            reason="Credentials, keys, or high-risk financial values were detected.",
        )
