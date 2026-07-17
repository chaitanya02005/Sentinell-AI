from __future__ import annotations

from .base import agent_report, values_for_types


PII_TYPES = {
    "email",
    "phone",
    "phone_words",
    "contextual_pii",
    "aadhaar",
    "mac_address",
    "ip_address",
    "passport",
}


class PIIAgent:
    """Detects personal data that should be masked before AI processing."""

    name = "pii_agent"

    def run(self, detections) -> dict:
        types = values_for_types(detections, PII_TYPES)
        if not types:
            return agent_report(
                name=self.name,
                found=False,
                action="ALLOW",
                confidence=0.99,
                reason="No personal identifiers were detected.",
            )

        return agent_report(
            name=self.name,
            found=True,
            types=types,
            action="TOKENIZE",
            confidence=0.98,
            reason="Personal identifiers were detected and should be masked.",
        )
