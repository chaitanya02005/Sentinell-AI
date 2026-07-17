from __future__ import annotations

from .base import agent_report, values_for_types


INJECTION_TYPES = {
    "adversarial_injection",
    "encoded_payload",
    "social_engineering_injection",
    "credential_request",
}


class PromptInjectionAgent:
    """Detects jailbreaks, prompt injection, and credential-exfiltration intent."""

    name = "prompt_injection_agent"

    def run(self, detections) -> dict:
        types = values_for_types(detections, INJECTION_TYPES)
        if not types:
            return agent_report(
                name=self.name,
                found=False,
                action="ALLOW",
                confidence=0.94,
                reason="No prompt-injection or social-engineering pattern was detected.",
            )

        return agent_report(
            name=self.name,
            found=True,
            types=types,
            action="BLOCK",
            confidence=0.93,
            reason="Prompt-injection or social-engineering behavior was detected.",
        )
