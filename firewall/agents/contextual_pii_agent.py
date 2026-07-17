from __future__ import annotations

from .base import agent_report, values_for_types


CONTEXTUAL_PII_TYPES = {"contextual_pii"}


class ContextualPIIAgent:
    """Flags unknown-format identifiers inferred from sensitive context."""

    name = "contextual_pii_agent"

    def run(self, detections) -> dict:
        types = values_for_types(detections, CONTEXTUAL_PII_TYPES)
        if not types:
            return agent_report(
                name=self.name,
                found=False,
                action="ALLOW",
                confidence=0.93,
                reason="No context-labeled unknown identifiers were detected.",
            )

        return agent_report(
            name=self.name,
            found=True,
            types=types,
            action="TOKENIZE",
            confidence=0.86,
            reason=(
                "A value was labeled as personal, customer, employee, account, "
                "medical, address, or company identifier data and should be masked."
            ),
        )
