from __future__ import annotations

from .base import agent_report
from ..risk_scorer import calculate_risk


class RiskAgent:
    """Produces the final context-aware risk score."""

    name = "risk_agent"

    def run(self, role: str, detections, direction: str = "PROMPT") -> dict:
        risk = calculate_risk(role, detections, direction=direction)
        score = risk["score"]
        level = risk["level"]
        action = "BLOCK" if risk["should_block"] else "ALLOW"
        return agent_report(
            name=self.name,
            found=bool(detections),
            types=sorted({d.dtype for d in detections}),
            action=action,
            confidence=0.95 if detections else 0.99,
            reason=f"Aggregate risk is {score}% ({level}).",
            extra=risk,
        )
