from __future__ import annotations

from .base import agent_report
from ..policy_engine import apply_policy


class PolicyAgent:
    """Applies role-aware firewall policy to all detections."""

    name = "policy_agent"

    def run(self, role: str, detections, direction: str = "PROMPT") -> dict:
        policy = apply_policy(role, detections, direction=direction)
        action = policy["action"]
        found = bool(detections)
        confidence = 1.0 if found else 0.99
        reason = (
            f"Role policy for {role} selected {action}."
            if found
            else f"Role policy for {role} found no restrictions."
        )
        return agent_report(
            name=self.name,
            found=found,
            types=sorted({d.dtype for d in detections}),
            action=action,
            confidence=confidence,
            reason=reason,
            extra={
                "reasons": policy["reasons"],
                "tokenize_count": len(policy["tokenize_targets"]),
            },
        )
