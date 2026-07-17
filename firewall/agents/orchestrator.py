from __future__ import annotations

from .base import detection_types
from .contextual_pii_agent import ContextualPIIAgent
from .injection_agent import PromptInjectionAgent
from .pii_agent import PIIAgent
from .policy_agent import PolicyAgent
from .risk_agent import RiskAgent
from .semantic_agent import SemanticSecurityAgent
from .secrets_agent import SecretsAgent
from ..policy_engine import apply_policy
from ..policy_rules import apply_policy_rules
from ..risk_scorer import calculate_risk, classify_risk
from ..scanner import scan


class SecurityOrchestrator:
    """
    Coordinates specialized security agents around the existing firewall engine.

    The first implementation is deterministic: it uses the current scanner,
    policy engine, and risk scorer. Later, any agent can add an LLM-backed
    semantic check while keeping the same output contract.
    """

    def __init__(self):
        self.pii_agent = PIIAgent()
        self.contextual_pii_agent = ContextualPIIAgent()
        self.secrets_agent = SecretsAgent()
        self.injection_agent = PromptInjectionAgent()
        self.semantic_agent = SemanticSecurityAgent()
        self.policy_agent = PolicyAgent()
        self.risk_agent = RiskAgent()

    def analyze(self, *, role: str, prompt: str, direction: str = "PROMPT", source: str = "") -> dict:
        detections = scan(prompt)
        policy = apply_policy(role, detections, direction=direction)
        risk = calculate_risk(role, detections, direction=direction)
        policy, risk, policy_rule_trace = apply_policy_rules(
            role=role,
            text=prompt,
            detections=detections,
            policy=policy,
            risk=risk,
            direction=direction,
            source=source,
        )
        semantic_report = self.semantic_agent.run(prompt=prompt, detections=detections)
        policy, risk = self._apply_semantic_decision(policy, risk, semantic_report)
        detected_types = detection_types(detections)
        if semantic_report.get("found"):
            detected_types = sorted(set(detected_types) | set(semantic_report.get("types", [])))

        trace = {
            "orchestrator": {
                "role": role,
                "direction": direction,
                "source": source,
                "detected_types": detected_types,
                "agent_count": 7,
            },
            "pii_agent": self.pii_agent.run(detections),
            "contextual_pii_agent": self.contextual_pii_agent.run(detections),
            "secrets_agent": self.secrets_agent.run(detections),
            "prompt_injection_agent": self.injection_agent.run(detections),
            "semantic_security_agent": semantic_report,
            "policy_agent": self.policy_agent.run(role, detections, direction=direction),
            "policy_rule_engine": policy_rule_trace,
            "risk_agent": self.risk_agent.run(role, detections, direction=direction),
            "final_decision": {
                "action": policy["action"],
                "risk_score": risk["score"],
                "risk_level": risk["level"],
                "semantic_elevated": bool(semantic_report.get("found") and semantic_report.get("action") == "BLOCK"),
            },
        }

        return {
            "detections": detections,
            "detected_types": detected_types,
            "policy": policy,
            "risk": risk,
            "agent_trace": trace,
        }

    @staticmethod
    def _apply_semantic_decision(policy: dict, risk: dict, semantic_report: dict) -> tuple[dict, dict]:
        if not semantic_report.get("found") or semantic_report.get("action") != "BLOCK":
            return policy, risk

        elevated_policy = {
            **policy,
            "action": "BLOCK",
            "reasons": [
                *policy.get("reasons", []),
                f"SemanticSecurityAgent blocked intent: {semantic_report.get('reason')}",
            ],
        }

        elevated_score = max(risk.get("score", 0), 85)
        elevated_risk = {
            **risk,
            "score": elevated_score,
            "level": classify_risk(elevated_score),
            "should_block": True,
        }
        return elevated_policy, elevated_risk
