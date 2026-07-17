from __future__ import annotations

from .models import PolicyRule
from .policy_engine import ALLOW, BLOCK, TOKENIZE
from .risk_scorer import classify_risk


_ACTION_STRENGTH = {
    ALLOW: 0,
    TOKENIZE: 1,
    BLOCK: 2,
}


def apply_policy_rules(
    *,
    role: str,
    text: str,
    detections: list,
    policy: dict,
    risk: dict,
    direction: str = PolicyRule.PROMPT,
    source: str = "",
) -> tuple[dict, dict, dict]:
    """
    Apply admin-managed policy rules as a stricter layer over built-in policy.

    Rules are intentionally additive. They can tokenize or block more cases, but
    they do not weaken built-in universal blocks.
    """
    trace = {
        "enabled": True,
        "direction": direction,
        "matched_rules": [],
        "rule_count": 0,
    }

    try:
        rules = list(PolicyRule.objects.filter(enabled=True).order_by("priority", "name"))
    except Exception as exc:
        trace.update({
            "enabled": False,
            "error": str(exc),
        })
        return policy, risk, trace

    trace["rule_count"] = len(rules)
    if not rules:
        return policy, risk, trace

    final_policy = {
        **policy,
        "reasons": list(policy.get("reasons", [])),
        "tokenize_targets": list(policy.get("tokenize_targets", [])),
    }
    final_risk = dict(risk)

    for rule in rules:
        match = _rule_matches(
            rule=rule,
            role=role,
            text=text,
            detections=detections,
            risk=final_risk,
            direction=direction,
            source=source,
        )
        if not match["matched"]:
            continue

        reason = rule.reason or f"Policy rule '{rule.name}' matched."
        trace["matched_rules"].append({
            "id": rule.pk,
            "name": rule.name,
            "action": rule.action,
            "priority": rule.priority,
            "matched_on": match["matched_on"],
        })
        final_policy["reasons"].append(f"PolicyRule[{rule.name}]: {reason}")

        if rule.action == TOKENIZE:
            final_policy["tokenize_targets"] = _merge_tokenize_targets(
                final_policy["tokenize_targets"],
                _matching_detections(rule, detections),
            )

        if _ACTION_STRENGTH[rule.action] > _ACTION_STRENGTH.get(final_policy["action"], 0):
            final_policy["action"] = rule.action

        if rule.action == BLOCK:
            final_risk = _elevate_risk(final_risk, 70)
        elif rule.action == TOKENIZE:
            final_risk = _elevate_risk(final_risk, 40)

    return final_policy, final_risk, trace


def _rule_matches(*, rule, role: str, text: str, detections: list, risk: dict, direction: str, source: str) -> dict:
    matched_on = []
    rule_direction = str(rule.direction or PolicyRule.BOTH).upper()
    if rule_direction not in {PolicyRule.BOTH, direction.upper()}:
        return {"matched": False, "matched_on": matched_on}

    role_upper = role.upper()
    roles = _upper_list(rule.roles)
    excluded_roles = _upper_list(rule.excluded_roles)
    if roles and role_upper not in roles:
        return {"matched": False, "matched_on": matched_on}
    if excluded_roles and role_upper in excluded_roles:
        return {"matched": False, "matched_on": matched_on}

    if rule.source_contains and rule.source_contains.lower() not in source.lower():
        return {"matched": False, "matched_on": matched_on}

    if rule.min_risk_score and risk.get("score", 0) < rule.min_risk_score:
        return {"matched": False, "matched_on": matched_on}
    if rule.min_risk_score:
        matched_on.append("risk_score")

    detected_types = {d.dtype for d in detections}
    required_types = set(_lower_list(rule.detection_types))
    if required_types:
        matched_types = sorted(detected_types & required_types)
        if not matched_types:
            return {"matched": False, "matched_on": matched_on}
        matched_on.append(f"detection_types:{','.join(matched_types)}")

    keywords = _lower_list(rule.keywords)
    if keywords:
        lower_text = text.lower()
        matched_keywords = [keyword for keyword in keywords if keyword and keyword in lower_text]
        if not matched_keywords:
            return {"matched": False, "matched_on": matched_on}
        matched_on.append(f"keywords:{','.join(matched_keywords[:5])}")

    if not required_types and not keywords and not rule.min_risk_score:
        matched_on.append("scope")

    return {"matched": True, "matched_on": matched_on}


def _matching_detections(rule, detections: list) -> list:
    required_types = set(_lower_list(rule.detection_types))
    if not required_types:
        return detections
    return [d for d in detections if d.dtype in required_types]


def _merge_tokenize_targets(existing: list, extra: list) -> list:
    seen = {(d.start, d.end, d.dtype) for d in existing}
    merged = list(existing)
    for detection in extra:
        key = (detection.start, detection.end, detection.dtype)
        if key not in seen:
            seen.add(key)
            merged.append(detection)
    return merged


def _elevate_risk(risk: dict, minimum_score: int) -> dict:
    score = max(int(risk.get("score", 0)), minimum_score)
    return {
        **risk,
        "score": score,
        "level": classify_risk(score),
        "should_block": bool(risk.get("should_block") or score >= 60),
    }


def _upper_list(value) -> list[str]:
    return [str(item).strip().upper() for item in (value or []) if str(item).strip()]


def _lower_list(value) -> list[str]:
    return [str(item).strip().lower() for item in (value or []) if str(item).strip()]
