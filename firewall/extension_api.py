import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from users.models import ExtensionToken

from .agents import SecurityOrchestrator
from .encryption import encrypt
from .file_scanning import scan_uploaded_file
from .models import PromptLog, ResponseLog, TokenMap
from .tokenization import tokenize
from .vault import seal_value


def _bearer_user(request):
    auth = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth.startswith(prefix):
        return None
    return ExtensionToken.authenticate(auth[len(prefix):].strip())


@csrf_exempt
@require_POST
def firewall_check(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": "Missing or invalid extension token."}, status=401)

    try:
        body = json.loads(request.body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    text = body.get("text", "")
    source = str(body.get("source", "browser_extension"))[:80]
    if not isinstance(text, str) or not text.strip():
        return JsonResponse({"error": "Field 'text' is required."}, status=400)

    original_prompt = text.strip()
    orchestration = SecurityOrchestrator().analyze(
        role=user.role,
        prompt=original_prompt,
        direction="PROMPT",
        source=source,
    )
    detections = orchestration["detections"]
    policy = orchestration["policy"]
    risk = orchestration["risk"]
    action = policy["action"]
    reasons = policy["reasons"]
    tokenize_targets = policy["tokenize_targets"]
    detected_types = orchestration["detected_types"]
    agent_trace = orchestration["agent_trace"]
    agent_trace["identity_context"] = user.identity_context

    processed_prompt = original_prompt
    token_map = {}
    if tokenize_targets:
        processed_prompt, token_map = tokenize(original_prompt, tokenize_targets)
        for label, original_value in token_map.items():
            sealed = seal_value(
                original_value,
                purpose="pii_token_map",
                context={"source": source, "direction": "PROMPT"},
            )
            TokenMap.objects.create(
                user=user,
                token_label=label[:30],
                **sealed.model_fields(),
            )

    if action == "BLOCK":
        processed_for_log = "[BLOCKED - extension did not forward]"
        ai_response = "[BLOCKED]"
        forwardable_prompt = ""
    else:
        processed_for_log = processed_prompt
        ai_response = "[EXTENSION_CHECK_ONLY]"
        forwardable_prompt = processed_prompt

    PromptLog.objects.create(
        user=user,
        original_prompt=encrypt(original_prompt),
        processed_prompt=processed_for_log,
        detected_types=detected_types,
        action=action,
        reasons=[f"[{source}] {reason}" for reason in reasons],
        risk_score=risk["score"],
        risk_level=risk["level"],
        agent_trace=agent_trace,
        ai_response=ai_response,
    )

    return JsonResponse({
        "action": action,
        "processed_prompt": forwardable_prompt,
        "original_changed": bool(token_map),
        "detected_types": detected_types,
        "reasons": reasons,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "agent_trace": {
            "semantic_security_agent": agent_trace.get("semantic_security_agent", {}),
            "final_decision": agent_trace.get("final_decision", {}),
            "identity_context": agent_trace.get("identity_context", {}),
        },
    })


@csrf_exempt
@require_POST
def firewall_check_response(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": "Missing or invalid extension token."}, status=401)

    try:
        body = json.loads(request.body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    text = body.get("text", "")
    source = str(body.get("source", "browser_extension"))[:80]
    if not isinstance(text, str) or not text.strip():
        return JsonResponse({"error": "Field 'text' is required."}, status=400)

    original_response = text.strip()
    orchestration = SecurityOrchestrator().analyze(
        role=user.role,
        prompt=original_response,
        direction="RESPONSE",
        source=source,
    )
    policy = orchestration["policy"]
    risk = orchestration["risk"]
    action = policy["action"]
    reasons = policy["reasons"]
    tokenize_targets = policy["tokenize_targets"]
    detected_types = orchestration["detected_types"]
    agent_trace = orchestration["agent_trace"]
    agent_trace["identity_context"] = user.identity_context

    processed_response = original_response
    token_map = {}
    if tokenize_targets:
        processed_response, token_map = tokenize(original_response, tokenize_targets)
        for label, original_value in token_map.items():
            sealed = seal_value(
                original_value,
                purpose="pii_token_map",
                context={"source": source, "direction": "RESPONSE"},
            )
            TokenMap.objects.create(
                user=user,
                token_label=label[:30],
                **sealed.model_fields(),
            )

    response_action = "ALLOW"
    display_response = original_response
    if action == "BLOCK":
        response_action = "BLOCK"
        display_response = "[RESPONSE BLOCKED - unsafe AI output hidden by Sentinell.AI]"
        processed_for_log = display_response
    elif token_map:
        response_action = "REDACT"
        display_response = processed_response
        processed_for_log = processed_response
    else:
        processed_for_log = original_response

    ResponseLog.objects.create(
        user=user,
        source=source,
        original_response=encrypt(original_response),
        processed_response=processed_for_log,
        detected_types=detected_types,
        action=response_action,
        reasons=[f"[{source}] {reason}" for reason in reasons],
        risk_score=risk["score"],
        risk_level=risk["level"],
        agent_trace=agent_trace,
    )

    return JsonResponse({
        "action": response_action,
        "backend_policy_action": action,
        "processed_response": display_response,
        "original_changed": display_response != original_response,
        "detected_types": detected_types,
        "reasons": reasons,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "agent_trace": {
            "semantic_security_agent": agent_trace.get("semantic_security_agent", {}),
            "final_decision": agent_trace.get("final_decision", {}),
            "identity_context": agent_trace.get("identity_context", {}),
        },
    })


@csrf_exempt
@require_POST
def firewall_check_file(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": "Missing or invalid extension token."}, status=401)

    uploaded = request.FILES.get("document")
    if uploaded is None:
        return JsonResponse({"error": "No file uploaded. Use field name 'document'."}, status=400)

    source = str(request.POST.get("source", "browser_extension_file"))[:80]
    result = scan_uploaded_file(user, uploaded, source=source)
    return JsonResponse(result.payload, status=result.status_code)
