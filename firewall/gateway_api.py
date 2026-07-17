import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .agents import SecurityOrchestrator
from .encryption import encrypt
from .extension_api import _bearer_user
from .file_scanning import scan_uploaded_file
from .llm_gateway import GatewayLLMRequest, gateway_provider_catalog, generate_gateway_response
from .models import PromptLog, ResponseLog, TokenMap
from .tokenization import tokenize
from .vault import seal_value


INSPECTABLE_ROLES = {"system", "developer", "user", "tool"}


def _store_token_map(user, token_map: dict[str, str], *, source: str, direction: str):
    for label, original_value in token_map.items():
        sealed = seal_value(
            original_value,
            purpose="pii_token_map",
            context={"source": source, "direction": direction},
        )
        TokenMap.objects.create(
            user=user,
            token_label=label[:30],
            **sealed.model_fields(),
        )


def _inspect_prompt(user, prompt: str, source: str, *, role: str = "user") -> dict:
    orchestration = SecurityOrchestrator().analyze(
        role=user.role,
        prompt=prompt,
        direction="PROMPT",
        source=source,
    )
    orchestration["agent_trace"]["identity_context"] = user.identity_context
    policy = orchestration["policy"]
    risk = orchestration["risk"]
    action = policy["action"]
    token_map = {}
    processed_prompt = prompt

    if policy["tokenize_targets"]:
        processed_prompt, token_map = tokenize(prompt, policy["tokenize_targets"])
        _store_token_map(user, token_map, source=source, direction="PROMPT")

    if action == "BLOCK":
        logged_processed = "[BLOCKED - gateway did not forward]"
        forwardable_prompt = ""
        ai_response = "[BLOCKED]"
    else:
        logged_processed = processed_prompt
        forwardable_prompt = processed_prompt
        ai_response = "[GATEWAY_PENDING]"

    PromptLog.objects.create(
        user=user,
        original_prompt=encrypt(prompt),
        processed_prompt=logged_processed,
        detected_types=orchestration["detected_types"],
        action=action,
        reasons=[f"[{source}] {reason}" for reason in policy["reasons"]],
        risk_score=risk["score"],
        risk_level=risk["level"],
        agent_trace=orchestration["agent_trace"],
        ai_response=ai_response,
    )

    return {
        "role": role,
        "action": action,
        "processed_prompt": forwardable_prompt,
        "detected_types": orchestration["detected_types"],
        "reasons": policy["reasons"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "agent_trace": orchestration["agent_trace"],
    }


def _inspect_response(user, response_text: str, source: str) -> dict:
    orchestration = SecurityOrchestrator().analyze(
        role=user.role,
        prompt=response_text,
        direction="RESPONSE",
        source=source,
    )
    orchestration["agent_trace"]["identity_context"] = user.identity_context
    policy = orchestration["policy"]
    risk = orchestration["risk"]
    backend_action = policy["action"]
    token_map = {}
    processed_response = response_text

    if policy["tokenize_targets"]:
        processed_response, token_map = tokenize(response_text, policy["tokenize_targets"])
        _store_token_map(user, token_map, source=source, direction="RESPONSE")

    if backend_action == "BLOCK":
        response_action = "BLOCK"
        display_response = "[RESPONSE BLOCKED - unsafe AI output hidden by Sentinell.AI]"
    elif token_map:
        response_action = "REDACT"
        display_response = processed_response
    else:
        response_action = "ALLOW"
        display_response = response_text

    ResponseLog.objects.create(
        user=user,
        source=source,
        original_response=encrypt(response_text),
        processed_response=display_response,
        detected_types=orchestration["detected_types"],
        action=response_action,
        reasons=[f"[{source}] {reason}" for reason in policy["reasons"]],
        risk_score=risk["score"],
        risk_level=risk["level"],
        agent_trace=orchestration["agent_trace"],
    )

    return {
        "action": response_action,
        "backend_policy_action": backend_action,
        "processed_response": display_response,
        "detected_types": orchestration["detected_types"],
        "reasons": policy["reasons"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "agent_trace": orchestration["agent_trace"],
    }


def _parse_json(request):
    try:
        return json.loads(request.body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _normalize_messages(body: dict) -> tuple[list[dict] | None, str | None]:
    if "messages" in body:
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return None, "Field 'messages' must be a non-empty list."
        normalized = []
        for item in messages:
            if not isinstance(item, dict):
                return None, "Each message must be an object."
            role = str(item.get("role", "user")).lower()
            content = item.get("content", "")
            if role not in {"system", "developer", "user", "assistant", "tool"}:
                return None, f"Unsupported message role '{role}'."
            if not isinstance(content, str):
                return None, "Only string message content is supported."
            normalized.append({"role": role, "content": content})
        return normalized, None

    prompt = body.get("prompt", "")
    if not isinstance(prompt, str) or not prompt.strip():
        return None, "Field 'prompt' or 'messages' is required."
    return [{"role": "user", "content": prompt.strip()}], None


def _inspect_outbound_messages(user, messages: list[dict], source: str) -> tuple[list[dict], list[dict], dict | None]:
    processed_messages = []
    inspections = []
    for index, message in enumerate(messages):
        content = message.get("content", "")
        role = message.get("role", "user")
        if role in INSPECTABLE_ROLES and content.strip():
            inspection = _inspect_prompt(
                user,
                content.strip(),
                f"{source}:{role}",
                role=role,
            )
            inspections.append(inspection)
            if inspection["action"] == "BLOCK":
                return processed_messages, inspections, inspection
            processed_messages.append({**message, "content": inspection["processed_prompt"]})
        else:
            processed_messages.append(message)
    return processed_messages, inspections, None


def _combined_prompt_result(inspections: list[dict], processed_messages: list[dict]) -> dict:
    if not inspections:
        return {
            "action": "ALLOW",
            "processed_prompt": "",
            "processed_messages": processed_messages,
            "detected_types": [],
            "reasons": [],
            "risk_score": 0,
            "risk_level": "LOW",
        }

    action_rank = {"ALLOW": 0, "TOKENIZE": 1, "BLOCK": 2}
    action = max((item["action"] for item in inspections), key=lambda value: action_rank.get(value, 0))
    return {
        "action": action,
        "processed_prompt": "\n\n".join(
            message["content"] for message in processed_messages if message.get("role") == "user"
        ),
        "processed_messages": processed_messages,
        "detected_types": sorted({dtype for item in inspections for dtype in item["detected_types"]}),
        "reasons": [reason for item in inspections for reason in item["reasons"]],
        "risk_score": max(item["risk_score"] for item in inspections),
        "risk_level": max(inspections, key=lambda item: item["risk_score"])["risk_level"],
        "inspections": inspections,
    }


def _gateway_chat_payload(user, body: dict) -> tuple[dict, int]:
    messages, error = _normalize_messages(body)
    if error:
        return {"error": error}, 400

    source = str(body.get("source", "gateway_api"))[:80]
    provider = str(body.get("provider", "")).strip().lower()
    model = str(body.get("model", "")).strip()
    metadata = body.get("metadata", {})
    if not isinstance(metadata, dict):
        return {"error": "Field 'metadata' must be an object when provided."}, 400
    try:
        temperature = float(body.get("temperature", 0.2))
        max_tokens = int(body.get("max_tokens", body.get("max_completion_tokens", 700)))
    except (TypeError, ValueError):
        return {"error": "Fields 'temperature' and 'max_tokens' must be numeric."}, 400

    processed_messages, inspections, blocked = _inspect_outbound_messages(user, messages, source)
    if blocked:
        return {
            "status": "BLOCKED",
            "gateway": {
                "provider": provider or "default",
                "model": model,
                "source": source,
                "forwarded": False,
            },
            "prompt": {
                "action": blocked["action"],
                "processed_prompt": "",
                "processed_messages": [],
                "detected_types": blocked["detected_types"],
                "reasons": blocked["reasons"],
                "risk_score": blocked["risk_score"],
                "risk_level": blocked["risk_level"],
                "inspections": inspections,
            },
            "response": None,
        }, 200

    prompt_result = _combined_prompt_result(inspections, processed_messages)
    llm_response = generate_gateway_response(
        GatewayLLMRequest(
            provider=provider,
            model=model,
            messages=processed_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            metadata=metadata,
        )
    )
    response_result = _inspect_response(user, llm_response.content, source)

    return {
        "status": "OK" if response_result["action"] != "BLOCK" else "RESPONSE_BLOCKED",
        "gateway": {
            "provider": llm_response.provider,
            "model": llm_response.model,
            "source": source,
            "forwarded": True,
            "fallback_used": llm_response.fallback_used,
            "provider_response": llm_response.raw,
        },
        "prompt": {
            "action": prompt_result["action"],
            "processed_prompt": prompt_result["processed_prompt"],
            "processed_messages": prompt_result["processed_messages"],
            "detected_types": prompt_result["detected_types"],
            "reasons": prompt_result["reasons"],
            "risk_score": prompt_result["risk_score"],
            "risk_level": prompt_result["risk_level"],
            "inspections": prompt_result.get("inspections", []),
        },
        "response": {
            "action": response_result["action"],
            "processed_response": response_result["processed_response"],
            "detected_types": response_result["detected_types"],
            "reasons": response_result["reasons"],
            "risk_score": response_result["risk_score"],
            "risk_level": response_result["risk_level"],
        },
    }, 200


@csrf_exempt
@require_POST
def gateway_chat(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": "Missing or invalid gateway token."}, status=401)

    body = _parse_json(request)
    if body is None:
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    payload, status = _gateway_chat_payload(user, body)
    return JsonResponse(payload, status=status)


@csrf_exempt
@require_POST
def openai_compatible_chat(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": {"message": "Missing or invalid gateway token."}}, status=401)

    body = _parse_json(request)
    if body is None:
        return JsonResponse({"error": {"message": "Invalid JSON body."}}, status=400)

    payload, status = _gateway_chat_payload(user, {
        **body,
        "source": body.get("source", "openai_compatible_gateway"),
    })
    if status != 200:
        return JsonResponse({"error": {"message": payload.get("error", "Gateway error.")}}, status=status)
    if payload["status"] == "BLOCKED":
        return JsonResponse({
            "id": "sentinell-blocked",
            "object": "chat.completion",
            "model": body.get("model", "sentinell-gateway"),
            "choices": [{
                "index": 0,
                "finish_reason": "content_filter",
                "message": {
                    "role": "assistant",
                    "content": "Sentinell.AI blocked this request before it reached the LLM.",
                },
            }],
            "sentinell": payload,
        })

    content = payload["response"]["processed_response"] if payload["response"] else ""
    return JsonResponse({
        "id": "sentinell-gateway",
        "object": "chat.completion",
        "model": payload["gateway"]["model"],
        "choices": [{
            "index": 0,
            "finish_reason": "stop" if payload["status"] == "OK" else "content_filter",
            "message": {"role": "assistant", "content": content},
        }],
        "sentinell": payload,
    })


@require_GET
def gateway_providers(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": "Missing or invalid gateway token."}, status=401)
    return JsonResponse({"providers": gateway_provider_catalog()})


@csrf_exempt
@require_POST
def gateway_file_scan(request):
    user = _bearer_user(request)
    if user is None:
        return JsonResponse({"error": "Missing or invalid gateway token."}, status=401)

    uploaded = request.FILES.get("document")
    if uploaded is None:
        return JsonResponse({"error": "No file uploaded. Use field name 'document'."}, status=400)

    source = str(request.POST.get("source", "gateway_file_scan"))[:80]
    result = scan_uploaded_file(user, uploaded, source=source)
    return JsonResponse({
        "status": "OK" if result.payload.get("action") == "ALLOW" else "FILE_BLOCKED",
        "gateway": {
            "source": source,
            "forwardable": result.payload.get("safe_to_upload", False),
        },
        "file_scan": result.payload,
    }, status=result.status_code)
