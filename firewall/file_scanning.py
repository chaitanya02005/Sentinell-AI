from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from .agents import SecurityOrchestrator
from .document_extractor import extract_text
from .encryption import encrypt
from .models import PromptLog, TokenMap
from .tokenization import tokenize
from .vault import seal_value


@dataclass
class FileScanResult:
    payload: dict
    status_code: int = 200


def scan_uploaded_file(user, uploaded_file, *, source: str = "file_scan") -> FileScanResult:
    max_bytes = int(getattr(settings, "FILE_SCAN_MAX_BYTES", 5 * 1024 * 1024))
    if uploaded_file.size and uploaded_file.size > max_bytes:
        return FileScanResult({
            "error": f"File is too large for inline scanning. Max allowed size is {max_bytes} bytes.",
            "action": "BLOCK",
        }, 413)

    extracted_text, error = extract_text(uploaded_file)
    if error:
        return FileScanResult({"error": error, "action": "BLOCK"}, 422)

    return scan_extracted_text(
        user,
        extracted_text,
        source=source,
        file_name=uploaded_file.name or "uploaded-file",
        file_size=uploaded_file.size or 0,
    )


def scan_extracted_text(
    user,
    text: str,
    *,
    source: str,
    file_name: str,
    file_size: int = 0,
) -> FileScanResult:
    max_chars = int(getattr(settings, "FILE_SCAN_MAX_TEXT_CHARS", 100_000))
    if len(text) > max_chars:
        return FileScanResult({
            "error": f"Extracted text is too large for safe inline scanning. Max allowed length is {max_chars} characters.",
            "action": "BLOCK",
            "file": {
                "name": file_name,
                "size": file_size,
                "extracted_length": len(text),
            },
        }, 413)

    orchestration = SecurityOrchestrator().analyze(
        role=user.role,
        prompt=text,
        direction="PROMPT",
        source=source,
    )
    policy = orchestration["policy"]
    risk = orchestration["risk"]
    action = policy["action"]
    agent_trace = orchestration["agent_trace"]
    agent_trace["identity_context"] = user.identity_context
    agent_trace["file_scan"] = {
        "file_name": file_name,
        "file_size": file_size,
        "extracted_length": len(text),
        "source": source,
    }

    processed_text = text
    token_map = {}
    if policy["tokenize_targets"]:
        processed_text, token_map = tokenize(text, policy["tokenize_targets"])
        for label, original_value in token_map.items():
            sealed = seal_value(
                original_value,
                purpose="pii_token_map",
                context={"source": source, "direction": "FILE", "file_name": file_name},
            )
            TokenMap.objects.create(
                user=user,
                token_label=label[:30],
                **sealed.model_fields(),
            )

    if action == "BLOCK":
        processed_for_log = "[BLOCKED - file did not forward]"
        forwardable_text = ""
    else:
        processed_for_log = processed_text
        forwardable_text = processed_text

    PromptLog.objects.create(
        user=user,
        original_prompt=encrypt(text),
        processed_prompt=processed_for_log,
        detected_types=orchestration["detected_types"],
        action=action,
        reasons=[f"[{source}:{file_name}] {reason}" for reason in policy["reasons"]],
        risk_score=risk["score"],
        risk_level=risk["level"],
        agent_trace=agent_trace,
        ai_response="[FILE_SCAN_ONLY]",
    )

    return FileScanResult({
        "action": action,
        "safe_to_upload": action == "ALLOW",
        "processed_text": forwardable_text,
        "original_changed": bool(token_map),
        "detected_types": orchestration["detected_types"],
        "reasons": policy["reasons"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "file": {
            "name": file_name,
            "size": file_size,
            "extracted_length": len(text),
        },
        "agent_trace": {
            "semantic_security_agent": agent_trace.get("semantic_security_agent", {}),
            "final_decision": agent_trace.get("final_decision", {}),
            "identity_context": agent_trace.get("identity_context", {}),
            "file_scan": agent_trace.get("file_scan", {}),
        },
    })
