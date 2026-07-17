from __future__ import annotations

from typing import Iterable


def detection_types(detections: Iterable) -> list[str]:
    """Return stable, de-duplicated detection type names."""
    return sorted({d.dtype for d in detections})


def values_for_types(detections: Iterable, dtype_set: set[str]) -> list[str]:
    """Return stable detection type names filtered by a type set."""
    return sorted({d.dtype for d in detections if d.dtype in dtype_set})


def agent_report(
    *,
    name: str,
    found: bool,
    types: list[str] | None = None,
    action: str = "ALLOW",
    confidence: float = 0.0,
    reason: str = "",
    extra: dict | None = None,
) -> dict:
    report = {
        "agent": name,
        "found": found,
        "types": types or [],
        "action": action,
        "confidence": round(confidence, 2),
        "reason": reason,
    }
    if extra:
        report.update(extra)
    return report
