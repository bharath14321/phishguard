"""
PHISHGUARD Sandbox Telemetry Validator
======================================

This module validates telemetry received from the isolated malware-analysis
sandbox before PHISHGUARD processes it.

IMPORTANT SECURITY PRINCIPLE
----------------------------
Telemetry coming from the sandbox must always be treated as untrusted input.

This module is responsible for structural validation only. It does NOT:
- execute files
- execute commands
- make network requests
- determine whether a sample is malware
- assign a final risk score
- treat generic activity as benign

The validated telemetry can later be passed to the behavioral analysis engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


# ---------------------------------------------------------------------------
# Expected telemetry categories.
#
# These categories correspond to the telemetry types currently used by the
# PHISHGUARD sandbox foundation.
# ---------------------------------------------------------------------------

_REQUIRED_TOP_LEVEL_KEYS: List[str] = [
    "processes",
    "file_events",
    "registry_events",
    "network_events",
    "dns_events",
    "persistence_events",
]


# ---------------------------------------------------------------------------
# Required fields for each telemetry event.
#
# These are intentionally minimal. Additional fields may be added later as
# the sandbox telemetry schema becomes more detailed.
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS: Dict[str, List[str]] = {
    "processes": [
        "process_name",
        "timestamp",
    ],
    "file_events": [
        "action",
        "path",
        "timestamp",
    ],
    "registry_events": [
        "action",
        "key",
        "timestamp",
    ],
    "network_events": [
        "destination",
        "port",
        "timestamp",
    ],
    "dns_events": [
        "domain",
        "timestamp",
    ],
    "persistence_events": [
        "type",
        "timestamp",
    ],
}


# ---------------------------------------------------------------------------
# Event classification keywords.
#
# These keywords identify potentially suspicious event descriptions.
# Classification here is only an indicator and must NOT be treated as a
# malware verdict.
# ---------------------------------------------------------------------------

_SUSPICIOUS_KEYWORDS = {
    "powershell",
    "cmd",
    "wmic",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
}


# ---------------------------------------------------------------------------
# Helper function: validate one telemetry event.
# ---------------------------------------------------------------------------

def _validate_event(
    event: Dict[str, Any],
    required_fields: List[str],
) -> List[str]:
    """
    Validate the required fields of one telemetry event.

    The function only checks structure. It does not inspect the event for
    malicious behavior and does not execute or interpret any event content.

    Args:
        event:
            A single telemetry event represented as a dictionary.

        required_fields:
            Fields that must exist for the event category.

    Returns:
        A list of validation errors. An empty list means that all required
        fields are present.
    """

    errors: List[str] = []

    # Check every required field individually so the caller receives useful
    # information about exactly what is missing.
    for field_name in required_fields:
        if field_name not in event:
            errors.append(
                f"Missing required field '{field_name}'"
            )

    return errors


# ---------------------------------------------------------------------------
# Main telemetry validation function.
# ---------------------------------------------------------------------------

def validate_telemetry(
    telemetry: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """
    Validate the structure of a sandbox telemetry payload.

    Validation is intentionally conservative.

    The function checks:

    1. The input is a dictionary.
    2. Required top-level telemetry categories exist.
    3. Each category contains a list.
    4. Each event in a category is a dictionary.
    5. Required fields exist in each event.
    6. Required timestamps are strings.

    This function does NOT determine whether telemetry is malicious.

    Args:
        telemetry:
            Telemetry received from the isolated sandbox VM.

    Returns:
        A tuple:

            (is_valid, errors)

        where:
            is_valid is True when no structural validation errors exist.
            errors contains human-readable validation errors.
    """

    errors: List[str] = []

    # -----------------------------------------------------------------------
    # Security boundary:
    # Never process arbitrary objects as telemetry.
    # -----------------------------------------------------------------------

    if not isinstance(telemetry, dict):
        return (
            False,
            [
                "Telemetry payload must be a dictionary"
            ],
        )

    # -----------------------------------------------------------------------
    # Validate all required top-level telemetry categories.
    # -----------------------------------------------------------------------

    for category in _REQUIRED_TOP_LEVEL_KEYS:

        # The category must exist.
        if category not in telemetry:
            errors.append(
                f"Missing top-level key '{category}'"
            )
            continue

        events = telemetry[category]

        # Every telemetry category must contain a list of events.
        if not isinstance(events, list):
            errors.append(
                f"Top-level key '{category}' must be a list, "
                f"got {type(events).__name__}"
            )
            continue

        required_fields = _REQUIRED_FIELDS.get(category, [])

        # -------------------------------------------------------------------
        # Validate every event in the category.
        # -------------------------------------------------------------------

        for index, event in enumerate(events):

            # A telemetry event must be represented as a dictionary.
            if not isinstance(event, dict):
                errors.append(
                    f"Event {index} in '{category}' must be a dictionary"
                )
                continue

            # Validate the required fields.
            event_errors = _validate_event(
                event,
                required_fields,
            )

            # Add the event location to each error so it can be traced back
            # to the exact telemetry record.
            for error in event_errors:
                errors.append(
                    f"{category}[{index}]: {error}"
                )

            # ---------------------------------------------------------------
            # Timestamp validation.
            #
            # We intentionally perform only a basic type check here.
            # Detailed timestamp parsing can be implemented later when the
            # final sandbox telemetry schema is established.
            # ---------------------------------------------------------------

            if "timestamp" in event:
                if not isinstance(event["timestamp"], str):
                    errors.append(
                        f"{category}[{index}]: "
                        "timestamp must be a string"
                    )

    # -----------------------------------------------------------------------
    # The payload is structurally valid only when no errors were found.
    #
    # IMPORTANT:
    # Structurally valid telemetry is NOT automatically benign.
    # -----------------------------------------------------------------------

    is_valid = len(errors) == 0

    return is_valid, errors


# ---------------------------------------------------------------------------
# Event classification helper.
# ---------------------------------------------------------------------------

def classify_event(event_type: str) -> str:
    """
    Conservatively classify a telemetry event type.

    This is NOT a malware detector and must NOT be used as a final security
    decision.

    Generic telemetry such as:
        process
        network
        dns
        file
        registry
        persistence

    does not prove that the activity is benign. Therefore, generic event
    categories are classified as "unknown".

    Specific suspicious indicators such as "powershell" or "rundll32" are
    classified as "suspicious", but even those are only signals and require
    additional context before a final verdict.

    Args:
        event_type:
            Name or description of the telemetry event type.

    Returns:
        One of:

            "unknown"
            "benign"
            "suspicious"
            "malicious"

        Currently this function intentionally does not return "malicious".
    """

    # -----------------------------------------------------------------------
    # Normalize the supplied value so classification is case-insensitive.
    # -----------------------------------------------------------------------

    if not isinstance(event_type, str):
        return "unknown"

    normalized_type = event_type.lower().strip()

    if not normalized_type:
        return "unknown"

    # -----------------------------------------------------------------------
    # Check for specific suspicious execution indicators.
    #
    # These are signals only. For example, PowerShell can be legitimately
    # used by administrators, so its presence alone cannot prove malware.
    # -----------------------------------------------------------------------

    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword in normalized_type:
            return "suspicious"

    # -----------------------------------------------------------------------
    # Generic event types provide no verdict by themselves.
    #
    # A process creation, network connection, DNS request, or file operation
    # can be completely legitimate or malicious depending on context.
    # -----------------------------------------------------------------------

    generic_event_types = {
        "process",
        "network",
        "dns",
        "file",
        "registry",
        "persistence",
    }

    if normalized_type in generic_event_types:
        return "unknown"

    # -----------------------------------------------------------------------
    # Unknown event types remain unknown rather than being treated as safe.
    # -----------------------------------------------------------------------

    return "unknown"


# ---------------------------------------------------------------------------
# Convenience helper for callers that only need the validation result.
# ---------------------------------------------------------------------------

def is_valid_telemetry(
    telemetry: Dict[str, Any],
) -> bool:
    """
    Return only the validity state of a telemetry payload.

    This helper calls the main validator rather than implementing a second
    validation system, preventing validation logic from becoming duplicated.

    Args:
        telemetry:
            Telemetry payload received from the sandbox.

    Returns:
        True when the telemetry passes structural validation, otherwise False.
    """

    # Reuse the main validator so both validation entry points always have
    # identical behavior.
    valid, _ = validate_telemetry(telemetry)

    return valid
