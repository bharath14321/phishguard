"""

Dynamic malware-analysis engine.

This module prepares telemetry collected from an isolated
sandbox and converts it into behavioral features.

IMPORTANT:
This module does NOT execute malware.
"""
from src.sandbox.telemetry_collector import create_demo_telemetry

from src.sandbox.telemetry_schema import create_empty_telemetry


def count_events(telemetry):
    """
    Count how many events were observed in each telemetry category.
    """

    return {
        "process_count": len(telemetry["processes"]),
        "file_event_count": len(telemetry["file_events"]),
        "registry_event_count": len(telemetry["registry_events"]),
        "network_event_count": len(telemetry["network_events"]),
        "dns_event_count": len(telemetry["dns_events"]),
        "persistence_event_count": len(
            telemetry["persistence_events"]
        ),
    }


def extract_behavioral_features(telemetry):
    """
    Convert raw sandbox telemetry into ML-friendly features.

    These features can later become input to the malware
    classification model.
    """

    counts = count_events(telemetry)

    features = {
        # Number of processes created.
        "process_count": counts["process_count"],

        # Number of filesystem changes.
        "file_event_count": counts["file_event_count"],

        # Number of registry modifications.
        "registry_event_count": counts["registry_event_count"],

        # Number of network connections.
        "network_event_count": counts["network_event_count"],

        # Number of DNS queries.
        "dns_event_count": counts["dns_event_count"],

        # Possible persistence activity.
        "persistence_event_count":
            counts["persistence_event_count"],
    }

    return features


def analyze_behavior(telemetry):
    """
    Perform basic behavioral analysis.

    This function currently extracts counts only.

    Later we will add behavioral indicators such as:
    - PowerShell execution
    - process injection
    - persistence
    - suspicious child processes
    - unusual network connections
    - DNS behavior
    - file encryption/modification patterns
    """

    features = extract_behavioral_features(telemetry)

    indicators = []

    # These are behavioral indicators, not final malware verdicts.

    if features["process_count"] > 20:
        indicators.append("high_process_activity")

    if features["network_event_count"] > 10:
        indicators.append("high_network_activity")

    if features["dns_event_count"] > 10:
        indicators.append("high_dns_activity")

    if features["persistence_event_count"] > 0:
        indicators.append("persistence_activity")

    if features["registry_event_count"] > 10:
        indicators.append("high_registry_activity")

    return {
        "features": features,
        "behavioral_indicators": indicators,
    }


def create_test_telemetry():
    """
    Create harmless synthetic telemetry for testing.

    This allows us to test the analysis engine without
    executing an actual executable.
    """

    telemetry = create_empty_telemetry()

    telemetry["processes"] = [
        {
            "process_name": "sample.exe"
        },
        {
            "process_name": "powershell.exe"
        },
    ]

    telemetry["file_events"] = [
        {
            "action": "create",
            "path": "C:\\Temp\\sample.dat"
        }
    ]

    telemetry["registry_events"] = [
        {
            "action": "modify",
            "key": "HKCU\\Software\\Example"
        }
    ]

    telemetry["network_events"] = [
        {
            "destination": "203.0.113.10",
            "port": 443
        }
    ]

    telemetry["dns_events"] = [
        {
            "domain": "example.test"
        }
    ]

    telemetry["persistence_events"] = [
        {
            "type": "run_key"
        }
    ]

    return telemetry
if __name__ == "__main__":

    # Generate synthetic telemetry.
    # No executable is launched.
    telemetry = create_demo_telemetry()

    # Convert raw telemetry into behavioral features.
    result = analyze_behavior(telemetry)

    print("\n" + "=" * 60)
    print("DYNAMIC ANALYSIS PIPELINE TEST")
    print("=" * 60)

    print("\nBehavioral Features:")

    for key, value in result["features"].items():
        print(f"  {key}: {value}")

    print("\nBehavioral Indicators:")

    for indicator in result["behavioral_indicators"]:
        print(f"  - {indicator}")

    print("\n" + "=" * 60)
