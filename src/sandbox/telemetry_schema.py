"""
Telemetry data structures used by the malware sandbox.

The sandbox will eventually collect information about:
- processes
- files
- registry activity
- network connections
- DNS requests
- persistence mechanisms
"""


def create_empty_telemetry():
    """
    Create an empty telemetry structure.

    Every category starts as an empty list so that the
    analysis engine can add events as they are observed.
    """

    return {
        "processes": [],
        "file_events": [],
        "registry_events": [],
        "network_events": [],
        "dns_events": [],
        "persistence_events": [],
    }


def add_process_event(telemetry, event):
    """
    Add a process-related event to the telemetry structure.

    Example:
        process creation, command line, parent process, etc.
    """

    telemetry["processes"].append(event)


def add_file_event(telemetry, event):
    """
    Add a filesystem event.

    Examples:
        file creation
        file modification
        file deletion
    """

    telemetry["file_events"].append(event)


def add_registry_event(telemetry, event):
    """
    Add a Windows Registry event.

    Examples:
        registry key creation
        registry value modification
    """

    telemetry["registry_events"].append(event)


def add_network_event(telemetry, event):
    """
    Add a network event.

    Examples:
        destination IP
        destination port
        protocol
        connection attempt
    """

    telemetry["network_events"].append(event)


def add_dns_event(telemetry, event):
    """
    Add a DNS event.

    Examples:
        requested domain
        resolved IP address
    """

    telemetry["dns_events"].append(event)


def add_persistence_event(telemetry, event):
    """
    Add an event indicating possible persistence activity.

    Examples:
        Run key modification
        service creation
        scheduled task
    """

    telemetry["persistence_events"].append(event)
