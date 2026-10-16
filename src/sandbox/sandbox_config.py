"""
Configuration for the malware-analysis sandbox.

This file contains safety limits and analysis settings.
The suspicious sample must be executed only inside an
isolated analysis environment.
"""

# Maximum amount of time allowed for one analysis.
ANALYSIS_TIMEOUT_SECONDS = 120


# Maximum number of processes we want to record.
MAX_PROCESSES = 500


# Maximum number of filesystem events we want to record.
MAX_FILE_EVENTS = 1000


# Maximum number of network events we want to record.
MAX_NETWORK_EVENTS = 1000


# Maximum number of DNS events we want to record.
MAX_DNS_EVENTS = 500


# Network access should be disabled or tightly controlled
# during initial sandbox development.
NETWORK_MODE = "isolated"


# Never expose the host filesystem to the suspicious sample.
HOST_SHARED_FOLDERS = False


# Never provide host credentials to the sandbox.
HOST_CREDENTIALS = False
