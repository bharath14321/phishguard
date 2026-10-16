# PHISHGUARD Isolated Malware Sandbox Architecture

## Purpose

PHISHGUARD must never execute potentially malicious files inside the main application environment.

Dynamic malware analysis will be performed inside a separate, isolated sandbox VM.

## Architecture

```text
PHISHGUARD MAIN ENVIRONMENT
    |
    | Sandbox Job Interface
    v
ISOLATED SANDBOX VM
    |
    | Execute Sample
    v
Telemetry Collection
    |
    v
Validated Telemetry
    |
    v
Behavioral Analysis
    |
    v
PHISHGUARD Risk Engine
Main PHISHGUARD Environment
The main environment performs:
- File identification
- Hash calculation
- Static analysis
- Machine-learning analysis
- URL analysis
- Email analysis
- Risk aggregation
- Storage of analysis results
The main environment must never execute submitted malware.
Sandbox VM
The sandbox VM is responsible for:
- Controlled sample execution
- Process telemetry
- File telemetry
- Registry telemetry
- Network telemetry
- DNS telemetry
- Persistence telemetry
- PowerShell/command-line telemetry
The sandbox must be isolated from the normal host environment.
Isolation Requirements
The sandbox should have:
- No shared folders
- No shared clipboard
- No drag-and-drop
- No personal credentials
- No access to the normal host filesystem
- No unrestricted Internet access
- A clean snapshot before analysis
- Snapshot reversion after analysis
Analysis Workflow
CLEAN SNAPSHOT
      |
      v
CREATE SANDBOX JOB
      |
      v
TRANSFER SAMPLE THROUGH A CONTROLLED MECHANISM
      |
      v
EXECUTE SAMPLE IN SANDBOX
      |
      v
COLLECT TELEMETRY
      |
      v
STOP ANALYSIS
      |
      v
EXPORT TELEMETRY
      |
      v
VALIDATE TELEMETRY
      |
      v
BEHAVIORAL ANALYSIS
      |
      v
PHISHGUARD RISK ENGINE
      |
      v
REVERT SANDBOX SNAPSHOT

Security Boundary
Telemetry returned by the sandbox is untrusted input.
PHISHGUARD must validate telemetry before processing it.
Unknown telemetry must not automatically be classified as benign or malicious.
Current Phase
Phase 9 establishes the software boundary between PHISHGUARD and a future isolated sandbox VM.
Actual hypervisor automation and malware execution are intentionally not implemented yet.
Future Work
Future phases may implement:
- Controlled VM adapter
- Controlled sample transfer
- Sandbox execution orchestration
- Telemetry collection
- Isolated simulated network
- Behavioral malware features
- Static + behavioral evidence correlation
- Behavioral ML analysis
These components must maintain the isolation boundary between the main application and the sandbox.
