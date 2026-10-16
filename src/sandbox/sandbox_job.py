from __future__ import annotations

import enum
import datetime
from dataclasses import dataclass, field
from typing import Optional


class JobStatus(enum.Enum):
    """Enumeration of possible sandbox job statuses.

    The main PHISHGUARD environment never executes malware; the status
    reflects the lifecycle as managed by a separate isolated VM.
    """

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    REJECTED = "rejected"


@dataclass
class SandboxJob:
    """Lightweight representation of a sandbox analysis job.

    All fields are plain data; no file handles or network resources are
    opened here. The job object is intended to be passed to a VM adapter
    that will execute the analysis in an isolated environment.
    """

    job_id: str
    """Unique identifier for the job (e.g., UUID)."""

    sample_sha256: str
    """SHA‑256 hash of the submitted sample. The hash is stored instead of
    the raw sample to avoid persisting potentially malicious binaries.
    """

    sample_type: str
    """MIME‑type or a short descriptor (e.g., 'exe', 'doc')."""

    status: JobStatus = field(default=JobStatus.QUEUED)
    """Current status of the job; initial value is QUEUED."""

    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    """Timestamp when the job object was created (UTC)."""

    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    timeout_seconds: int = 300
    """Maximum allowed runtime in the sandbox VM. The main process will treat a
    job that exceeds this limit as TIMEOUT without executing any code.
    """

    result_path: Optional[str] = None
    """Path to the analysis result produced by the sandbox VM. The main
    environment must treat the file contents as untrusted and validate it
    before consumption.
    """

    error_message: Optional[str] = None
    """Human‑readable error if the job fails. Sensitive details are avoided
    to prevent leaking sandbox internals.
    """
