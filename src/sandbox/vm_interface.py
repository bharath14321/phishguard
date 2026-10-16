from __future__ import annotations

import abc
from typing import Dict, Any
from .sandbox_job import SandboxJob, JobStatus


class SandboxVMInterface(abc.ABC):
    """Abstract base class defining the contract for a sandbox VM adapter.

    Implementations must run in a **separate, isolated VM** and never
    execute malicious code in the main PHISHGUARD process. The methods are
    intentionally minimal – they only transfer job metadata, query status,
    retrieve results, and optionally cancel a job.
    """

    @abc.abstractmethod
    def submit_job(self, job: SandboxJob) -> str:
        """Submit a ``SandboxJob`` to the VM.

        Returns the job identifier that the VM will use. The caller should
        treat the returned ID as an opaque string – it may be the same as
        ``job.job_id`` or a VM‑generated identifier.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_job_status(self, job_id: str) -> JobStatus:
        """Query the current status of a job identified by ``job_id``.

        The result must be one of the ``JobStatus`` enum values. Implementers
        must **never** expose raw exception traces or host environment details.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def collect_result(self, job_id: str) -> Dict[str, Any]:
        """Retrieve the telemetry/result produced by the sandbox VM.

        The returned dictionary is considered **untrusted**; callers should
        validate it (e.g., via :func:`validate_telemetry`) before further
        processing.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def cancel_job(self, job_id: str) -> bool:
        """Request cancellation of the job.

        Returns ``True`` if the VM acknowledged the cancellation request.
        """
        raise NotImplementedError
