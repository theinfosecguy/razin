"""Closed sandbox backend boundary with a non-executing v1 implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from razin.constants.sandbox import SANDBOX_SIMULATION_ADAPTER_VERSION, SANDBOX_SIMULATION_BACKEND


@dataclass(frozen=True, slots=True)
class BackendOutcome:
    """Strict backend outcome consumed by the result writer."""

    execution_status: str
    reason_codes: tuple[str, ...]
    enforcement_status: str
    conclusion: str
    backend_instance_id: str | None = None
    process: dict[str, Any] | None = None
    backend_invocation_sha256: str | None = None


class SandboxBackend(Protocol):
    """Backend contract; implementations receive only already-verified bytes."""

    backend_id: str
    adapter_version: str

    def run(self, *, plan: dict[str, Any], bundle_bytes: bytes) -> BackendOutcome:
        """Return an auditable outcome for a verified plan and bundle."""
        ...


class SimulationBackend:
    """A backend that deliberately performs no code or process execution."""

    backend_id = SANDBOX_SIMULATION_BACKEND
    adapter_version = SANDBOX_SIMULATION_ADAPTER_VERSION

    def run(self, *, plan: dict[str, Any], bundle_bytes: bytes) -> BackendOutcome:
        """Acknowledge verified inputs without interpreting either one."""
        del plan, bundle_bytes
        return BackendOutcome(
            execution_status="simulated",
            reason_codes=("simulation-only",),
            enforcement_status="not-applied",
            conclusion="not-run",
        )


def builtin_backends() -> dict[str, SandboxBackend]:
    """Return a fresh closed registry; plan data can never import a backend."""
    backend = SimulationBackend()
    return {backend.backend_id: backend}
