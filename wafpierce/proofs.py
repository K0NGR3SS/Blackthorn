"""Proof-contract execution with mandatory budgets and cleanup accounting."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .pentest_models import (
    CleanupState,
    ProofArtifact,
    ProofContract,
    VerificationState,
)
from .pentest_policy import ExecutionPolicy, RequestBudget


Probe = Callable[[RequestBudget], Dict[str, Any]]
Cleanup = Callable[[], bool]


@dataclass
class ProofRunResult:
    artifact: ProofArtifact
    requests_used: int
    runtime_seconds: float
    cleanup_error: str = ""


class ProofRunner:
    """Run one proof module while keeping authorization and cleanup explicit."""

    def __init__(self, policy: ExecutionPolicy):
        self.policy = policy

    def run(
        self,
        contract: ProofContract,
        target: str,
        probe: Probe,
        *,
        cleanup: Optional[Cleanup] = None,
        request_id: Optional[str] = None,
    ) -> ProofRunResult:
        self.policy.require(target, contract.impact)
        limit = min(contract.max_requests, self.policy.request_budget)
        budget = RequestBudget(limit, self.policy.minimum_delay)
        started = time.monotonic()
        cleanup_state = (
            CleanupState.PENDING if contract.cleanup_required
            else CleanupState.NOT_REQUIRED
        )
        cleanup_error = ""
        payload: Dict[str, Any] = {}
        probe_error = ""
        try:
            payload = dict(probe(budget) or {})
        except Exception as exc:
            probe_error = "%s: %s" % (type(exc).__name__, exc)
            payload = {"probe_error": probe_error}
        finally:
            if contract.cleanup_required:
                if cleanup is None:
                    cleanup_state = CleanupState.FAILED
                    cleanup_error = "cleanup callback was not provided"
                else:
                    try:
                        cleanup_state = (
                            CleanupState.COMPLETE if cleanup() else CleanupState.FAILED
                        )
                        if cleanup_state == CleanupState.FAILED:
                            cleanup_error = "cleanup callback reported failure"
                    except Exception as exc:
                        cleanup_state = CleanupState.FAILED
                        cleanup_error = "%s: %s" % (type(exc).__name__, exc)

        elapsed = time.monotonic() - started
        positive = bool(payload.get("positive_oracle"))
        negative = bool(payload.get("negative_control"))
        if probe_error:
            verification = VerificationState.REJECTED
        elif positive and negative:
            verification = VerificationState.CONFIRMED
        elif positive:
            verification = VerificationState.CANDIDATE
        else:
            verification = VerificationState.OBSERVATION

        # A state-changing proof is never considered complete if its cleanup did
        # not finish. Preserve the evidence, but force analyst review.
        if verification == VerificationState.CONFIRMED and cleanup_state == CleanupState.FAILED:
            verification = VerificationState.CANDIDATE
        if cleanup_error:
            payload["cleanup_error"] = cleanup_error
        payload.setdefault("positive_oracles", list(contract.positive_oracles))
        payload.setdefault("negative_controls", list(contract.negative_controls))
        payload["runtime_seconds"] = round(elapsed, 6)
        payload["requests_used"] = budget.used

        artifact = ProofArtifact(
            contract_id=contract.module_id,
            target=target,
            verification=verification,
            evidence=payload,
            request_id=request_id,
            cleanup=cleanup_state,
        )
        return ProofRunResult(
            artifact=artifact,
            requests_used=budget.used,
            runtime_seconds=elapsed,
            cleanup_error=cleanup_error,
        )

